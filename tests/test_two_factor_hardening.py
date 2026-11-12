import asyncio
import time

import pyotp
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.common.security import keyed_hash, sha256
from app.configs import policy
from app.core.auth.models import IdentifierType, TwoFactorBackupCode, TwoFactorMethod
from app.core.auth.services import identifiers, otp, two_factor
from app.database.session import SessionLocal
from app.infrastructure.cache import cache, key
from tests.conftest import PASSWORD, auth, register, verified_user
from tests.test_auth import _enable_totp


async def _login_challenge(client) -> dict:
    body = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()
    return {"challengeId": body["challengeId"], "type": "TOTP"}


async def test_parallel_wrong_otp_guesses_cannot_exceed_the_attempt_cap(client, outbox, monkeypatch):
    await register(client)
    code = outbox.code_for("a@example.com")
    wrong = "000000" if code != "000000" else "111111"
    checks = 0
    real_verify = otp.verify_secret

    async def counting_verify(value: str, hashed: str | None) -> bool:
        nonlocal checks
        checks += 1
        return await real_verify(value, hashed)

    monkeypatch.setattr(otp, "verify_secret", counting_verify)
    guesses = [client.post("/auth/email/verify/otp", json={"email": "a@example.com", "code": wrong}) for _ in range(9)]
    statuses = [r.status_code for r in await asyncio.gather(*guesses)]
    assert checks <= policy.OTP_MAX_ATTEMPTS
    assert 429 in statuses
    r = await client.post("/auth/email/verify/otp", json={"email": "a@example.com", "code": code})
    assert r.status_code in (401, 429)


async def test_a_correct_otp_is_accepted_once_under_concurrency(outbox):
    await otp.issue("user-1", otp.Purpose.SUDO, "email", "a@example.com")
    code = outbox.code_for("a@example.com")
    tries = [otp.verify_code("user-1", otp.Purpose.SUDO, "email", code) for _ in range(4)]
    results = await asyncio.gather(*tries, return_exceptions=True)
    assert sum(isinstance(r, dict) for r in results) == 1
    assert all(isinstance(r, HTTPException) and r.status_code == 401 for r in results if not isinstance(r, dict))


async def test_parallel_challenge_guesses_cannot_exceed_the_attempt_cap(client, outbox, monkeypatch):
    await _enable_totp(client, outbox)
    verify = await _login_challenge(client)
    checks = 0
    real_match = two_factor._matched_step

    def counting_match(secret: str, code: str) -> int | None:
        nonlocal checks
        checks += 1
        return real_match(secret, code)

    monkeypatch.setattr(two_factor, "_matched_step", counting_match)
    guesses = [client.post("/auth/2fa/challenge/verify", json={**verify, "code": "000000"}) for _ in range(9)]
    statuses = [r.status_code for r in await asyncio.gather(*guesses)]
    assert checks <= policy.OTP_MAX_ATTEMPTS
    assert 429 in statuses and 200 not in statuses


async def test_two_factor_failures_are_capped_per_user_across_challenges(client, outbox, monkeypatch):
    monkeypatch.setattr(policy, "TWO_FACTOR_MAX_FAILS", 3)
    _, secret, _ = await _enable_totp(client, outbox)
    first = await _login_challenge(client)
    for _ in range(2):
        assert (await client.post("/auth/2fa/challenge/verify", json={**first, "code": "000000"})).status_code == 401
    second = await _login_challenge(client)
    assert (await client.post("/auth/2fa/challenge/verify", json={**second, "code": "000000"})).status_code == 401
    r = await client.post("/auth/2fa/challenge/verify", json={**second, "code": pyotp.TOTP(secret).at(int(time.time()) + 30)})
    assert r.status_code == 429


async def test_a_successful_challenge_clears_the_per_user_count(client, outbox):
    tokens, secret, _ = await _enable_totp(client, outbox)
    user_id = (await client.get("/auth/me", headers=auth(tokens))).json()["data"]["id"]
    verify = await _login_challenge(client)
    assert (await client.post("/auth/2fa/challenge/verify", json={**verify, "code": "000000"})).status_code == 401
    assert await cache.get(key(f"2fa:fail:{user_id}")) == 1
    r = await client.post("/auth/2fa/challenge/verify", json={**verify, "code": pyotp.TOTP(secret).at(int(time.time()) + 30)})
    assert r.status_code == 200
    assert await cache.get(key(f"2fa:fail:{user_id}")) is None


async def test_sudo_elevation_locks_out_after_too_many_failures(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    for _ in range(policy.SUDO_MAX_FAILS):
        assert (await client.post("/auth/sudo/password", json={"password": "wrong-password"}, headers=headers)).status_code == 401
    r = await client.post("/auth/sudo/password", json={"password": PASSWORD}, headers=headers)
    assert r.status_code == 429


async def test_sudo_success_clears_the_failure_count(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    for _ in range(policy.SUDO_MAX_FAILS - 1):
        assert (await client.post("/auth/sudo/password", json={"password": "wrong-password"}, headers=headers)).status_code == 401
    assert (await client.post("/auth/sudo/password", json={"password": PASSWORD}, headers=headers)).status_code == 200
    for _ in range(policy.SUDO_MAX_FAILS - 1):
        assert (await client.post("/auth/sudo/password", json={"password": "wrong-password"}, headers=headers)).status_code == 401
    assert (await client.post("/auth/sudo/password", json={"password": PASSWORD}, headers=headers)).status_code == 200


async def test_backup_codes_are_stored_as_keyed_hashes(client, outbox):
    _, _, codes = await _enable_totp(client, outbox)
    async with SessionLocal() as db:
        stored = set(await db.scalars(select(TwoFactorBackupCode.code_hash)))
    assert keyed_hash(codes[0], "backup-code") in stored
    assert sha256(codes[0]) not in stored
    verify = await _login_challenge(client)
    r = await client.post("/auth/2fa/challenge/verify", json={**verify, "code": codes[0].upper()})
    assert r.status_code == 200


async def test_totp_code_is_accepted_once(client, outbox):
    tokens, secret, _ = await _enable_totp(client, outbox)
    headers = auth(tokens)
    async with SessionLocal() as db:
        spent = await db.scalar(select(TwoFactorMethod.last_totp_step))
    assert spent is not None
    replay = {"type": "TOTP", "code": pyotp.TOTP(secret).generate_otp(spent)}
    assert (await client.post("/auth/sudo/2fa", json=replay, headers=headers)).status_code == 401
    code = pyotp.TOTP(secret).at(int(time.time()) + 30)
    tries = [client.post("/auth/sudo/2fa", json={"type": "TOTP", "code": code}, headers=headers) for _ in range(3)]
    statuses = sorted(r.status_code for r in await asyncio.gather(*tries))
    assert statuses == [200, 401, 401]


async def test_identifier_unique_race_returns_conflict_not_500(client, outbox, monkeypatch):
    tokens = await register(client)
    await register(client, "b@example.com")
    user_id = (await client.get("/auth/me", headers=auth(tokens))).json()["data"]["id"]

    async def lost_the_race(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(identifiers, "_assert_free", lost_the_race)
    async with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await identifiers._commit_identifier(db, user_id, IdentifierType.EMAIL, "b@example.com")
    assert exc.value.status_code == 409
