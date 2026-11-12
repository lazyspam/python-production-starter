import time

import jwt
import pyotp
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select, update

from app.core.auth.models import AuthProvider, User, UserIdentifier
from app.core.auth.services import identifiers, oauth
from app.database.session import SessionLocal, utcnow
from app.infrastructure.cache import cache, key
from tests.conftest import PASSWORD, auth, elevate, register, verified_user


async def test_register_returns_user_and_tokens_and_blocks_unverified_routes(client):
    r = await client.post("/auth/register", json={"email": "A@Example.com", "password": PASSWORD, "name": "A"})
    body = r.json()
    assert r.status_code == 201
    assert body["success"] is True and body["statusCode"] == 201
    assert body["data"]["email"] == "a@example.com"
    assert body["data"]["isAccountVerified"] is False
    assert "passwordHash" not in body["data"]
    headers = auth(body["tokens"])
    assert (await client.get("/auth/me", headers=headers)).status_code == 200
    r = await client.get("/auth/2fa/methods", headers=headers)
    assert r.status_code == 403
    assert r.json()["success"] is False and r.json()["data"] is None


async def test_register_rejects_duplicates_and_needs_email_or_phone(client):
    await register(client)
    assert (await client.post("/auth/register", json={"email": "a@example.com", "password": PASSWORD})).status_code == 409
    r = await client.post("/auth/register", json={"password": PASSWORD})
    assert r.status_code == 400 and isinstance(r.json()["message"], list)


async def test_phone_registration_verifies_over_sms(client, outbox):
    r = await client.post("/auth/register", json={"phone": "+14155552671", "password": PASSWORD})
    assert r.status_code == 201, r.text
    assert r.json()["data"]["phone"] == "+14155552671"
    code = outbox.code_for("+14155552671")
    r = await client.post("/auth/phone/verify/otp", json={"phone": "+14155552671", "code": code})
    assert r.json()["data"]["isAccountVerified"] is True
    r = await client.post("/auth/login", json={"phone": "+14155552671", "password": PASSWORD})
    assert r.status_code == 200


async def test_email_verification_by_link_and_session_code(client, outbox):
    await register(client)
    r = await client.post("/auth/email/verify", json={"token": outbox.token_for("a@example.com")})
    assert r.json()["data"]["isAccountVerified"] is True
    tokens = await register(client, "b@example.com")
    code = outbox.code_for("b@example.com")
    r = await client.post("/auth/email/verify/confirm", json={"code": code}, headers=auth(tokens))
    assert r.json()["data"]["isAccountVerified"] is True


async def test_otp_is_single_use_and_dies_after_too_many_wrong_attempts(client, outbox):
    await register(client)
    code = outbox.code_for("a@example.com")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        r = await client.post("/auth/email/verify/otp", json={"email": "a@example.com", "code": wrong})
        assert r.status_code == 401
    r = await client.post("/auth/email/verify/otp", json={"email": "a@example.com", "code": code})
    assert r.status_code == 429
    r = await client.post("/auth/email/verify/otp", json={"email": "a@example.com", "code": code})
    assert r.status_code == 401


async def test_otp_resend_has_a_cooldown(client):
    tokens = await register(client)
    r = await client.post("/auth/email/verify/resend/me", headers=auth(tokens))
    assert r.status_code == 429 and "Wait" in r.json()["message"]


async def test_login_cookie_transport_sets_httponly_cookies_and_no_tokens(client):
    await register(client)
    r = await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD}, headers={"X-Auth-Transport": ""})
    assert r.status_code == 200 and "tokens" not in r.json()
    cookies = r.headers.get_list("set-cookie")
    assert any(c.startswith("access_token=") and "HttpOnly" in c for c in cookies)
    assert any(c.startswith("refresh_token=") and "Path=/api/v1/auth" in c for c in cookies)
    client.cookies.set("access_token", r.cookies["access_token"])
    assert (await client.get("/auth/me")).status_code == 200


async def test_login_failures_are_uniform_and_lock_out(client):
    await register(client)
    bad = {"email": "a@example.com", "password": "wrong-password"}
    unknown = {"email": "nobody@example.com", "password": "wrong-password"}
    a, b = await client.post("/auth/login", json=bad), await client.post("/auth/login", json=unknown)
    assert a.status_code == b.status_code == 401 and a.json()["message"] == b.json()["message"]
    both = {"email": "a@example.com", "phone": "+14155552671", "password": PASSWORD}
    assert (await client.post("/auth/login", json=both)).status_code == 400

    from app.common.security import sha256

    await cache.set(key(f"login:fail:{sha256('a@example.com')}:127.0.0.1"), 10, expire=60)
    r = await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})
    assert r.status_code == 429 and "attempts" in r.json()["message"]


async def test_failed_logins_count_up(client):
    from app.common.security import sha256

    await register(client)
    for _ in range(3):
        await client.post("/auth/login", json={"email": "a@example.com", "password": "wrong-password"})
    assert int(await cache.get(key(f"login:fail:{sha256('a@example.com')}:127.0.0.1")) or 0) == 3


async def test_two_logins_in_the_same_second_get_separate_sessions(client):
    await register(client)
    body = {"email": "a@example.com", "password": PASSWORD}
    a, b = await client.post("/auth/login", json=body), await client.post("/auth/login", json=body)
    assert a.status_code == b.status_code == 200
    assert a.json()["tokens"]["refresh"]["token"] != b.json()["tokens"]["refresh"]["token"]


async def test_refresh_rotates_and_replay_ends_every_session(client):
    first = await register(client)
    old = first["refresh"]["token"]
    r = await client.post("/auth/refresh", json={"refreshToken": old})
    assert r.status_code == 200
    rotated = r.json()["tokens"]["refresh"]["token"]
    assert (await client.post("/auth/refresh", json={"refreshToken": old})).status_code == 401
    assert (await client.post("/auth/refresh", json={"refreshToken": rotated})).status_code == 401


async def test_access_token_is_not_a_refresh_token(client):
    tokens = await register(client)
    assert (await client.post("/auth/refresh", json={"refreshToken": tokens["access"]["token"]})).status_code == 401
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['refresh']['token']}"})
    assert r.status_code == 401


async def test_logout_and_sessions(client):
    a = await register(client)
    b = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()["tokens"]
    listed = (await client.get("/auth/sessions", headers=auth(a))).json()["data"]
    assert len(listed) == 2 and sum(s["current"] for s in listed) == 1
    other = next(s for s in listed if not s["current"])
    assert (await client.delete(f"/auth/sessions/{other['id']}", headers=auth(a))).status_code == 200
    assert (await client.post("/auth/refresh", json={"refreshToken": b["refresh"]["token"]})).status_code == 401
    await client.post("/auth/logout", json={"refreshToken": a["refresh"]["token"]})
    assert (await client.post("/auth/refresh", json={"refreshToken": a["refresh"]["token"]})).status_code == 401


async def test_sudo_is_required_bound_to_the_session_and_spent_by_consuming_routes(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    assert (await client.post("/auth/2fa/enroll/totp", headers=headers)).status_code == 403
    assert (await client.post("/auth/sudo/password", json={"password": "wrong-password"}, headers=headers)).status_code == 401
    await elevate(client, tokens)
    status = (await client.get("/auth/sudo", headers=headers)).json()["data"]
    assert status["active"] is True and status["method"] == "password"

    other = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()["tokens"]
    assert (await client.get("/auth/sudo", headers=auth(other))).json()["data"]["active"] is False

    r = await client.post("/auth/identifiers/email", json={"email": "b@example.com"}, headers=headers)
    assert r.status_code == 200
    assert (await client.get("/auth/sudo", headers=headers)).json()["data"]["active"] is True
    primary = (await client.get("/auth/identifiers", headers=headers)).json()["data"][0]
    assert (await client.delete(f"/auth/identifiers/{primary['id']}", headers=headers)).status_code == 400
    assert (await client.get("/auth/sudo", headers=headers)).json()["data"]["active"] is True


async def test_sudo_with_email_otp(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    options = (await client.get("/auth/sudo/options", headers=headers)).json()["data"]["methods"]
    assert {o["kind"] for o in options} == {"password", "otp"}
    assert "a@example.com" not in str(options)
    assert (await client.post("/auth/sudo/otp/request", json={"channel": "email"}, headers=headers)).status_code == 200
    code = outbox.code_for("a@example.com")
    r = await client.post("/auth/sudo/otp/confirm", json={"channel": "email", "code": code}, headers=headers)
    assert r.json()["data"]["method"] == "otp"


async def _enable_totp(client, outbox) -> tuple[dict, str, list[str]]:
    tokens = await verified_user(client, outbox)
    await elevate(client, tokens)
    enrollment = (await client.post("/auth/2fa/enroll/totp", headers=auth(tokens))).json()["data"]
    assert enrollment["qrDataUrl"].startswith("data:image/png")
    secret = enrollment["secret"]
    r = await client.post("/auth/2fa/enroll/totp/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=auth(tokens))
    codes = r.json()["data"]["backupCodes"]
    assert len(codes) == 10
    return tokens, secret, codes


async def test_totp_login_challenge(client, outbox):
    _, secret, _ = await _enable_totp(client, outbox)
    r = await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})
    body = r.json()
    assert "tokens" not in body and body["methods"] == ["TOTP"]
    verify = {"challengeId": body["challengeId"], "type": "TOTP"}
    assert (await client.post("/auth/2fa/challenge/verify", json={**verify, "code": "000000"})).status_code == 401
    # Enrollment spent the current step's code; the next step's code is still inside the window.
    code = pyotp.TOTP(secret).at(int(time.time()) + 30)
    r = await client.post("/auth/2fa/challenge/verify", json={**verify, "code": code})
    assert r.status_code == 200 and r.json()["tokens"]["access"]["token"]
    assert (await client.post("/auth/2fa/challenge/verify", json={**verify, "code": code})).status_code == 401


async def test_backup_code_works_once(client, outbox):
    tokens, _, codes = await _enable_totp(client, outbox)
    assert (await client.get("/auth/2fa/backup-codes", headers=auth(tokens))).json()["data"]["remaining"] == 10

    async def try_code() -> int:
        body = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()
        verify = {"challengeId": body["challengeId"], "type": "TOTP", "code": codes[0]}
        return (await client.post("/auth/2fa/challenge/verify", json=verify)).status_code

    assert await try_code() == 200
    assert await try_code() == 401
    assert (await client.get("/auth/2fa/backup-codes", headers=auth(tokens))).json()["data"]["remaining"] == 9


async def test_challenge_stops_after_too_many_wrong_codes(client, outbox):
    await _enable_totp(client, outbox)
    body = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()
    verify = {"challengeId": body["challengeId"], "type": "TOTP", "code": "000000"}
    statuses = [(await client.post("/auth/2fa/challenge/verify", json=verify)).status_code for _ in range(6)]
    assert statuses == [401, 401, 401, 401, 429, 401]


async def test_email_otp_two_factor_and_disable(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    await elevate(client, tokens)
    await cache.delete_match(key("otp:*"))
    assert (await client.post("/auth/2fa/enroll/email/request", headers=headers)).status_code == 200
    r = await client.post("/auth/2fa/enroll/email/confirm", json={"code": outbox.code_for("a@example.com")}, headers=headers)
    assert len(r.json()["data"]["backupCodes"]) == 10
    method = (await client.get("/auth/2fa/methods", headers=headers)).json()["data"][0]
    assert method["destination"] != "a@example.com" and "*" in method["destination"]

    body = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()
    challenge = {"challengeId": body["challengeId"], "type": "EMAIL_OTP"}
    assert (await client.post("/auth/2fa/challenge/send", json=challenge)).status_code == 200
    r = await client.post("/auth/2fa/challenge/verify", json={**challenge, "code": outbox.code_for("a@example.com")})
    assert r.status_code == 200

    assert (await client.delete(f"/auth/2fa/methods/{method['id']}", headers=headers)).status_code == 200
    assert (await client.get("/auth/sudo", headers=headers)).json()["data"]["active"] is False
    assert (await client.get("/auth/2fa/backup-codes", headers=headers)).json()["data"]["remaining"] == 0
    r = await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})
    assert "tokens" in r.json()


async def test_password_reset_by_code_and_link_ends_sessions(client, outbox):
    tokens = await verified_user(client, outbox)
    await cache.delete_match(key("otp:*"))
    forgot = (await client.post("/auth/password/forgot", json={"identifier": "a@example.com"})).json()["data"]
    assert forgot["channels"][0]["hint"] != "a@example.com"
    send = {"resetId": forgot["resetId"], "channelId": forgot["channels"][0]["id"]}
    assert (await client.post("/auth/password/forgot/send", json=send)).status_code == 200
    r = await client.post(
        "/auth/password/reset/otp",
        json={"resetId": forgot["resetId"], "code": outbox.code_for("a@example.com"), "password": "brand-new-password"},
    )
    assert r.status_code == 200, r.text
    assert (await client.post("/auth/refresh", json={"refreshToken": tokens["refresh"]["token"]})).status_code == 401
    assert (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).status_code == 401
    new_login = {"email": "a@example.com", "password": "brand-new-password"}
    assert (await client.post("/auth/login", json=new_login)).status_code == 200

    await cache.delete_match(key("otp:*"))
    forgot = (await client.post("/auth/password/forgot", json={"identifier": "a@example.com"})).json()["data"]
    send = {"resetId": forgot["resetId"], "channelId": forgot["channels"][0]["id"]}
    await client.post("/auth/password/forgot/send", json=send)
    reset = {"token": outbox.token_for("a@example.com"), "password": "third-password-x"}
    r = await client.post("/auth/password/reset", json=reset)
    assert r.status_code == 200


async def test_forgot_does_not_send_for_unknown_or_unverified_accounts(client, outbox):
    await register(client)
    sent = len(outbox)
    for identifier in ("a@example.com", "nobody@example.com"):
        r = await client.post("/auth/password/forgot", json={"identifier": identifier})
        data = r.json()["data"]
        assert r.status_code == 200 and len(data["channels"]) == 1 and data["channels"][0]["type"] == "EMAIL"
        send = {"resetId": data["resetId"], "channelId": data["channels"][0]["id"]}
        assert (await client.post("/auth/password/forgot/send", json=send)).status_code == 200
    assert len(outbox) == sent


async def test_password_change_rules(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    wrong = {"currentPassword": "wrong-password", "newPassword": "brand-new-password"}
    assert (await client.patch("/auth/password/change", json=wrong, headers=headers)).status_code == 401
    same = {"currentPassword": PASSWORD, "newPassword": PASSWORD}
    assert (await client.patch("/auth/password/change", json=same, headers=headers)).status_code == 400
    good = {"currentPassword": PASSWORD, "newPassword": "brand-new-password"}
    assert (await client.patch("/auth/password/change", json=good, headers=headers)).status_code == 200
    assert (await client.post("/auth/refresh", json={"refreshToken": tokens["refresh"]["token"]})).status_code == 401


async def test_add_set_primary_and_remove_identifier(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    await elevate(client, tokens)
    assert (await client.post("/auth/identifiers/email", json={"email": "b@example.com"}, headers=headers)).status_code == 200
    r = await client.post("/auth/identifiers/email/confirm", json={"token": outbox.token_for("b@example.com")})
    assert r.status_code == 200
    rows = (await client.get("/auth/identifiers", headers=headers)).json()["data"]
    second = next(i for i in rows if i["value"] == "b@example.com")
    assert second["isPrimary"] is False and second["isVerified"] is True

    assert (await client.delete(f"/auth/identifiers/{second['id']}", headers=headers)).status_code == 200
    r = await client.delete(f"/auth/identifiers/{second['id']}", headers=headers)
    assert r.status_code == 403  # The successful delete spent the sudo grant.


async def test_email_change_notifies_old_address_and_moves_login(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    await elevate(client, tokens)
    r = await client.post("/auth/email/change/request", json={"email": "new@example.com"}, headers=headers)
    assert r.status_code == 200
    assert "new@example.com" in outbox.latest("a@example.com")["text"]
    r = await client.post("/auth/email/change/confirm", json={"token": outbox.token_for("new@example.com")})
    assert r.json()["data"]["email"] == "new@example.com"
    assert (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).status_code == 401
    assert (await client.post("/auth/login", json={"email": "new@example.com", "password": PASSWORD})).status_code == 200
    assert (await client.post("/auth/refresh", json={"refreshToken": tokens["refresh"]["token"]})).status_code == 401


async def test_phone_change(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    await elevate(client, tokens)
    assert (await client.post("/auth/phone/change/request", json={"phone": "+14155552671"}, headers=headers)).status_code == 200
    r = await client.post("/auth/phone/change/confirm", json={"code": outbox.code_for("+14155552671")}, headers=headers)
    assert r.status_code == 200, r.text


async def test_unverified_account_can_still_delete_itself(client):
    tokens = await register(client)
    headers = auth(tokens)
    assert (await client.post("/auth/account/deactivate", headers=headers)).status_code == 403
    await elevate(client, tokens)
    assert (await client.post("/auth/account/deactivate", headers=headers)).status_code == 200
    assert (await client.get("/auth/me", headers=headers)).status_code == 401
    assert (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).status_code == 401


async def test_deleted_accounts_release_identifiers_only_after_the_grace_period(client):
    tokens = await register(client)
    await elevate(client, tokens)
    await client.post("/auth/account/deactivate", headers=auth(tokens))
    async with SessionLocal() as db:
        assert await identifiers.reclaim_identifiers(db) == 0
        await db.execute(update(User).values(deleted_at=utcnow().replace(year=2000)))
        await db.commit()
        assert await identifiers.reclaim_identifiers(db) == 1
        assert await db.scalar(select(UserIdentifier)) is None


# OAuth, against locally generated provider keys

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_ISSUERS = {AuthProvider.GOOGLE: "https://accounts.google.com", AuthProvider.APPLE: "https://appleid.apple.com"}


class _FakeJwks:
    def get_signing_key_from_jwt(self, _):
        return type("Key", (), {"key": _KEY.public_key()})


@pytest.fixture
def provider_keys(monkeypatch):
    for provider in oauth._jwks:
        monkeypatch.setitem(oauth._jwks, provider, _FakeJwks())


def _id_token(provider=AuthProvider.GOOGLE, sub="sub-1", email="o@example.com", verified=True, aud=None, key_=_KEY, **extra):
    now = int(time.time())
    claims = {
        "iss": _ISSUERS[provider], "aud": aud or f"{provider.value.lower()}-client", "sub": sub,
        "iat": now, "exp": now + 600, "email": email, "email_verified": verified, **extra,
    }  # fmt: skip
    return jwt.encode(claims, key_, algorithm="RS256")


async def test_oauth_creates_a_verified_account_then_logs_in(client, provider_keys):
    r = await client.post("/auth/oauth/google", json={"idToken": _id_token(name="Olu")})
    body = r.json()
    assert r.status_code == 200, r.text
    assert body["data"]["isAccountVerified"] is True and body["data"]["name"] == "Olu"
    again = await client.post("/auth/oauth/google", json={"idToken": _id_token()})
    assert again.json()["data"]["id"] == body["data"]["id"]


async def test_apple_string_email_verified_claim(client, provider_keys):
    r = await client.post("/auth/oauth/apple", json={"idToken": _id_token(AuthProvider.APPLE, verified="true")})
    assert r.status_code == 200 and r.json()["data"]["isAccountVerified"] is True


@pytest.mark.parametrize(
    "token_args",
    [
        {"aud": "someone-else"},
        {"exp": 1000},
        {"iss": "https://evil.example.com"},
        {"key_": rsa.generate_private_key(public_exponent=65537, key_size=2048)},
    ],
)
async def test_oauth_rejects_bad_tokens(client, provider_keys, token_args):
    r = await client.post("/auth/oauth/google", json={"idToken": _id_token(**token_args)})
    assert r.status_code == 401


async def test_oauth_never_takes_over_an_existing_email(client, provider_keys):
    await register(client, "o@example.com")
    assert (await client.post("/auth/oauth/google", json={"idToken": _id_token()})).status_code == 409


async def test_oauth_rejects_unverified_email(client, provider_keys):
    assert (await client.post("/auth/oauth/google", json={"idToken": _id_token(verified=False)})).status_code == 400


async def test_link_and_unlink_keep_a_way_in(client, provider_keys, outbox):
    tokens = (await client.post("/auth/oauth/google", json={"idToken": _id_token()})).json()["tokens"]
    headers = auth(tokens)
    assert (await client.delete("/auth/oauth/google", headers=headers)).status_code == 403
    await cache.delete_match(key("otp:*"))
    await client.post("/auth/sudo/otp/request", json={"channel": "email"}, headers=headers)
    code = outbox.code_for("o@example.com")
    await client.post("/auth/sudo/otp/confirm", json={"channel": "email", "code": code}, headers=headers)

    assert (await client.delete("/auth/oauth/google", headers=headers)).status_code == 400
    apple = _id_token(AuthProvider.APPLE, sub="apple-1", email="x@example.com")
    assert (await client.post("/auth/oauth/apple/link", json={"idToken": apple}, headers=headers)).status_code == 200
    assert (await client.delete("/auth/oauth/google", headers=headers)).status_code == 200
    assert (await client.post("/auth/oauth/apple", json={"idToken": apple})).status_code == 200


async def test_audit_rows_carry_who_did_what(client, outbox):
    await register(client)
    await client.post("/auth/login", json={"email": "a@example.com", "password": "wrong-password"})
    actions = {row["action"]: row for row in outbox.audit}
    assert "register" in actions and actions["login.fail"]["outcome"] == "FAILURE"
    assert actions["register"]["ip_address"] == "127.0.0.1"
    assert PASSWORD not in str(outbox.audit)
