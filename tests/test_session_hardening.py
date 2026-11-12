import asyncio
import hashlib
from unittest.mock import AsyncMock

from app.common.security import sha256
from app.core.auth.services import sessions, tokens
from app.database.session import SessionLocal
from app.infrastructure.cache import cache, key
from tests.conftest import PASSWORD, auth, register, verified_user
from tests.test_auth import _id_token, provider_keys  # noqa: F401


async def test_concurrent_refresh_with_one_token_yields_at_most_one_session(client):
    first = await register(client)
    body = {"refreshToken": first["refresh"]["token"]}
    a, b = await asyncio.gather(client.post("/auth/refresh", json=body), client.post("/auth/refresh", json=body))
    assert sorted([a.status_code, b.status_code]) in ([200, 401], [401, 401])


async def test_access_token_rejected_after_logout_all_and_after_logout(client):
    tokens_ = await register(client)
    headers = auth(tokens_)
    assert (await client.get("/auth/me", headers=headers)).status_code == 200
    assert (await client.post("/auth/logout-all", headers=headers)).status_code == 200
    assert (await client.get("/auth/me", headers=headers)).status_code == 401

    other = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()["tokens"]
    await client.post("/auth/logout", json={"refreshToken": other["refresh"]["token"]})
    assert (await client.get("/auth/me", headers=auth(other))).status_code == 401


async def test_access_token_rejected_after_revoking_its_session_and_after_password_change(client, outbox):
    first = await verified_user(client, outbox)
    second = (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).json()["tokens"]
    listed = (await client.get("/auth/sessions", headers=auth(first))).json()["data"]
    other_id = next(s["id"] for s in listed if not s["current"])
    assert (await client.delete(f"/auth/sessions/{other_id}", headers=auth(first))).status_code == 200
    assert (await client.get("/auth/me", headers=auth(second))).status_code == 401
    assert (await client.delete(f"/auth/sessions/{other_id}", headers=auth(first))).status_code == 401

    change = {"currentPassword": PASSWORD, "newPassword": "brand-new-password"}
    assert (await client.patch("/auth/password/change", json=change, headers=auth(first))).status_code == 200
    assert (await client.get("/auth/me", headers=auth(first))).status_code == 401


async def test_rotated_refresh_ends_the_old_access_token(client):
    first = await register(client)
    assert (await client.post("/auth/refresh", json={"refreshToken": first["refresh"]["token"]})).status_code == 200
    assert (await client.get("/auth/me", headers=auth(first))).status_code == 401


async def test_socket_authorization_checks_session_and_account(client):
    tokens_ = await register(client)
    async with SessionLocal() as db:
        assert await sessions.authorize_socket(db, tokens_["access"]["token"]) is not None
        assert await sessions.authorize_socket(db, "not-a-token") is None
    await client.post("/auth/logout-all", headers=auth(tokens_))
    async with SessionLocal() as db:
        assert await sessions.authorize_socket(db, tokens_["access"]["token"]) is None


async def test_revocation_disconnects_the_sessions_sockets(client, monkeypatch):
    tokens_ = await register(client)
    me = (await client.get("/auth/sessions", headers=auth(tokens_))).json()["data"][0]["id"]
    await cache.set_add(key(f"sockets:{me}"), "socket-1", "socket-2")
    disconnect = AsyncMock()
    monkeypatch.setattr("app.infrastructure.realtime.sio.disconnect", disconnect)
    await client.post("/auth/logout-all", headers=auth(tokens_))
    assert sorted(call.args[0] for call in disconnect.await_args_list) == ["socket-1", "socket-2"]


async def test_one_ip_cannot_lock_the_owner_out_everywhere(client):
    await register(client)
    identity = sha256("a@example.com")
    await cache.set(key(f"login:fail:{identity}:10.0.0.9"), 10, expire=60)
    good = {"email": "a@example.com", "password": PASSWORD}
    assert (await client.post("/auth/login", json=good)).status_code == 200

    await cache.set(key(f"login:fail:{identity}"), 100, expire=60)
    assert (await client.post("/auth/login", json=good)).status_code == 429


async def test_failed_logins_count_per_ip_and_per_identity(client):
    await register(client)
    for _ in range(2):
        await client.post("/auth/login", json={"email": "a@example.com", "password": "wrong-password"})
    identity = sha256("a@example.com")
    assert int(await cache.get(key(f"login:fail:{identity}:127.0.0.1")) or 0) == 2
    assert int(await cache.get(key(f"login:fail:{identity}")) or 0) == 2


async def test_forgot_looks_the_same_for_known_and_unknown_accounts(client, outbox):
    await verified_user(client, outbox)
    await client.post("/auth/register", json={"phone": "+14155552671", "password": PASSWORD})
    known = (await client.post("/auth/password/forgot", json={"identifier": "a@example.com"})).json()
    unknown = (await client.post("/auth/password/forgot", json={"identifier": "b@example.com"})).json()
    assert known["message"] == unknown["message"]
    for body in (known, unknown):
        channels = body["data"]["channels"]
        assert len(channels) == 1 and channels[0]["type"] == "EMAIL" and set(channels[0]) == {"id", "type", "hint"}
        assert len(channels[0]["id"]) == 36

    sent = len(outbox)
    send = {"resetId": unknown["data"]["resetId"], "channelId": unknown["data"]["channels"][0]["id"]}
    assert (await client.post("/auth/password/forgot/send", json=send)).status_code == 200
    assert (await client.post("/auth/password/forgot/send", json=send)).status_code == 429
    assert len(outbox) == sent
    wrong = {"resetId": unknown["data"]["resetId"], "code": "123456", "password": "brand-new-password"}
    assert (await client.post("/auth/password/reset/otp", json=wrong)).status_code == 401


async def test_password_change_and_session_revocation_share_one_commit(client, outbox, monkeypatch):
    """If revoking sessions fails, the new password must not be saved either."""
    first = await verified_user(client, outbox)
    monkeypatch.setattr(tokens.fcm_token_repo, "delete_for_user", AsyncMock(side_effect=RuntimeError("db error")))
    change = {"currentPassword": PASSWORD, "newPassword": "brand-new-password"}
    try:
        r = await client.patch("/auth/password/change", json=change, headers=auth(first))
        assert r.status_code == 500
    except RuntimeError:
        pass  # raised through the test transport when no catch-all error middleware is installed
    monkeypatch.undo()
    assert (await client.post("/auth/login", json={"email": "a@example.com", "password": PASSWORD})).status_code == 200
    assert (await client.get("/auth/me", headers=auth(first))).status_code == 200


async def test_registration_race_is_a_conflict_not_a_server_error(client, monkeypatch):
    from app.core.auth.repositories import identifier as identifier_repo

    real = identifier_repo.find_identifier
    calls = {"n": 0}

    async def first_check_misses(*args, **kwargs):
        calls["n"] += 1
        return None if calls["n"] == 1 else await real(*args, **kwargs)

    await register(client)
    monkeypatch.setattr(identifier_repo, "find_identifier", first_check_misses)
    r = await client.post("/auth/register", json={"email": "a@example.com", "password": PASSWORD})
    assert r.status_code == 409


async def test_oauth_nonce(client, provider_keys):  # noqa: F811
    raw = "client-nonce-123"
    ok = await client.post("/auth/oauth/google", json={"idToken": _id_token(nonce=raw), "nonce": raw})
    assert ok.status_code == 200, ok.text
    hashed = _id_token(nonce=hashlib.sha256(raw.encode()).hexdigest())
    assert (await client.post("/auth/oauth/google", json={"idToken": hashed, "nonce": raw})).status_code == 200
    bad = await client.post("/auth/oauth/google", json={"idToken": _id_token(nonce="other-nonce"), "nonce": raw})
    assert bad.status_code == 401


async def test_oauth_first_sign_in_race_logs_in_the_existing_account(client, provider_keys, monkeypatch):  # noqa: F811
    from app.core.auth.services import oauth

    created = (await client.post("/auth/oauth/google", json={"idToken": _id_token()})).json()["data"]["id"]
    real = oauth.credential_repo.find_credential_by_identity
    calls = {"n": 0}

    async def first_lookup_misses(*args, **kwargs):
        calls["n"] += 1
        return None if calls["n"] == 1 else await real(*args, **kwargs)

    monkeypatch.setattr(oauth.credential_repo, "find_credential_by_identity", first_lookup_misses)
    monkeypatch.setattr(oauth.identifier_repo, "find_identifier", AsyncMock(return_value=None))
    r = await client.post("/auth/oauth/google", json={"idToken": _id_token()})
    assert r.status_code == 200 and r.json()["data"]["id"] == created


async def test_auth_responses_are_not_cacheable(client):
    r = await client.post("/auth/register", json={"email": "a@example.com", "password": PASSWORD})
    assert r.headers["cache-control"] == "no-store" and r.headers["pragma"] == "no-cache"
    me = await client.get("/auth/me", headers=auth(r.json()["tokens"]))
    assert me.headers["cache-control"] == "no-store"
