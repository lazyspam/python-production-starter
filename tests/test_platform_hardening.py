from datetime import timedelta
from types import SimpleNamespace
from typing import cast

from bullmq import Job
from sqlalchemy import select

from app.core.audit.models import Activity, AuditOutcome
from app.core.audit.services.audit import scrub_deleted_users
from app.core.auth.models import User
from app.core.files.models import FileObject, FileStatus
from app.core.files.services.files import cleanup_pending
from app.database.session import SessionLocal, utcnow
from app.worker import process_maintenance
from tests.conftest import auth, register, verified_user

FRONTEND = "http://localhost:5173"


async def test_cookie_writes_need_a_trusted_origin(client):
    tokens = await register(client)
    client.cookies.set("access_token", tokens["access"]["token"])

    # DELETE /auth/sudo is cookie-authenticated and leaves the cookies in place, so every call below sends one.
    missing = await client.delete("/auth/sudo")
    assert missing.status_code == 403 and missing.json()["success"] is False
    assert (await client.delete("/auth/sudo", headers={"Origin": "https://evil.example"})).status_code == 403
    assert (await client.delete("/auth/sudo", headers={"Referer": "https://evil.example/x"})).status_code == 403
    assert (await client.delete("/auth/sudo", headers={"Origin": FRONTEND})).status_code == 200
    assert (await client.delete("/auth/sudo", headers={"Referer": f"{FRONTEND}/settings"})).status_code == 200
    # Reads are never blocked.
    assert (await client.get("/auth/me")).status_code == 200


async def test_bearer_and_cookieless_writes_skip_the_origin_check(client):
    tokens = await register(client)
    assert (await client.post("/auth/logout", json={})).status_code == 200
    client.cookies.set("access_token", tokens["access"]["token"])
    assert (await client.post("/auth/logout-all", headers=auth(tokens))).status_code == 200


async def test_unhandled_errors_keep_cors_and_security_headers(client, monkeypatch):
    def boom() -> dict:
        raise RuntimeError("boom")

    monkeypatch.setattr("app.core.health.services.health.liveness", boom)
    r = await client.get("/health/liveness", headers={"Origin": FRONTEND})
    assert r.status_code == 500
    assert r.json() == {"success": False, "statusCode": 500, "message": "boom", "data": None}
    assert r.headers["access-control-allow-origin"] == FRONTEND
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-request-id"]


async def test_public_and_private_uploads_use_separate_prefixes(client, outbox):
    headers = auth(await verified_user(client, outbox))
    body = {"filename": "a.png", "contentType": "image/png", "size": 10}
    private = await client.post("/files/upload-url", json=body, headers=headers)
    public = await client.post("/files/upload-url", json={**body, "visibility": "PUBLIC"}, headers=headers)
    assert private.json()["data"]["file"]["key"].startswith("uploads/private/")
    assert public.json()["data"]["file"]["key"].startswith("uploads/public/")


async def test_cleanup_removes_only_stale_pending_uploads(monkeypatch):
    deleted: list[str] = []

    async def fake_delete(key: str) -> None:
        if key == "fails":
            raise RuntimeError("s3 down")
        deleted.append(key)

    monkeypatch.setattr("app.infrastructure.storage.delete_object", fake_delete)
    old = utcnow() - timedelta(days=3)
    rows = [
        ("stale", FileStatus.PENDING, old),
        ("fails", FileStatus.PENDING, old),
        ("fresh", FileStatus.PENDING, utcnow()),
        ("done", FileStatus.UPLOADED, old),
    ]
    async with SessionLocal() as db:
        for key, status, created in rows:
            db.add(FileObject(owner_id="u", key=key, bucket="b", content_type="image/png", status=status, created_at=created))
        await db.commit()
        assert await cleanup_pending(db) == 1
        remaining = set(await db.scalars(select(FileObject.key)))
    assert deleted == ["stale"]
    assert remaining == {"fails", "fresh", "done"}


async def test_audit_rows_of_long_deleted_users_lose_personal_data():
    async with SessionLocal() as db:
        gone = User(is_deleted=True, deleted_at=utcnow() - timedelta(days=60))
        recent = User(is_deleted=True, deleted_at=utcnow() - timedelta(days=1))
        active = User()
        db.add_all([gone, recent, active])
        await db.flush()
        for user in (gone, recent, active):
            db.add(Activity(
                module="auth", action="register", outcome=AuditOutcome.SUCCESS, user_id=user.id,
                metadata_={"email": f"{user.id}@example.com"}, ip_address="1.2.3.4", user_agent="ua",
            ))  # fmt: skip
        await db.commit()
        assert await scrub_deleted_users(db) == 1
        rows = {a.user_id: a for a in await db.scalars(select(Activity).execution_options(populate_existing=True))}
    assert rows[gone.id].metadata_ is None and rows[gone.id].ip_address is None and rows[gone.id].user_agent is None
    assert rows[gone.id].action == "register"
    assert rows[recent.id].metadata_ and rows[active.id].ip_address == "1.2.3.4"


async def test_maintenance_jobs_dispatch_by_name():
    assert await process_maintenance(cast(Job, SimpleNamespace(name="scrub-audit")), "t") == 0
    assert await process_maintenance(cast(Job, SimpleNamespace(name="nope")), "t") == 0
