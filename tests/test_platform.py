import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

from bullmq import Worker
from sqlalchemy import select

from app.core.audit.models import Activity
from app.core.audit.services.audit import write
from app.core.fcm_token.models import FcmToken
from app.database.session import SessionLocal
from app.infrastructure.cache import cache
from app.infrastructure.queue import AUDIT_QUEUE, close_queues, get_queue, worker_options
from app.locals import msg
from app.worker import PROCESSORS
from tests.conftest import auth, verified_user


def test_every_message_used_in_code_exists():
    src = Path(__file__).parent.parent / "src" / "app"
    missing = []
    for path in src.rglob("*.py"):
        for section, name in re.findall(r"\bmsg\.(\w+)\.(\w+)", path.read_text()):
            if not hasattr(getattr(msg, section, SimpleNamespace()), name):
                missing.append(f"{path.name}: msg.{section}.{name}")
    assert not missing


async def test_errors_use_the_envelope_and_responses_have_security_headers(client):
    r = await client.get("/does-not-exist")
    assert r.status_code == 404 and r.json()["success"] is False and r.json()["statusCode"] == 404
    r = await client.get("/health/liveness")
    assert r.json()["success"] is True
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-request-id"]


async def test_readiness_checks_database_and_redis(client):
    r = await client.get("/health/readiness")
    assert r.status_code == 200, r.text


async def test_routes_are_rate_limited(client):
    statuses = [(await client.post("/auth/password/forgot", json={"identifier": "a@example.com"})).status_code for _ in range(6)]
    assert statuses == [200] * 5 + [429]


async def test_cache_decorator_and_redis_values_round_trip():
    calls = []

    @cache(ttl="1m", key="test:{value}")
    async def expensive(value: int) -> dict:
        calls.append(value)
        return {"value": value}

    assert await expensive(1) == await expensive(1) == {"value": 1}
    assert calls == [1]


async def test_fcm_sync_is_idempotent_and_owner_scoped(client, outbox):
    tokens = await verified_user(client, outbox)
    headers = auth(tokens)
    body = {"token": "t" * 40, "deviceId": "device-1", "platform": "android"}
    first = await client.post("/fcm-tokens", json=body, headers=headers)
    second = await client.post("/fcm-tokens", json=body, headers=headers)
    assert first.status_code == 201, first.text
    assert first.json()["data"]["id"] == second.json()["data"]["id"]
    assert first.json()["data"]["platform"] == "android"
    r = await client.post("/fcm-tokens", json={**body, "token": "u" * 40}, headers=headers)
    assert r.json()["data"]["id"] == first.json()["data"]["id"]

    other = await verified_user(client, outbox, "b@example.com")
    await client.request("DELETE", "/fcm-tokens", json={"token": "u" * 40}, headers=auth(other))
    async with SessionLocal() as db:
        assert await db.scalar(select(FcmToken)) is not None

    await client.post("/auth/logout-all", headers=headers)
    async with SessionLocal() as db:
        assert await db.scalar(select(FcmToken)) is None


async def test_file_upload_flow_with_presigned_urls_and_ownership(client, outbox, monkeypatch):
    sizes = {}

    async def fake_size(key: str) -> int | None:
        return sizes.get(key)

    deleted = []

    async def fake_delete(key: str) -> None:
        deleted.append(key)

    monkeypatch.setattr("app.infrastructure.storage.get_object_size", fake_size)
    monkeypatch.setattr("app.infrastructure.storage.delete_object", fake_delete)

    headers = auth(await verified_user(client, outbox))
    rejected = await client.post(
        "/files/upload-url", json={"filename": "x.exe", "contentType": "application/x-msdownload", "size": 10}, headers=headers
    )
    assert rejected.status_code == 400
    too_big = await client.post(
        "/files/upload-url", json={"filename": "x.png", "contentType": "image/png", "size": 10**10}, headers=headers
    )
    assert too_big.status_code == 400

    r = await client.post(
        "/files/upload-url", json={"filename": "../../etc/pass wd.png", "contentType": "image/png", "size": 10}, headers=headers
    )
    assert r.status_code == 201, r.text
    data = r.json()["data"]
    file_id = data["file"]["id"]
    assert "X-Amz-Signature" in data["upload"]["url"]
    key = data["file"]["key"]
    assert ".." not in key and " " not in key

    assert (await client.get(f"/files/{file_id}/download-url", headers=headers)).status_code == 400
    assert (await client.post(f"/files/{file_id}/complete", headers=headers)).status_code == 400
    sizes[key] = 10
    assert (await client.post(f"/files/{file_id}/complete", headers=headers)).status_code == 201
    download = await client.get(f"/files/{file_id}/download-url", headers=headers)
    assert "X-Amz-Signature" in download.json()["data"]["url"]

    stranger = auth(await verified_user(client, outbox, "b@example.com"))
    assert (await client.get(f"/files/{file_id}/download-url", headers=stranger)).status_code == 404
    assert (await client.delete(f"/files/{file_id}", headers=stranger)).status_code == 404
    assert len((await client.get("/files", headers=headers)).json()["data"]) == 1
    assert (await client.delete(f"/files/{file_id}", headers=headers)).status_code == 200
    assert deleted == [key]


async def test_real_queue_and_worker_write_an_audit_row():
    """No fakes: a job goes through BullMQ on Redis to a real worker and into Postgres."""
    worker = Worker(AUDIT_QUEUE, PROCESSORS[AUDIT_QUEUE], worker_options())
    data = {
        "module": "auth", "action": "queue.test", "outcome": "SUCCESS", "user_id": None, "resource_type": None,
        "resource_id": None, "metadata_": {"x": 1}, "ip_address": None, "user_agent": None, "request_id": None,
    }  # fmt: skip
    await get_queue(AUDIT_QUEUE).add("record", data)
    try:
        async with SessionLocal() as db:
            for _ in range(50):
                row = await db.scalar(select(Activity).where(Activity.action == "queue.test"))
                if row:
                    break
                await asyncio.sleep(0.1)
        assert row is not None and row.metadata_ == {"x": 1}
    finally:
        await worker.close()
        await close_queues()


async def test_audit_write_stores_a_row():
    await write({"module": "auth", "action": "direct", "outcome": "SUCCESS"})
    async with SessionLocal() as db:
        assert await db.scalar(select(Activity).where(Activity.action == "direct")) is not None
