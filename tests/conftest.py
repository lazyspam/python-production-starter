"""Runs against real Postgres and Redis, from DATABASE_URL and REDIS_URL. Both are wiped: never point at real data."""

import os
import re

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("JWT_ACCESS_SECRET", "test-access-secret-test-access-secret-0123")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-test-refresh-secret-01")
os.environ.setdefault("AUTH_ENCRYPTION_KEY", "kCwVmC2rOjTg2Pxv5wJp1hTz0zLx9qUeR7nBvYc3sWQ=")
os.environ.setdefault("GOOGLE_CLIENT_IDS", "google-client")
os.environ.setdefault("APPLE_CLIENT_IDS", "apple-client")
os.environ.setdefault("S3_ACCESS_KEY_ID", "test")
os.environ.setdefault("S3_SECRET_ACCESS_KEY", "test")

import httpx
import pytest
from sqlalchemy import text

from app.database.session import Base, engine
from app.infrastructure.cache import cache
from app.main import app

API = "/api/v1"
BEARER = {"X-Auth-Transport": "bearer"}
PASSWORD = "correct-horse-battery"


class Outbox(list):
    """Everything the app queued, instead of a real queue. `code_for` reads the latest code sent to someone."""

    def latest(self, to: str) -> dict:
        return next(m for m in reversed(self) if m.get("to") == to)

    def code_for(self, to: str) -> str:
        message = self.latest(to)
        return re.search(r"\b(\d{6})\b", message.get("text") or message["body"]).group(1)

    def token_for(self, to: str) -> str:
        return re.search(r"token=([0-9a-f]+)", self.latest(to)["text"]).group(1)


@pytest.fixture(scope="session", autouse=True)
async def schema():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


@pytest.fixture(autouse=True)
async def clean():
    tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {tables} CASCADE"))  # noqa: S608
    await cache.clear()


@pytest.fixture(autouse=True)
def outbox(monkeypatch) -> Outbox:
    box = Outbox()
    audit: list = []

    async def fake_enqueue(queue: str, job: str, data: dict) -> None:
        box.append(data)

    async def fake_audit_enqueue(queue: str, job: str, data: dict) -> None:
        audit.append(data)

    monkeypatch.setattr("app.infrastructure.messaging.enqueue", fake_enqueue)
    monkeypatch.setattr("app.core.audit.service.enqueue", fake_audit_enqueue)
    box.audit = audit
    return box


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1234))
    async with httpx.AsyncClient(transport=transport, base_url=f"http://test{API}", headers=BEARER) as c:
        yield c


def auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access']['token']}"}


async def register(client, email="a@example.com", password=PASSWORD) -> dict:
    r = await client.post("/auth/register", json={"email": email, "password": password, "name": "A"})
    assert r.status_code == 201, r.text
    return r.json()["tokens"]


async def verified_user(client, outbox, email="a@example.com") -> dict:
    tokens = await register(client, email)
    r = await client.post("/auth/email/verify/otp", json={"email": email, "code": outbox.code_for(email)})
    assert r.status_code == 200, r.text
    return tokens


async def elevate(client, tokens, password=PASSWORD) -> None:
    r = await client.post("/auth/sudo/password", json={"password": password}, headers=auth(tokens))
    assert r.status_code == 200, r.text
