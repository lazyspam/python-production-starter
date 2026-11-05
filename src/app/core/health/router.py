import time
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from app.common.schemas import Envelope, Schema
from app.database.session import SessionLocal
from app.infrastructure.cache import cache

router = APIRouter(prefix="/health", tags=["health"])

_started = time.monotonic()


class Liveness(Schema):
    status: Literal["ok"] = "ok"
    uptime_seconds: int
    timestamp: str


class Checks(Schema):
    database: Literal["up", "down"]
    redis: Literal["up", "down"]


class Readiness(Liveness):
    checks: Checks


def _liveness() -> dict:
    return {"uptime_seconds": int(time.monotonic() - _started), "timestamp": datetime.now(UTC).isoformat()}


@router.get("/liveness")
async def liveness() -> Envelope[Liveness]:
    return Envelope(data=Liveness(**_liveness()))


@router.get("/readiness")
async def readiness() -> Envelope[Readiness]:
    checks = {"database": "down", "redis": "down"}
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "up"
        await cache.ping()
        checks["redis"] = "up"
    except Exception as exc:
        down = ", ".join(name for name, state in checks.items() if state == "down")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Service not ready: {down} unavailable",
        ) from exc
    return Envelope(data=Readiness(**_liveness(), checks=Checks(**checks)))
