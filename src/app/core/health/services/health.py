import time
from datetime import UTC, datetime

from fastapi import HTTPException, status

from app.core.health.repositories import health as health_repo
from app.database.session import SessionLocal
from app.infrastructure.cache import cache

_started = time.monotonic()


def liveness() -> dict:
    return {"uptime_seconds": int(time.monotonic() - _started), "timestamp": datetime.now(UTC).isoformat()}


async def readiness() -> dict:
    checks = {"database": "down", "redis": "down"}
    try:
        async with SessionLocal() as session:
            await health_repo.ping(session)
        checks["database"] = "up"
        await cache.ping()
        checks["redis"] = "up"
    except Exception as exc:
        down = ", ".join(name for name, state in checks.items() if state == "down")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Service not ready: {down} unavailable",
        ) from exc
    return {**liveness(), "checks": checks}
