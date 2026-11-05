from fastapi import APIRouter

from app.common.schemas import Envelope
from app.core.health.dto.response.health import Checks, Liveness, Readiness
from app.core.health.services import health as health_service

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/liveness")
async def liveness() -> Envelope[Liveness]:
    return Envelope(data=Liveness(**health_service.liveness()))


@router.get("/readiness")
async def readiness() -> Envelope[Readiness]:
    data = await health_service.readiness()
    return Envelope(data=Readiness(**{**data, "checks": Checks(**data["checks"])}))
