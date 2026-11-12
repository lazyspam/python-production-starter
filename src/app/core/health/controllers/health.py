from fastapi import APIRouter

from app.common.schemas import Envelope
from app.core.health.dto.response.health import Liveness, Readiness
from app.core.health.services import health as health_service

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/liveness")
async def liveness() -> Envelope[Liveness]:
    return Envelope(data=Liveness.model_validate(health_service.liveness()))


@router.get("/readiness")
async def readiness() -> Envelope[Readiness]:
    return Envelope(data=Readiness.model_validate(await health_service.readiness()))
