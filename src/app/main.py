from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import socketio
from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.common.errors import register_error_handlers
from app.common.rate_limit import limit
from app.configs.settings import get_settings
from app.core.auth.routers import identifier, password, session, sudo, two_factor, verify
from app.core.fcm_token.router import router as fcm_router
from app.core.files.router import router as files_router
from app.core.health.router import router as health_router
from app.database import models  # noqa: F401
from app.database.session import engine
from app.infrastructure.cache import cache, setup_cache
from app.infrastructure.context import RequestContextMiddleware
from app.infrastructure.observability import setup_logging, setup_telemetry
from app.infrastructure.queue import close_queues
from app.infrastructure.realtime import sio

settings = get_settings()
setup_logging()
setup_cache()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    await close_queues()
    await cache.close()
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/api/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/api/openapi.json",
)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
register_error_handlers(app)

auth = APIRouter(prefix="/auth", tags=["auth"])
for router in (session.router, password.router, verify.router, identifier.router, two_factor.router, sudo.router):
    auth.include_router(router)

api = APIRouter(prefix="/api/v1")
limited = [limit(settings.rate_limit_limit, settings.rate_limit_ttl)]
api.include_router(auth, dependencies=limited)
api.include_router(fcm_router, dependencies=limited)
api.include_router(files_router, dependencies=limited)
api.include_router(health_router)
# New business routers from app/modules go here, with dependencies=limited.
app.include_router(api)
setup_telemetry(app)

asgi = socketio.ASGIApp(sio, other_asgi_app=app)
