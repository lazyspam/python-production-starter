from fastapi import Depends, HTTPException, Request, status

from app.infrastructure.cache import cache, key
from app.locals import msg


def limit(times: int, seconds: int = 60):
    """Per-IP, per-route limit: `dependencies=[limit(5)]`."""

    async def dependency(request: Request) -> None:
        route = getattr(request.scope.get("route"), "path", request.url.path)
        ip = request.client.host if request.client else "unknown"
        if await cache.incr(key(f"rl:{route}:{ip}:{times}:{seconds}"), expire=seconds) > times:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, msg.error.too_many_requests)

    return Depends(dependency)
