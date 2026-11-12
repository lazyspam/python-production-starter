import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.configs.settings import get_settings
from app.locals import msg

log = structlog.get_logger()


def error_response(status_code: int, message: object, headers: dict[str, str] | None = None) -> JSONResponse:
    content = {"success": False, "statusCode": status_code, "message": message, "data": None}
    return JSONResponse(content, status_code, headers=headers)


async def _http(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, HTTPException)
    log.warning("http_exception", path=request.url.path, status=exc.status_code, detail=exc.detail)
    return error_response(exc.status_code, exc.detail, dict(exc.headers) if exc.headers else None)


async def _validation(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    messages = [f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()]
    return error_response(status.HTTP_400_BAD_REQUEST, messages)


def _unhandled(scope: Scope, exc: Exception) -> JSONResponse:
    log.exception("unhandled_exception", path=scope.get("path"), exc_info=exc)
    generic = msg.error.internal_server_error
    return error_response(500, generic if get_settings().is_production else str(exc) or generic)


class UnhandledErrorMiddleware:
    """Turns uncaught exceptions into the JSON 500 body here, inside CORS and the security headers.

    Starlette sends `Exception` handlers through its outermost middleware, so their responses skip CORS and browsers
    report a CORS failure instead of the 500. Add this one first so it sits innermost.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            if started:
                raise
            await _unhandled(scope, exc)(scope, receive, send)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, _http)
    app.add_exception_handler(RequestValidationError, _validation)
