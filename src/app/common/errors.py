import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.configs.settings import get_settings
from app.locals import msg

log = structlog.get_logger()


def _body(status_code: int, message: object, headers: dict[str, str] | None = None) -> JSONResponse:
    content = {"success": False, "statusCode": status_code, "message": message, "data": None}
    return JSONResponse(content, status_code, headers=headers)


async def _http(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, HTTPException)
    log.warning("http_exception", path=request.url.path, status=exc.status_code, detail=exc.detail)
    return _body(exc.status_code, exc.detail, dict(exc.headers) if exc.headers else None)


async def _validation(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    messages = [f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()]
    return _body(status.HTTP_400_BAD_REQUEST, messages)


async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled_exception", path=request.url.path, exc_info=exc)
    generic = msg.error.internal_server_error
    return _body(500, generic if get_settings().is_production else str(exc) or generic)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, _http)
    app.add_exception_handler(RequestValidationError, _validation)
    app.add_exception_handler(Exception, _unhandled)
