"""Origin check for cookie-authenticated writes. Bearer clients are exempt: a browser can't attach their header cross-site."""

from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.requests import cookie_parser
from starlette.types import ASGIApp, Receive, Scope, Send

from app.common.errors import error_response
from app.configs.settings import get_settings
from app.core.auth.constants import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
from app.locals import msg

_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
_AUTH_COOKIES = {ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE}


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower() if parts.scheme and parts.netloc else None


def allowed_origins() -> set[str]:
    s = get_settings()
    return {origin for origin in (_origin_of(s.frontend_url), _origin_of(s.backend_url)) if origin}


class CsrfMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in _UNSAFE:
            headers = Headers(scope=scope)
            uses_cookie = "authorization" not in headers and _AUTH_COOKIES & cookie_parser(headers.get("cookie", "")).keys()
            source = headers.get("origin") or headers.get("referer")
            if uses_cookie and (not source or _origin_of(source) not in allowed_origins()):
                await error_response(403, msg.error.csrf_origin_mismatch)(scope, receive, send)
                return
        await self.app(scope, receive, send)
