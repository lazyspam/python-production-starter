from contextvars import ContextVar
from dataclasses import dataclass

from asgi_correlation_id import correlation_id
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
]


@dataclass(frozen=True)
class RequestInfo:
    ip: str | None = None
    user_agent: str | None = None


_request_info: ContextVar[RequestInfo] = ContextVar("request_info", default=RequestInfo())  # noqa: B039


def request_info() -> RequestInfo:
    return _request_info.get()


def request_id() -> str | None:
    return correlation_id.get()


class RequestContextMiddleware:
    """Makes the caller's IP and user agent available anywhere in a request, and adds security headers."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        token = _request_info.set(RequestInfo(client[0] if client else None, Headers(scope=scope).get("user-agent")))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *_SECURITY_HEADERS]
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            _request_info.reset(token)
