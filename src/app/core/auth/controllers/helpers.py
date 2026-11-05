from fastapi import Request, Response

from app.configs.settings import get_settings
from app.core.auth.constants import (
    ACCESS_TOKEN_COOKIE,
    AUTH_TRANSPORT_BEARER,
    AUTH_TRANSPORT_HEADER,
    REFRESH_TOKEN_COOKIE,
    REFRESH_TOKEN_COOKIE_PATH,
)
from app.core.auth.dto.response.session import AuthEnvelope, AuthUserOut, TokensOut
from app.core.auth.services.login import LoginResult
from app.core.auth.services.tokens import AuthTokens
from app.locals import msg


def wants_bearer(request: Request) -> bool:
    return request.headers.get(AUTH_TRANSPORT_HEADER, "").lower() == AUTH_TRANSPORT_BEARER


def _cookie_options() -> dict:
    s = get_settings()
    return {"httponly": True, "secure": s.is_production, "samesite": s.auth_cookie_same_site, "domain": s.auth_cookie_domain}


def set_auth_cookies(response: Response, tokens: AuthTokens) -> None:
    options = _cookie_options()
    response.set_cookie(ACCESS_TOKEN_COOKIE, tokens.access.token, expires=tokens.access.expires_at, path="/", **options)
    response.set_cookie(
        REFRESH_TOKEN_COOKIE, tokens.refresh.token, expires=tokens.refresh.expires_at,
        path=REFRESH_TOKEN_COOKIE_PATH, **options,
    )  # fmt: skip


def clear_auth_cookies(response: Response) -> None:
    options = _cookie_options()
    response.delete_cookie(ACCESS_TOKEN_COOKIE, path="/", **options)
    response.delete_cookie(REFRESH_TOKEN_COOKIE, path=REFRESH_TOKEN_COOKIE_PATH, **options)


def deliver_tokens(response: Response, tokens: AuthTokens, bearer: bool) -> TokensOut | None:
    """Bearer clients get tokens in the body; everyone else gets httpOnly cookies."""
    if bearer:
        return TokensOut.model_validate(tokens)
    set_auth_cookies(response, tokens)
    return None


def login_response(
    result: LoginResult, request: Request, response: Response, message: str, status_code: int = 200
) -> AuthEnvelope:
    if result.challenge:
        return AuthEnvelope(
            message=msg.auth.two_factor_required,
            challenge_id=result.challenge["challenge_id"],
            methods=result.challenge["methods"],
        )
    assert result.tokens
    return AuthEnvelope(
        message=message,
        status_code=status_code,
        data=AuthUserOut.model_validate(result.user),
        tokens=deliver_tokens(response, result.tokens, wants_bearer(request)),
    )
