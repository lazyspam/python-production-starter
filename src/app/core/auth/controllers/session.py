from fastapi import APIRouter, Depends, Request, Response, status

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.auth.constants import REFRESH_TOKEN_COOKIE
from app.core.auth.controllers.helpers import clear_auth_cookies, deliver_tokens, login_response, no_store
from app.core.auth.deps import AuthAny, Sudo, SudoConsume
from app.core.auth.dto.request.session import IdTokenIn, LoginIn, RefreshIn, RegisterIn
from app.core.auth.dto.response.session import AuthEnvelope, AuthUserOut, SessionOut
from app.core.auth.models import AuthProvider
from app.core.auth.services import login as login_service
from app.core.auth.services import oauth, tokens
from app.core.auth.services import sessions as session_service
from app.core.auth.services.tokens import unauthorized
from app.database.session import Db
from app.locals import msg

router = APIRouter(dependencies=[Depends(no_store)])


@router.post("/register", status_code=status.HTTP_201_CREATED, dependencies=[limit(5)])
async def register(body: RegisterIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    result = await login_service.register(db, email=body.email, phone=body.phone, password=body.password, name=body.name)
    return login_response(result, request, response, msg.auth.account_created_successfully, 201)


@router.post("/login", dependencies=[limit(10)])
async def login(body: LoginIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    result = await login_service.login(db, email=body.email, phone=body.phone, password=body.password)
    return login_response(result, request, response, msg.auth.logged_in_successfully)


async def _oauth_login(provider: AuthProvider, body: IdTokenIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    result = await oauth.sign_in(db, provider, body.id_token, body.nonce)
    return login_response(result, request, response, msg.auth.oauth_login_successful)


@router.post("/oauth/google", dependencies=[limit(10)])
async def oauth_google(body: IdTokenIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    return await _oauth_login(AuthProvider.GOOGLE, body, request, response, db)


@router.post("/oauth/apple", dependencies=[limit(10)])
async def oauth_apple(body: IdTokenIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    return await _oauth_login(AuthProvider.APPLE, body, request, response, db)


@router.post("/oauth/{provider}/link")
async def oauth_link(provider: str, body: IdTokenIn, user: Sudo, db: Db) -> Envelope[None]:
    await oauth.link_account(db, user.sub, provider, body.id_token, body.nonce)
    return Envelope(message=msg.auth.oauth_linked)


@router.delete("/oauth/{provider}")
async def oauth_unlink(provider: str, user: SudoConsume, db: Db) -> Envelope[None]:
    await oauth.unlink_account(db, user.sub, provider)
    return Envelope(message=msg.auth.oauth_unlinked)


@router.post("/refresh")
async def refresh(body: RefreshIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    presented = body.refresh_token or request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not presented:
        raise unauthorized(msg.auth.refresh_token_required)
    issued = await tokens.refresh(db, presented)
    return AuthEnvelope(message=msg.auth.token_refreshed, tokens=deliver_tokens(response, issued, body.refresh_token is not None))


@router.post("/logout")
async def logout(body: RefreshIn, request: Request, response: Response, db: Db) -> Envelope[None]:
    presented = body.refresh_token or request.cookies.get(REFRESH_TOKEN_COOKIE)
    if presented:
        await tokens.revoke(db, presented)
    clear_auth_cookies(response)
    return Envelope(message=msg.auth.logged_out_successfully)


@router.get("/me")
async def me(user: AuthAny, db: Db) -> Envelope[AuthUserOut]:
    return Envelope(data=AuthUserOut.model_validate(await session_service.current_user(db, user.sub)))


@router.post("/logout-all")
async def logout_all(user: AuthAny, response: Response, db: Db) -> Envelope[None]:
    await session_service.logout_all(db, user.sub)
    clear_auth_cookies(response)
    return Envelope(message=msg.auth.logged_out_all_successfully)


@router.get("/sessions")
async def sessions(user: AuthAny, db: Db) -> Envelope[list[SessionOut]]:
    rows = await session_service.list_sessions(db, user.sub)
    return Envelope(data=[
        SessionOut(
            id=s.id, device_id=s.device_id, device_label=s.device_label, created_at=s.created_at,
            expires_at=s.expires_at, current=s.id == user.sid,
        )
        for s in rows
    ])  # fmt: skip


@router.delete("/sessions/{session_id}")
async def revoke_session(session_id: str, user: AuthAny, db: Db) -> Envelope[None]:
    await session_service.revoke_session(db, user.sub, session_id)
    return Envelope(message=msg.auth.session_revoked)
