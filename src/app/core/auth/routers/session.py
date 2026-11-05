from fastapi import APIRouter, Request, Response, status

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.audit import service as audit
from app.core.auth import login as login_service
from app.core.auth import oauth, tokens
from app.core.auth import repository as repo
from app.core.auth.constants import REFRESH_TOKEN_COOKIE
from app.core.auth.deps import AuthAny, Sudo, SudoConsume
from app.core.auth.models import AuthProvider, Session
from app.core.auth.routers.helpers import clear_auth_cookies, deliver_tokens, login_response
from app.core.auth.schemas import AuthEnvelope, AuthUserOut, IdTokenIn, LoginIn, RefreshIn, RegisterIn, SessionOut
from app.core.auth.tokens import unauthorized
from app.database.session import Db, utcnow
from app.infrastructure.cache import cache
from app.locals import msg

router = APIRouter()
_PROVIDERS = {"google": AuthProvider.GOOGLE, "apple": AuthProvider.APPLE}


@router.post("/register", status_code=status.HTTP_201_CREATED, dependencies=[limit(5)])
async def register(body: RegisterIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    result = await login_service.register(db, email=body.email, phone=body.phone, password=body.password, name=body.name)
    return login_response(result, request, response, msg.auth.account_created_successfully, 201)


@router.post("/login", dependencies=[limit(10)])
async def login(body: LoginIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    result = await login_service.login(db, email=body.email, phone=body.phone, password=body.password)
    return login_response(result, request, response, msg.auth.logged_in_successfully)


async def _oauth_login(provider: AuthProvider, body: IdTokenIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    identity = await oauth.verify_id_token(provider, body.id_token)
    return login_response(await oauth.login_or_create(db, identity), request, response, msg.auth.oauth_login_successful)


@router.post("/oauth/google", dependencies=[limit(10)])
async def oauth_google(body: IdTokenIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    return await _oauth_login(AuthProvider.GOOGLE, body, request, response, db)


@router.post("/oauth/apple", dependencies=[limit(10)])
async def oauth_apple(body: IdTokenIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    return await _oauth_login(AuthProvider.APPLE, body, request, response, db)


@router.post("/oauth/{provider}/link")
async def oauth_link(provider: str, body: IdTokenIn, user: Sudo, db: Db) -> Envelope[None]:
    if provider not in _PROVIDERS:
        raise unauthorized(msg.auth.oauth_token_invalid)
    await oauth.link(db, user.sub, await oauth.verify_id_token(_PROVIDERS[provider], body.id_token))
    return Envelope(message=msg.auth.oauth_linked)


@router.delete("/oauth/{provider}")
async def oauth_unlink(provider: str, user: SudoConsume, db: Db) -> Envelope[None]:
    if provider not in _PROVIDERS:
        raise unauthorized(msg.auth.oauth_token_invalid)
    await oauth.unlink(db, user.sub, _PROVIDERS[provider])
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
    found = await repo.find_auth_user(db, user.sub)
    if not found:
        raise unauthorized(msg.auth.user_not_found)
    return Envelope(data=AuthUserOut.model_validate(found))


@router.post("/logout-all")
async def logout_all(user: AuthAny, response: Response, db: Db) -> Envelope[None]:
    await tokens.revoke_all(db, user.sub)
    clear_auth_cookies(response)
    await audit.record("session.revoked_all", user_id=user.sub, resource_type="session")
    return Envelope(message=msg.auth.logged_out_all_successfully)


@router.get("/sessions")
async def sessions(user: AuthAny, db: Db) -> Envelope[list[SessionOut]]:
    rows = await repo.list_active_sessions(db, user.sub)
    return Envelope(data=[
        SessionOut(
            id=s.id, device_id=s.device_id, device_label=s.device_label, created_at=s.created_at,
            expires_at=s.expires_at, current=s.id == user.sid,
        )
        for s in rows
    ])  # fmt: skip


@router.delete("/sessions/{session_id}")
async def revoke_session(session_id: str, user: AuthAny, db: Db) -> Envelope[None]:
    session = await db.get(Session, session_id)
    if not session or session.user_id != user.sub or session.revoked_at or session.expires_at <= utcnow():
        raise unauthorized(msg.auth.session_not_found)
    session.revoked_at = utcnow()
    await db.commit()
    await cache.delete(tokens.sudo_key(user.sub, session_id))
    await audit.record("session.revoked", user_id=user.sub, resource_type="session", resource_id=session_id)
    return Envelope(message=msg.auth.session_revoked)
