from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.services import audit
from app.core.auth.models import Session, UserStatus
from app.core.auth.repositories import session as session_repo
from app.core.auth.repositories import user as user_repo
from app.core.auth.services import tokens
from app.core.auth.services.tokens import unauthorized
from app.core.auth.types import AuthUser
from app.locals import msg


async def current_user(db: AsyncSession, user_id: str) -> AuthUser:
    user = await user_repo.find_auth_user(db, user_id)
    if not user:
        raise unauthorized(msg.auth.user_not_found)
    return user


async def authorize_socket(db: AsyncSession, token: str) -> tuple[str, str] | None:
    """The (user id, session id) behind a socket's access token, or None if the token, session or account is not live."""
    payload = tokens.decode_access_token(token) if token else None
    session_id = payload.get("sid") if payload else None
    if not payload or not session_id or await tokens.is_session_revoked(session_id):
        return None
    user = await user_repo.find_user(db, payload["sub"])
    if not user or user.status != UserStatus.ACTIVE:
        return None
    return user.id, session_id


async def list_sessions(db: AsyncSession, user_id: str) -> list[Session]:
    return await session_repo.list_active_sessions(db, user_id)


async def revoke_session(db: AsyncSession, user_id: str, session_id: str) -> None:
    if not await session_repo.revoke_owned_session(db, user_id, session_id):
        raise unauthorized(msg.auth.session_not_found)
    await db.commit()
    await tokens.finish_revoke(user_id, [session_id])
    await audit.record("session.revoked", user_id=user_id, resource_type="session", resource_id=session_id)


async def logout_all(db: AsyncSession, user_id: str) -> None:
    await tokens.revoke_all(db, user_id)
    await audit.record("session.revoked_all", user_id=user_id, resource_type="session")
