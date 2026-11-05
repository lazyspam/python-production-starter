from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.services import audit
from app.core.auth.models import Session
from app.core.auth.repositories import session as session_repo
from app.core.auth.repositories import user as user_repo
from app.core.auth.services import tokens
from app.core.auth.services.tokens import unauthorized
from app.core.auth.types import AuthUser
from app.database.session import utcnow
from app.infrastructure.cache import cache
from app.locals import msg


async def current_user(db: AsyncSession, user_id: str) -> AuthUser:
    user = await user_repo.find_auth_user(db, user_id)
    if not user:
        raise unauthorized(msg.auth.user_not_found)
    return user


async def list_sessions(db: AsyncSession, user_id: str) -> list[Session]:
    return await session_repo.list_active_sessions(db, user_id)


async def revoke_session(db: AsyncSession, user_id: str, session_id: str) -> None:
    session = await session_repo.get_session(db, session_id)
    if not session or session.user_id != user_id or session.revoked_at or session.expires_at <= utcnow():
        raise unauthorized(msg.auth.session_not_found)
    session.revoked_at = utcnow()
    await db.commit()
    await cache.delete(tokens.sudo_key(user_id, session_id))
    await audit.record("session.revoked", user_id=user_id, resource_type="session", resource_id=session_id)


async def logout_all(db: AsyncSession, user_id: str) -> None:
    await tokens.revoke_all(db, user_id)
    await audit.record("session.revoked_all", user_id=user_id, resource_type="session")
