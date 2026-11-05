from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.models import Session
from app.database.session import utcnow


async def add_session(
    db: AsyncSession, user_id: str, refresh_token_hash: str, expires_at, ip_address: str | None, user_agent: str | None
) -> Session:
    session = Session(
        user_id=user_id, refresh_token_hash=refresh_token_hash, expires_at=expires_at,
        ip_address=ip_address, user_agent=user_agent,
    )  # fmt: skip
    db.add(session)
    return session


async def get_session(db: AsyncSession, session_id: str) -> Session | None:
    return await db.get(Session, session_id)


async def list_active_sessions(db: AsyncSession, user_id: str) -> list[Session]:
    return list(await db.scalars(
        select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None), Session.expires_at > utcnow())
        .order_by(Session.created_at.desc())
    ))  # fmt: skip


async def find_active_session_by_hash(db: AsyncSession, token_hash: str) -> Session | None:
    return await db.scalar(
        select(Session).where(
            Session.refresh_token_hash == token_hash, Session.revoked_at.is_(None), Session.expires_at > utcnow()
        )
    )


async def revoke_user_sessions(db: AsyncSession, user_id: str) -> None:
    await db.execute(update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None)).values(revoked_at=utcnow()))
