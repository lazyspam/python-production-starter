from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import uuid4

import jwt
from fastapi import HTTPException, status
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.security import sha256
from app.configs.settings import get_settings
from app.core.auth import repository as repo
from app.core.auth.models import Session, UserStatus
from app.core.fcm_token.models import FcmToken
from app.database.session import utcnow
from app.infrastructure.cache import cache, key
from app.infrastructure.context import request_info
from app.locals import msg

ALGORITHM = "HS256"


@dataclass
class Token:
    token: str
    expires_at: datetime


@dataclass
class AuthTokens:
    access: Token
    refresh: Token


def unauthorized(message: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, message)


def sudo_key(user_id: str, session_id: str) -> str:
    return key(f"sudo:{user_id}:{session_id}")


def _sign(claims: dict, secret: str, ttl: int) -> tuple[str, datetime]:
    now = utcnow()
    expires = now + timedelta(seconds=ttl)
    return jwt.encode({**claims, "iat": now, "exp": expires}, secret, ALGORITHM), expires


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, get_settings().jwt_access_secret, [ALGORITHM])
    except jwt.PyJWTError:
        return None
    return payload if payload.get("tokenType") == "access" else None


async def issue(db: AsyncSession, user_id: str) -> AuthTokens:
    """Starts a session. The jti keeps two logins in the same second from producing one identical refresh token."""
    s = get_settings()
    refresh_claims = {"sub": user_id, "tokenType": "refresh", "jti": str(uuid4())}
    refresh, refresh_expires = _sign(refresh_claims, s.jwt_refresh_secret, s.jwt_refresh_ttl_seconds)
    info = request_info()
    session = Session(
        user_id=user_id, refresh_token_hash=sha256(refresh), expires_at=refresh_expires,
        ip_address=info.ip, user_agent=info.user_agent[:512] if info.user_agent else None,
    )  # fmt: skip
    db.add(session)
    await db.commit()
    access_claims = {"sub": user_id, "tokenType": "access", "sid": session.id}
    access, access_expires = _sign(access_claims, s.jwt_access_secret, s.jwt_access_ttl_seconds)
    return AuthTokens(Token(access, access_expires), Token(refresh, refresh_expires))


async def refresh(db: AsyncSession, presented: str) -> AuthTokens:
    try:
        payload = jwt.decode(presented, get_settings().jwt_refresh_secret, [ALGORITHM])
    except jwt.PyJWTError as exc:
        raise unauthorized(msg.auth.refresh_token_required) from exc
    if payload.get("tokenType") != "refresh":
        raise unauthorized(msg.auth.refresh_token_required)

    user_id = payload["sub"]
    user = await repo.find_user(db, user_id)
    if not user or user.status != UserStatus.ACTIVE:
        await revoke_all(db, user_id)
        raise unauthorized(msg.auth.account_no_longer_available)

    session = await repo.find_active_session_by_hash(db, sha256(presented))
    if not session or session.user_id != user_id:
        # A valid token with no live session is a replayed, already-rotated token: end every session.
        await revoke_all(db, user_id)
        raise unauthorized(msg.auth.refresh_token_required)

    session.revoked_at = utcnow()
    await db.commit()
    await cache.delete(sudo_key(user_id, session.id))
    return await issue(db, user_id)


async def revoke(db: AsyncSession, presented: str) -> None:
    session = await repo.find_active_session_by_hash(db, sha256(presented))
    if session:
        session.revoked_at = utcnow()
        await db.commit()
        await cache.delete(sudo_key(session.user_id, session.id))


async def revoke_all(db: AsyncSession, user_id: str) -> None:
    sessions = await repo.list_active_sessions(db, user_id)
    await repo.revoke_user_sessions(db, user_id)
    await db.execute(delete(FcmToken).where(FcmToken.user_id == user_id))
    await db.commit()
    for session in sessions:
        await cache.delete(sudo_key(user_id, session.id))
