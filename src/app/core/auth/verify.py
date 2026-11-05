"""Email and phone verification. Both flows are the same apart from the identifier type and purpose."""

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import service as audit
from app.core.auth import otp
from app.core.auth import repository as repo
from app.core.auth.models import IdentifierType
from app.core.auth.otp import Purpose
from app.core.auth.repository import AuthUser, normalize_email, normalize_phone
from app.core.auth.tokens import unauthorized
from app.database.session import utcnow
from app.locals import msg


@dataclass(frozen=True)
class Flow:
    type: IdentifierType
    purpose: Purpose
    channel: str
    audit_action: str
    normalize: Callable[[str], str]


EMAIL = Flow(IdentifierType.EMAIL, Purpose.REGISTER_VERIFY, "email", "email.verified", normalize_email)
PHONE = Flow(IdentifierType.PHONE, Purpose.REGISTER_VERIFY_PHONE, "sms", "phone.verified", normalize_phone)


async def _mark_verified(db: AsyncSession, flow: Flow, user_id: str, value: str) -> AuthUser:
    identifier = await repo.find_identifier(db, flow.type, flow.normalize(value))
    if identifier and identifier.user_id == user_id:
        identifier.is_verified, identifier.verified_at = True, utcnow()
        await db.commit()
    await audit.record(
        flow.audit_action, user_id=user_id, resource_type="user", resource_id=user_id,
        metadata={flow.channel: value},
    )  # fmt: skip
    user = await repo.find_auth_user(db, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.user_not_found)
    return user


async def resend_to(db: AsyncSession, flow: Flow, value: str) -> None:
    """Public endpoint: stays silent about unknown or verified identifiers and about cooldowns."""
    normalized = flow.normalize(value)
    owner = await repo.find_active_owner(db, flow.type, normalized)
    if not owner or owner[0].is_verified:
        return
    try:
        await otp.issue(owner[1].id, flow.purpose, flow.channel, normalized)
    except HTTPException:
        pass


async def resend_for_user(db: AsyncSession, flow: Flow, user_id: str) -> None:
    primary = await repo.find_primary(db, user_id, flow.type)
    if primary and not primary.is_verified:
        await otp.issue(user_id, flow.purpose, flow.channel, primary.value)


async def confirm_token(db: AsyncSession, token: str) -> AuthUser:
    record = await otp.verify_token(token, EMAIL.purpose)
    return await _mark_verified(db, EMAIL, record["user_id"], record["destination"])


async def confirm_code(db: AsyncSession, flow: Flow, value: str, code: str) -> AuthUser:
    owner = await repo.find_active_owner(db, flow.type, flow.normalize(value))
    if not owner:
        raise unauthorized(msg.auth.code_invalid_or_expired)
    record = await otp.verify_code(owner[1].id, flow.purpose, flow.channel, code)
    return await _mark_verified(db, flow, record["user_id"], record["destination"])


async def confirm_code_for_user(db: AsyncSession, flow: Flow, user_id: str, code: str) -> AuthUser:
    primary = await repo.find_primary(db, user_id, flow.type)
    if not primary:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.user_not_found)
    if primary.is_verified:
        user = await repo.find_auth_user(db, user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.user_not_found)
        return user
    record = await otp.verify_code(user_id, flow.purpose, flow.channel, code)
    return await _mark_verified(db, flow, record["user_id"], record["destination"])
