"""Timed re-authentication for sensitive actions, bound to one session."""

import time

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.mask import mask_email, mask_phone
from app.common.security import verify_secret
from app.configs.policy import SUDO_GRANT_TTL
from app.core.auth import otp, two_factor
from app.core.auth import repository as repo
from app.core.auth.models import AuthProvider, IdentifierType, TwoFactorType
from app.core.auth.otp import Purpose
from app.core.auth.tokens import sudo_key, unauthorized
from app.database.session import utcnow
from app.infrastructure.cache import cache, take
from app.locals import msg

_INACTIVE = {"active": False, "expires_at": None, "method": None}


def _required() -> HTTPException:
    return HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.sudo_required)


def _mask(type_: str, destination: str | None) -> str | None:
    if not destination:
        return None
    return mask_email(destination) if type_ in ("email", TwoFactorType.EMAIL_OTP) else mask_phone(destination)


async def _mint(user_id: str, session_id: str | None, method: str) -> dict:
    if not session_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.sudo_session_required)
    grant = {"active": True, "method": method, "expires_at": int((time.time() + SUDO_GRANT_TTL) * 1000)}
    await cache.set(sudo_key(user_id, session_id), grant, expire=SUDO_GRANT_TTL)
    return grant


async def status_of(user_id: str, session_id: str | None) -> dict:
    grant = await cache.get(sudo_key(user_id, session_id)) if session_id else None
    return grant or _INACTIVE


async def require(user_id: str, session_id: str | None) -> None:
    if not session_id or not await cache.get(sudo_key(user_id, session_id)):
        raise _required()


async def consume(user_id: str, session_id: str | None) -> None:
    if session_id:
        await take(sudo_key(user_id, session_id))


async def clear(user_id: str, session_id: str) -> None:
    await cache.delete(sudo_key(user_id, session_id))


async def list_options(db: AsyncSession, user_id: str) -> list[dict]:
    options: list[dict] = []
    credential = await repo.find_credential(db, user_id, AuthProvider.EMAIL)
    if credential and credential.password_hash:
        options.append({"kind": "password"})
    for channel, type_ in (("email", IdentifierType.EMAIL), ("sms", IdentifierType.PHONE)):
        primary = await repo.find_primary(db, user_id, type_)
        if primary and primary.is_verified:
            options.append({"kind": "otp", "channel": channel, "hint": _mask(channel, primary.value)})
    for method in await repo.enabled_methods(db, user_id):
        options.append({
            "kind": "2fa", "type": method.type, "hint": _mask(method.type, method.destination),
            "requires_send": method.type != TwoFactorType.TOTP,
        })  # fmt: skip
    return options


async def elevate_with_password(db: AsyncSession, user_id: str, session_id: str | None, password: str) -> dict:
    credential = await repo.find_credential(db, user_id, AuthProvider.EMAIL)
    if not credential or not credential.password_hash:
        raise unauthorized(msg.auth.no_password_credential)
    if not await verify_secret(password, credential.password_hash):
        raise unauthorized(msg.auth.sudo_elevation_failed)
    return await _mint(user_id, session_id, "password")


async def request_otp(db: AsyncSession, user_id: str, channel: str) -> None:
    is_email = channel == "email"
    primary = await repo.find_primary(db, user_id, IdentifierType.EMAIL if is_email else IdentifierType.PHONE)
    if not primary or not primary.is_verified:
        message = msg.auth.sudo_no_verified_email if is_email else msg.auth.sudo_no_verified_phone
        raise HTTPException(status.HTTP_400_BAD_REQUEST, message)
    await otp.issue(user_id, Purpose.SUDO, channel, primary.value)


async def elevate_with_otp(user_id: str, session_id: str | None, channel: str, code: str) -> dict:
    try:
        await otp.verify_code(user_id, Purpose.SUDO, channel, code)
    except HTTPException as exc:
        raise unauthorized(msg.auth.sudo_elevation_failed) from exc
    return await _mint(user_id, session_id, "otp")


async def request_two_factor_otp(db: AsyncSession, user_id: str, type_: TwoFactorType) -> None:
    if type_ == TwoFactorType.TOTP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.totp_no_sent_code)
    method = await repo.find_method(db, user_id, type_)
    if not method or not method.is_enabled or not method.destination:
        raise HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.method_not_available_for_challenge)
    await otp.issue(user_id, Purpose.SUDO_2FA, two_factor.channel_of(type_), method.destination)


async def elevate_with_two_factor(
    db: AsyncSession, user_id: str, session_id: str | None, type_: TwoFactorType, code: str
) -> dict:
    method = await repo.find_method(db, user_id, type_)
    ok = False
    if method and method.is_enabled:
        if type_ == TwoFactorType.TOTP:
            ok = bool(method.secret) and two_factor.verify_totp(method.secret or "", code)
        else:
            try:
                await otp.verify_code(user_id, Purpose.SUDO_2FA, two_factor.channel_of(type_), code)
                ok = True
            except HTTPException:
                ok = False
    if ok and method:
        method.last_used_at = utcnow()
        await db.commit()
    elif not await two_factor.claim_backup_code(db, user_id, code):
        raise unauthorized(msg.auth.sudo_elevation_failed)
    return await _mint(user_id, session_id, "2fa")
