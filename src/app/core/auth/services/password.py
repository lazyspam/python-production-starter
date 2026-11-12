import time
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.mask import mask_email, mask_phone
from app.common.security import hash_secret, random_token, verify_secret
from app.configs import policy
from app.core.audit.services import audit
from app.core.auth.helpers.normalize import resolve_identifier
from app.core.auth.models import AuthProvider, IdentifierType
from app.core.auth.repositories import credential as credential_repo
from app.core.auth.repositories import identifier as identifier_repo
from app.core.auth.services import otp, tokens
from app.core.auth.services.otp import Purpose
from app.core.auth.services.tokens import unauthorized
from app.infrastructure.cache import cache, key
from app.locals import msg


def _reset_key(reset_id: str) -> str:
    return key(f"password-reset:{reset_id}")


def _user_reset_key(user_id: str) -> str:
    return key(f"password-reset-user:{user_id}")


def _invalid_challenge() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.reset_challenge_invalid_or_expired)


async def forgot(db: AsyncSession, identifier: str) -> dict:
    """Same answer for every identifier: one channel, the one entered, masked.

    When there is no usable account behind it (unknown, unverified, or no password), the ids are decoys and `send`
    reports success without sending anything, so the response can't be used to find out who has an account.
    """
    type_, value = resolve_identifier(identifier)
    reset_id = random_token(24)
    owner = await identifier_repo.find_active_owner(db, type_, value)
    usable = None
    if owner and owner[0].is_verified:
        credential = await credential_repo.find_credential(db, owner[1].id, AuthProvider.EMAIL)
        usable = owner if credential and credential.password_hash else None

    channel_id = usable[0].id if usable else str(uuid4())
    user_id = usable[1].id if usable else None
    record = {"user_id": user_id, "channel_ids": [channel_id], "created_at": time.time(), "otp_channel": None}
    ttl = policy.PASSWORD_RESET_CHALLENGE_TTL
    await cache.set(_reset_key(reset_id), record, expire=ttl)
    if user_id:
        await cache.set(_user_reset_key(user_id), reset_id, expire=ttl)
    hint = mask_email(value) if type_ == IdentifierType.EMAIL else mask_phone(value)
    return {"reset_id": reset_id, "channels": [{"id": channel_id, "type": type_, "hint": hint}]}


async def send(db: AsyncSession, reset_id: str, channel_id: str) -> None:
    challenge = await cache.get(_reset_key(reset_id))
    if not challenge or channel_id not in challenge["channel_ids"]:
        raise _invalid_challenge()
    channel = "none"  # a decoy from forgot(): behaves as if a code was sent, resend cooldown included
    if not challenge["user_id"] and (age := int(time.time() - challenge.get("sent_at", 0))) < policy.OTP_RESEND_COOLDOWN:
        message = msg.auth.otp_resend_cooldown.format(seconds=policy.OTP_RESEND_COOLDOWN - age)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, message)
    if challenge["user_id"]:
        identifier = await identifier_repo.find_identifier_by_id(db, channel_id)
        if not identifier or identifier.user_id != challenge["user_id"] or not identifier.is_verified:
            raise _invalid_challenge()
        channel = "email" if identifier.type == IdentifierType.EMAIL else "sms"
        await otp.issue(challenge["user_id"], Purpose.RESET_PASSWORD, channel, identifier.value)
    remaining = max(1, policy.PASSWORD_RESET_CHALLENGE_TTL - int(time.time() - challenge["created_at"]))
    await cache.set(_reset_key(reset_id), {**challenge, "otp_channel": channel, "sent_at": time.time()}, expire=remaining)


async def _save_and_end_sessions(db: AsyncSession, user_id: str) -> None:
    """Commits the password change and the session revocation together, so one can't happen without the other."""
    session_ids = await tokens.stage_revoke_all(db, user_id)
    await db.commit()
    await tokens.finish_revoke(user_id, session_ids)


async def _apply_new_password(db: AsyncSession, user_id: str, new_password: str) -> None:
    credential = await credential_repo.find_credential(db, user_id, AuthProvider.EMAIL)
    if not credential:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.no_password_credential)
    credential.password_hash = await hash_secret(new_password)
    await _save_and_end_sessions(db, user_id)
    reset_id = await cache.get(_user_reset_key(user_id))
    if reset_id:
        await cache.delete(_reset_key(reset_id))
        await cache.delete(_user_reset_key(user_id))
    await audit.record("password.reset", user_id=user_id, resource_type="user", resource_id=user_id)


async def reset_with_token(db: AsyncSession, token: str, new_password: str) -> None:
    record = await otp.verify_token(token, Purpose.RESET_PASSWORD)
    await _apply_new_password(db, record["user_id"], new_password)


async def reset_with_code(db: AsyncSession, reset_id: str, code: str, new_password: str) -> None:
    challenge = await cache.get(_reset_key(reset_id))
    if not challenge or not challenge.get("otp_channel"):
        raise _invalid_challenge()
    if not challenge["user_id"]:
        raise unauthorized(msg.auth.code_invalid_or_expired)  # what a wrong code on a real account gets
    await otp.verify_code(challenge["user_id"], Purpose.RESET_PASSWORD, challenge["otp_channel"], code)
    await _apply_new_password(db, challenge["user_id"], new_password)


async def change(db: AsyncSession, user_id: str, current: str, new: str) -> None:
    credential = await credential_repo.find_credential(db, user_id, AuthProvider.EMAIL)
    if not credential or not credential.password_hash:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.no_password_credential)
    if not await verify_secret(current, credential.password_hash):
        raise unauthorized(msg.auth.current_password_incorrect)
    if current == new:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.password_must_differ)
    credential.password_hash = await hash_secret(new)
    await _save_and_end_sessions(db, user_id)
    await audit.record("password.changed", user_id=user_id, resource_type="user", resource_id=user_id)


async def set_first(db: AsyncSession, user_id: str, new: str) -> None:
    email = await identifier_repo.find_primary(db, user_id, IdentifierType.EMAIL)
    if not email or not email.is_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.verified_email_required_for_password)
    if email.value.endswith(policy.APPLE_RELAY_DOMAIN):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.real_email_required_for_password)
    if await credential_repo.find_credential(db, user_id, AuthProvider.EMAIL):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.password_credential_exists)
    await credential_repo.add_credential(db, user_id, AuthProvider.EMAIL, email.value, await hash_secret(new))
    await _save_and_end_sessions(db, user_id)
    await audit.record("password.set", user_id=user_id, resource_type="user", resource_id=user_id)
