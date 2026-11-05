import time

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
    """Always returns a reset id, so an unknown account looks the same as one with nothing to send to."""
    reset_id = random_token(24)
    empty = {"reset_id": reset_id, "channels": []}
    owner = await identifier_repo.find_active_owner(db, *resolve_identifier(identifier))
    if not owner:
        return empty
    user_id = owner[1].id
    credential = await credential_repo.find_credential(db, user_id, AuthProvider.EMAIL)
    verified = await identifier_repo.list_identifiers(db, user_id, verified_only=True)
    if not credential or not credential.password_hash or not verified:
        return empty

    record = {"user_id": user_id, "channel_ids": [i.id for i in verified], "created_at": time.time(), "otp_channel": None}
    ttl = policy.PASSWORD_RESET_CHALLENGE_TTL
    await cache.set(_reset_key(reset_id), record, expire=ttl)
    await cache.set(_user_reset_key(user_id), reset_id, expire=ttl)
    channels = [
        {"id": i.id, "type": i.type, "hint": mask_email(i.value) if i.type == IdentifierType.EMAIL else mask_phone(i.value)}
        for i in verified
    ]
    return {"reset_id": reset_id, "channels": channels}


async def send(db: AsyncSession, reset_id: str, channel_id: str) -> None:
    challenge = await cache.get(_reset_key(reset_id))
    if not challenge or channel_id not in challenge["channel_ids"]:
        raise _invalid_challenge()
    identifier = await identifier_repo.find_identifier_by_id(db, channel_id)
    if not identifier or identifier.user_id != challenge["user_id"] or not identifier.is_verified:
        raise _invalid_challenge()
    channel = "email" if identifier.type == IdentifierType.EMAIL else "sms"
    await otp.issue(challenge["user_id"], Purpose.RESET_PASSWORD, channel, identifier.value)
    remaining = max(1, policy.PASSWORD_RESET_CHALLENGE_TTL - int(time.time() - challenge["created_at"]))
    await cache.set(_reset_key(reset_id), {**challenge, "otp_channel": channel}, expire=remaining)


async def _apply_new_password(db: AsyncSession, user_id: str, new_password: str) -> None:
    credential = await credential_repo.find_credential(db, user_id, AuthProvider.EMAIL)
    if not credential:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.no_password_credential)
    credential.password_hash = await hash_secret(new_password)
    await db.commit()
    await tokens.revoke_all(db, user_id)
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
    await db.commit()
    await tokens.revoke_all(db, user_id)
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
    await db.commit()
    await tokens.revoke_all(db, user_id)
    await audit.record("password.set", user_id=user_id, resource_type="user", resource_id=user_id)
