"""Adding, changing and removing emails and phones, and account lifecycle."""

from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs import policy
from app.core.audit.services import audit
from app.core.auth.helpers.normalize import normalize_email, normalize_phone
from app.core.auth.models import IdentifierType, TwoFactorType, UserIdentifier, UserStatus
from app.core.auth.repositories import credential as credential_repo
from app.core.auth.repositories import identifier as identifier_repo
from app.core.auth.repositories import two_factor as two_factor_repo
from app.core.auth.repositories import user as user_repo
from app.core.auth.services import otp, tokens
from app.core.auth.services.otp import Purpose
from app.database.session import utcnow
from app.infrastructure.messaging import queue_mail
from app.locals import msg


def _in_use(type_: IdentifierType) -> HTTPException:
    message = msg.auth.email_already_in_use if type_ == IdentifierType.EMAIL else msg.auth.phone_already_in_use
    return HTTPException(status.HTTP_409_CONFLICT, message)


def _not_found() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.identifier_not_found)


async def _assert_free(db: AsyncSession, type_: IdentifierType, value: str, *, for_user: str | None = None) -> None:
    owner = await identifier_repo.find_identifier(db, type_, value)
    if owner and owner.user_id != for_user:
        raise _in_use(type_)


async def list_identifiers(db: AsyncSession, user_id: str) -> list[UserIdentifier]:
    return await identifier_repo.list_identifiers(db, user_id)


# Add


async def request_add_email(db: AsyncSession, user_id: str, email: str) -> None:
    value = normalize_email(email)
    await _assert_free(db, IdentifierType.EMAIL, value)
    await otp.issue(user_id, Purpose.ADD_EMAIL, "email", value)
    await audit.record(
        "email.change.requested", user_id=user_id, resource_type="identifier", metadata={"email": value, "mode": "add"}
    )


async def request_add_phone(db: AsyncSession, user_id: str, phone: str) -> None:
    value = normalize_phone(phone)
    await _assert_free(db, IdentifierType.PHONE, value)
    await otp.issue(user_id, Purpose.ADD_PHONE, "sms", value)


async def _commit_identifier(db: AsyncSession, user_id: str, type_: IdentifierType, value: str) -> None:
    await _assert_free(db, type_, value)
    is_primary = not await identifier_repo.find_primary(db, user_id, type_)
    identifier = await identifier_repo.add_identifier(db, user_id, type_, value, primary=is_primary, verified=True)
    if is_primary and type_ == IdentifierType.EMAIL:
        await credential_repo.sync_email_credential(db, user_id, value)
    await db.commit()
    action = "email.added" if type_ == IdentifierType.EMAIL else "phone.added"
    await audit.record(
        action, user_id=user_id, resource_type="identifier", resource_id=identifier.id,
        metadata={"identifierId": identifier.id, "value": value},
    )  # fmt: skip


async def confirm_add_email_token(db: AsyncSession, token: str) -> None:
    record = await otp.verify_token(token, Purpose.ADD_EMAIL)
    await _commit_identifier(db, record["user_id"], IdentifierType.EMAIL, record["destination"])


async def confirm_add_email_code(db: AsyncSession, user_id: str, code: str) -> None:
    record = await otp.verify_code(user_id, Purpose.ADD_EMAIL, "email", code)
    await _commit_identifier(db, user_id, IdentifierType.EMAIL, record["destination"])


async def confirm_add_phone(db: AsyncSession, user_id: str, code: str) -> None:
    record = await otp.verify_code(user_id, Purpose.ADD_PHONE, "sms", code)
    await _commit_identifier(db, user_id, IdentifierType.PHONE, record["destination"])


# Primary and removal


async def set_primary(db: AsyncSession, user_id: str, identifier_id: str) -> None:
    identifier = await identifier_repo.find_identifier_by_id(db, identifier_id)
    if not identifier or identifier.user_id != user_id:
        raise _not_found()
    if not identifier.is_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.identifier_not_verified)
    if identifier.is_primary:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.identifier_already_primary)
    await identifier_repo.clear_primary(db, user_id, identifier.type)
    identifier.is_primary = True
    if identifier.type == IdentifierType.EMAIL:
        await credential_repo.sync_email_credential(db, user_id, identifier.value)
    await db.commit()
    await tokens.revoke_all(db, user_id)
    await audit.record(
        "identifier.primary.changed", user_id=user_id, resource_type="identifier", resource_id=identifier_id,
        metadata={"identifierId": identifier_id, "type": identifier.type, "value": identifier.value},
    )  # fmt: skip


async def remove(db: AsyncSession, user_id: str, identifier_id: str) -> None:
    await user_repo.lock_user(db, user_id)
    identifier = await identifier_repo.find_identifier_by_id(db, identifier_id)
    if not identifier or identifier.user_id != user_id:
        raise _not_found()
    if identifier.is_primary:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.cannot_remove_primary_identifier)
    if identifier.is_verified and len(await identifier_repo.list_identifiers(db, user_id, verified_only=True)) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.cannot_remove_last_recovery_method)
    await identifier_repo.delete_identifier(db, identifier)
    await db.commit()
    await audit.record(
        "identifier.removed", user_id=user_id, resource_type="identifier", resource_id=identifier_id,
        metadata={"identifierId": identifier_id, "type": identifier.type, "value": identifier.value},
    )  # fmt: skip


# Change the primary email or phone


async def _replace_primary(db: AsyncSession, user_id: str, type_: IdentifierType, value: str) -> None:
    await _assert_free(db, type_, value, for_user=user_id)
    primary = await identifier_repo.find_primary(db, user_id, type_)
    if primary and primary.value == value:
        primary.is_verified, primary.verified_at = True, utcnow()
    else:
        if primary:
            await identifier_repo.delete_identifier(db, primary)
            await db.flush()
        await identifier_repo.add_identifier(db, user_id, type_, value, primary=True, verified=True)
    if type_ == IdentifierType.EMAIL:
        await credential_repo.sync_email_credential(db, user_id, value)

    two_factor_type = TwoFactorType.EMAIL_OTP if type_ == IdentifierType.EMAIL else TwoFactorType.SMS_OTP
    method = await two_factor_repo.find_method(db, user_id, two_factor_type)
    if method and method.is_enabled:
        await db.flush()
        verified = await identifier_repo.list_identifiers(db, user_id, verified_only=True)
        if method.destination not in {i.value for i in verified}:
            method.destination = value
    await db.commit()
    await tokens.revoke_all(db, user_id)


async def request_email_change(db: AsyncSession, user_id: str, new_email: str) -> None:
    email = normalize_email(new_email)
    await _assert_free(db, IdentifierType.EMAIL, email, for_user=user_id)
    primary = await identifier_repo.find_primary(db, user_id, IdentifierType.EMAIL)
    await otp.issue(user_id, Purpose.CHANGE_EMAIL, "email", email)
    if primary:
        text = (
            f"A request was made to change your account email to {email}. "
            "If this was not you, sign in and secure your account immediately."
        )
        await queue_mail(primary.value, "Your email address change was requested", text)
    await audit.record("email.change.requested", user_id=user_id, resource_type="identifier", metadata={"email": email})


async def _apply_email_change(db: AsyncSession, user_id: str, email: str) -> dict:
    await _replace_primary(db, user_id, IdentifierType.EMAIL, email)
    await audit.record("email.changed", user_id=user_id, resource_type="identifier", metadata={"email": email})
    return {"user_id": user_id, "email": email}


async def confirm_email_change_token(db: AsyncSession, token: str) -> dict:
    record = await otp.verify_token(token, Purpose.CHANGE_EMAIL)
    return await _apply_email_change(db, record["user_id"], record["destination"])


async def confirm_email_change_code(db: AsyncSession, user_id: str, code: str) -> dict:
    record = await otp.verify_code(user_id, Purpose.CHANGE_EMAIL, "email", code)
    return await _apply_email_change(db, user_id, record["destination"])


async def request_phone_change(db: AsyncSession, user_id: str, new_phone: str) -> None:
    phone = normalize_phone(new_phone)
    await _assert_free(db, IdentifierType.PHONE, phone, for_user=user_id)
    await otp.issue(user_id, Purpose.CHANGE_PHONE, "sms", phone)
    await audit.record(
        "phone.added", user_id=user_id, resource_type="identifier", metadata={"phone": phone, "mode": "change-request"}
    )


async def confirm_phone_change(db: AsyncSession, user_id: str, code: str) -> None:
    record = await otp.verify_code(user_id, Purpose.CHANGE_PHONE, "sms", code)
    await _replace_primary(db, user_id, IdentifierType.PHONE, record["destination"])
    await audit.record(
        "phone.added", user_id=user_id, resource_type="identifier",
        metadata={"phone": record["destination"], "mode": "change-confirm"},
    )  # fmt: skip


# Account lifecycle


async def deactivate(db: AsyncSession, user_id: str) -> None:
    user = await user_repo.find_user(db, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.user_not_found)
    user.is_deleted, user.deleted_at, user.status = True, utcnow(), UserStatus.SUSPENDED
    await db.commit()
    await tokens.revoke_all(db, user_id)
    await audit.record("account.deactivated", user_id=user_id, resource_type="user", resource_id=user_id)


async def reclaim_identifiers(db: AsyncSession) -> int:
    """Frees emails and phones held by accounts deleted longer ago than the grace period."""
    cutoff = utcnow() - timedelta(seconds=policy.IDENTIFIER_RECLAIM_GRACE)
    count = await identifier_repo.delete_held_by_deleted_users(db, cutoff)
    await db.commit()
    return count
