import pyotp
import segno
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.security import decrypt, encrypt, random_token, sha256
from app.configs import policy
from app.configs.settings import get_settings
from app.core.audit.services import audit
from app.core.auth.models import IdentifierType, TwoFactorMethod, TwoFactorType, UserStatus
from app.core.auth.repositories import identifier as identifier_repo
from app.core.auth.repositories import two_factor as two_factor_repo
from app.core.auth.repositories import user as user_repo
from app.core.auth.services import otp, tokens
from app.core.auth.services.otp import Purpose
from app.core.auth.services.tokens import unauthorized
from app.database.session import utcnow
from app.infrastructure.cache import cache, key, take
from app.locals import msg

_CHANNELS = {TwoFactorType.EMAIL_OTP: "email", TwoFactorType.SMS_OTP: "sms"}
_IDENTIFIER_TYPES = {TwoFactorType.EMAIL_OTP: IdentifierType.EMAIL, TwoFactorType.SMS_OTP: IdentifierType.PHONE}


def _challenge_key(challenge_id: str) -> str:
    return key(f"2fa-challenge:{challenge_id}")


def channel_of(type_: str) -> str:
    return _CHANNELS[TwoFactorType(type_)]


def verify_totp(secret_ciphertext: str, code: str) -> bool:
    return pyotp.TOTP(decrypt(secret_ciphertext)).verify(code, valid_window=get_settings().totp_window)


async def _upsert_method(db: AsyncSession, user_id: str, type_: TwoFactorType, **fields: str) -> TwoFactorMethod:
    method = await two_factor_repo.find_method(db, user_id, type_)
    if method:
        for name, value in fields.items():
            setattr(method, name, value)
    else:
        method = await two_factor_repo.add_method(db, user_id, type_, **fields)
    await db.commit()
    return method


async def _enable(db: AsyncSession, method: TwoFactorMethod) -> None:
    method.is_enabled, method.verified_at = True, utcnow()
    await db.commit()
    await audit.record("2fa.enabled", user_id=method.user_id, resource_type="two_factor", metadata={"type": method.type})


# TOTP


async def enroll_totp(db: AsyncSession, user_id: str) -> dict:
    user = await user_repo.find_user(db, user_id)
    if not user:
        raise unauthorized(msg.auth.user_not_found)
    existing = await two_factor_repo.find_method(db, user.id, TwoFactorType.TOTP)
    if existing and existing.is_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.totp_already_enabled)

    secret = pyotp.random_base32()
    method = await _upsert_method(db, user.id, TwoFactorType.TOTP, secret=encrypt(secret))
    email = await identifier_repo.find_primary(db, user.id, IdentifierType.EMAIL)
    url = pyotp.TOTP(secret).provisioning_uri(email.value if email else user.id, issuer_name=get_settings().totp_issuer)
    return {"method_id": method.id, "secret": secret, "otpauth_url": url, "qr_data_url": segno.make(url).png_data_uri(scale=5)}


async def confirm_totp(db: AsyncSession, user_id: str, code: str) -> list[str] | None:
    """Returns backup codes when this is the first confirmed method: they are shown once."""
    method = await two_factor_repo.find_method(db, user_id, TwoFactorType.TOTP)
    if not method or not method.secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.totp_enrollment_not_started)
    if method.is_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.totp_already_enabled)
    if not verify_totp(method.secret, code):
        raise unauthorized(msg.auth.invalid_authenticator_code)
    await _enable(db, method)
    return await issue_backup_codes_if_none(db, user_id)


# Email and SMS OTP


async def enroll_otp(db: AsyncSession, user_id: str, type_: TwoFactorType) -> None:
    is_email = type_ == TwoFactorType.EMAIL_OTP
    verified = await identifier_repo.list_identifiers(db, user_id, verified_only=True)
    match = next((i for i in verified if i.type == _IDENTIFIER_TYPES[type_]), None)
    if not match:
        raise HTTPException(400, msg.auth.no_email_to_enroll if is_email else msg.auth.no_phone_to_enroll)
    existing = await two_factor_repo.find_method(db, user_id, type_)
    if existing and existing.is_enabled:
        raise HTTPException(409, msg.auth.email_otp_already_enabled if is_email else msg.auth.sms_otp_already_enabled)
    await _upsert_method(db, user_id, type_, destination=match.value)
    await otp.issue(user_id, Purpose.ENROLL_2FA, _CHANNELS[type_], match.value)


async def confirm_otp(db: AsyncSession, user_id: str, type_: TwoFactorType, code: str) -> list[str] | None:
    is_email = type_ == TwoFactorType.EMAIL_OTP
    method = await two_factor_repo.find_method(db, user_id, type_)
    if not method:
        message = msg.auth.email_otp_enrollment_not_started if is_email else msg.auth.sms_otp_enrollment_not_started
        raise HTTPException(404, message)
    if method.is_enabled:
        raise HTTPException(409, msg.auth.email_otp_already_enabled if is_email else msg.auth.sms_otp_already_enabled)
    await otp.verify_code(user_id, Purpose.ENROLL_2FA, _CHANNELS[type_], code)
    await _enable(db, method)
    return await issue_backup_codes_if_none(db, user_id)


async def list_methods(db: AsyncSession, user_id: str) -> list[TwoFactorMethod]:
    return await two_factor_repo.list_methods(db, user_id)


async def disable(db: AsyncSession, user_id: str, method_id: str) -> None:
    method = await two_factor_repo.get_method(db, method_id)
    if not method or method.user_id != user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.auth.two_factor_method_not_found)
    await two_factor_repo.delete_method(db, method)
    await db.flush()
    if not await two_factor_repo.enabled_methods(db, user_id):
        await two_factor_repo.delete_backup_codes(db, user_id)
    await db.commit()
    await audit.record(
        "2fa.disabled", user_id=user_id, resource_type="two_factor", resource_id=method_id,
        metadata={"methodId": method_id, "type": method.type},
    )  # fmt: skip


# Backup codes


async def _replace_backup_codes(db: AsyncSession, user_id: str) -> list[str]:
    codes = [random_token(policy.BACKUP_CODE_BYTES) for _ in range(policy.BACKUP_CODE_COUNT)]
    await two_factor_repo.delete_backup_codes(db, user_id)
    await two_factor_repo.add_backup_codes(db, user_id, [sha256(code) for code in codes])
    await db.commit()
    return codes


async def count_backup_codes(db: AsyncSession, user_id: str) -> int:
    return await two_factor_repo.count_backup_codes(db, user_id)


async def issue_backup_codes_if_none(db: AsyncSession, user_id: str) -> list[str] | None:
    return None if await count_backup_codes(db, user_id) else await _replace_backup_codes(db, user_id)


async def regenerate_backup_codes(db: AsyncSession, user_id: str) -> list[str]:
    if not await two_factor_repo.enabled_methods(db, user_id):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.enable_2fa_before_backup_codes)
    return await _replace_backup_codes(db, user_id)


async def claim_backup_code(db: AsyncSession, user_id: str, code: str) -> bool:
    claimed = await two_factor_repo.claim_backup_code(db, user_id, sha256(code))
    await db.commit()
    return claimed


# Login challenge


async def issue_challenge(user_id: str, methods: list[TwoFactorMethod]) -> dict:
    challenge_id = random_token(24)
    record = {"user_id": user_id, "method_ids": [m.id for m in methods], "attempts": 0}
    await cache.set(_challenge_key(challenge_id), record, expire=policy.TWO_FACTOR_CHALLENGE_TTL)
    return {"challenge_id": challenge_id, "methods": [m.type for m in methods]}


async def send_challenge_code(db: AsyncSession, challenge_id: str, type_: TwoFactorType) -> None:
    if type_ == TwoFactorType.TOTP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.auth.totp_no_sent_code)
    record = await cache.get(_challenge_key(challenge_id))
    if not record:
        raise unauthorized(msg.auth.challenge_invalid_or_expired)
    methods = await two_factor_repo.enabled_methods(db, record["user_id"])
    method = next((m for m in methods if m.type == type_ and m.id in record["method_ids"]), None)
    if not method or not method.destination:
        raise HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.method_not_available_for_challenge)
    await otp.issue(record["user_id"], Purpose.LOGIN, _CHANNELS[type_], method.destination)


async def verify_challenge(db: AsyncSession, challenge_id: str, type_: TwoFactorType, code: str) -> tokens.AuthTokens:
    challenge_key = _challenge_key(challenge_id)
    record = await cache.get(challenge_key)
    if not record:
        raise unauthorized(msg.auth.challenge_invalid_or_expired)
    user = await user_repo.find_user(db, record["user_id"])
    if not user or user.status != UserStatus.ACTIVE:
        raise unauthorized(msg.auth.account_no_longer_available)

    methods = await two_factor_repo.enabled_methods(db, user.id)
    method = next((m for m in methods if m.type == type_ and m.id in record["method_ids"]), None)
    if not method:
        raise HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.method_not_available_for_challenge)

    if type_ == TwoFactorType.TOTP:
        if not method.secret:
            raise HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.totp_method_missing_secret)
        ok = verify_totp(method.secret, code)
    else:
        try:
            await otp.verify_code(user.id, Purpose.LOGIN, _CHANNELS[type_], code)
            ok = True
        except HTTPException:
            ok = False

    if not ok and not await claim_backup_code(db, user.id, code):
        attempts = record["attempts"] + 1
        if attempts >= policy.OTP_MAX_ATTEMPTS:
            await cache.delete(challenge_key)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, msg.auth.too_many_incorrect_attempts)
        await cache.set(challenge_key, {**record, "attempts": attempts}, expire=policy.TWO_FACTOR_CHALLENGE_TTL)
        raise unauthorized(msg.auth.invalid_code)

    if not await take(challenge_key):
        raise unauthorized(msg.auth.challenge_invalid_or_expired)
    method.last_used_at = utcnow()
    await db.commit()
    return await tokens.issue(db, user.id)
