"""One-time codes and links, held in Redis. One live session per user, purpose and channel."""

import html
import math
import time
from dataclasses import dataclass
from enum import StrEnum

import structlog
from fastapi import HTTPException, status

from app.common.security import hash_secret, random_code, random_token, sha256, verify_secret
from app.configs import policy
from app.configs.settings import get_settings
from app.core.auth.services.tokens import unauthorized
from app.infrastructure.cache import cache, key
from app.infrastructure.messaging import queue_mail, queue_sms
from app.locals import msg

log = structlog.get_logger()
Channel = str  # "email" | "sms"


class Purpose(StrEnum):
    LOGIN = "login"
    REGISTER_VERIFY = "register-verify"
    REGISTER_VERIFY_PHONE = "register-verify-phone"
    RESET_PASSWORD = "reset-password"
    ENROLL_2FA = "enroll-2fa"
    CHANGE_EMAIL = "change-email"
    ADD_EMAIL = "add-email"
    ADD_PHONE = "add-phone"
    CHANGE_PHONE = "change-phone"
    SUDO = "sudo"
    SUDO_2FA = "sudo-2fa"


@dataclass(frozen=True)
class PurposeConfig:
    ttl: int
    subject: str
    wording: str
    """Fills "Your {wording} code is 123456."; a link adds "{subject}: <url>"."""
    link_path: str | None = None
    """Set when the email also carries a link."""


_t = msg.otp
_PURPOSES = {
    Purpose.LOGIN: PurposeConfig(policy.TWO_FACTOR_CHALLENGE_TTL, _t.sign_in_subject, _t.sign_in_wording),
    Purpose.REGISTER_VERIFY: PurposeConfig(
        policy.EMAIL_VERIFY_TTL, _t.verify_email_subject, _t.verification_wording, "verify-email"
    ),
    Purpose.REGISTER_VERIFY_PHONE: PurposeConfig(policy.EMAIL_VERIFY_TTL, _t.verify_phone_subject, _t.verification_wording),
    Purpose.RESET_PASSWORD: PurposeConfig(
        policy.PASSWORD_RESET_TTL, _t.reset_password_subject, _t.reset_password_wording, "reset-password"
    ),
    Purpose.ENROLL_2FA: PurposeConfig(policy.OTP_TTL, _t.enroll_2fa_subject, _t.enroll_2fa_wording),
    Purpose.CHANGE_EMAIL: PurposeConfig(
        policy.IDENTIFIER_CHANGE_TTL, _t.confirm_email_subject, _t.confirmation_wording, "confirm-email"
    ),
    Purpose.ADD_EMAIL: PurposeConfig(
        policy.IDENTIFIER_CHANGE_TTL, _t.confirm_email_subject, _t.confirmation_wording, "confirm-email"
    ),
    Purpose.ADD_PHONE: PurposeConfig(policy.IDENTIFIER_CHANGE_TTL, _t.confirm_phone_subject, _t.phone_confirmation_wording),
    Purpose.CHANGE_PHONE: PurposeConfig(policy.IDENTIFIER_CHANGE_TTL, _t.confirm_phone_subject, _t.phone_confirmation_wording),
    Purpose.SUDO: PurposeConfig(policy.OTP_SUDO_TTL, _t.sudo_subject, _t.confirmation_wording),
    Purpose.SUDO_2FA: PurposeConfig(policy.OTP_SUDO_TTL, _t.sudo_subject, _t.confirmation_wording),
}  # fmt: skip


def _session_key(user_id: str, purpose: str, channel: str) -> str:
    return key(f"otp:session:{user_id}:{purpose}:{channel}")


def _attempts_key(user_id: str, purpose: str, channel: str) -> str:
    return key(f"otp:attempts:{user_id}:{purpose}:{channel}")


def _token_key(token_hash: str) -> str:
    return key(f"otp:token:{token_hash}")


def _too_many(message: str) -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, message)


async def _destroy(record: dict) -> bool:
    """True only for the one caller that actually removed the session."""
    removed = await cache.delete(_session_key(record["user_id"], record["purpose"], record["channel"]))
    await cache.delete(_attempts_key(record["user_id"], record["purpose"], record["channel"]))
    if record.get("token_hash"):
        await cache.delete(_token_key(record["token_hash"]))
    return bool(removed)


async def _send(config: PurposeConfig, channel: str, destination: str, code: str, token: str | None) -> None:
    expiry = msg.otp.expiry_line.format(minutes=round(config.ttl / 60))
    code_line = msg.otp.code_line.format(wording=config.wording, code=code)
    if channel == "sms":
        await queue_sms(destination, f"{code_line} {expiry}")
        return
    link = None
    if token and config.link_path:
        link = f"{get_settings().frontend_url.rstrip('/')}/{config.link_path}?token={token}"
    link_line = msg.otp.link_line.format(subject=config.subject, link=link) if link else None
    text = "\n\n".join(p for p in (link_line, code_line, expiry) if p)
    anchor = f'<a href="{html.escape(link)}">{html.escape(link)}</a>' if link else ""
    link_html = f"<p>{msg.otp.link_line.format(subject=html.escape(config.subject), link=anchor)}</p>" if link else ""
    await queue_mail(destination, config.subject, text, f"{link_html}<p>{code_line}</p><p>{expiry}</p>")


async def issue(user_id: str, purpose: Purpose, channel: Channel, destination: str) -> None:
    config = _PURPOSES[purpose]
    existing = await cache.get(_session_key(user_id, purpose, channel))
    if existing:
        age = int(time.time() - existing["sent_at"])
        if age < policy.OTP_RESEND_COOLDOWN:
            raise _too_many(msg.auth.otp_resend_cooldown.format(seconds=policy.OTP_RESEND_COOLDOWN - age))
        await _destroy(existing)

    sends_key = key(f"otp:throttle:{channel}:{destination}")
    if int(await cache.get(sends_key) or 0) >= policy.OTP_MAX_SENDS_PER_WINDOW:
        raise _too_many(msg.auth.too_many_requests_destination)

    code = random_code()
    token = random_token() if channel == "email" and config.link_path else None
    await _send(config, channel, destination, code, token)
    if not get_settings().is_production:
        log.info("dev_otp", purpose=purpose.value, destination=destination, code=code, token=token)

    now = time.time()
    token_hash = sha256(token) if token else None
    record = {
        "user_id": user_id, "purpose": purpose.value, "channel": channel, "destination": destination,
        "code_hash": await hash_secret(code), "token_hash": token_hash,
        "sent_at": now, "expires_at": now + config.ttl,
    }  # fmt: skip
    await cache.set(_session_key(user_id, purpose, channel), record, expire=config.ttl)
    await cache.delete(_attempts_key(user_id, purpose, channel))
    if token_hash:
        index = {"user_id": user_id, "purpose": purpose.value, "channel": channel}
        await cache.set(_token_key(token_hash), index, expire=config.ttl)
    await cache.incr(sends_key, expire=policy.OTP_SEND_WINDOW)


async def verify_code(user_id: str, purpose: Purpose, channel: Channel, code: str) -> dict:
    """Returns the consumed session. Each try reserves an attempt atomically first, so parallel guesses can't exceed the cap."""
    record = await cache.get(_session_key(user_id, purpose, channel))
    if not record:
        raise unauthorized(msg.auth.code_invalid_or_expired)
    ttl = max(1, math.ceil(record["expires_at"] - time.time()))
    if await cache.incr(_attempts_key(user_id, purpose, channel), expire=ttl) > policy.OTP_MAX_ATTEMPTS:
        await _destroy(record)
        raise _too_many(msg.auth.too_many_incorrect_attempts)
    if not await verify_secret(code, record["code_hash"]) or not await _destroy(record):
        raise unauthorized(msg.auth.code_invalid_or_expired)
    return record


async def verify_token(raw_token: str, purpose: Purpose) -> dict:
    token_hash = sha256(raw_token)
    index = await cache.get(_token_key(token_hash))
    if not index or index["purpose"] != purpose:
        raise unauthorized(msg.auth.link_invalid_or_expired)
    record = await cache.get(_session_key(index["user_id"], index["purpose"], index["channel"]))
    if not record or record.get("token_hash") != token_hash or not await _destroy(record):
        await cache.delete(_token_key(token_hash))
        raise unauthorized(msg.auth.link_invalid_or_expired)
    return record
