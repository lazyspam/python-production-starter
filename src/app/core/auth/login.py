from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.security import hash_secret, sha256, verify_secret
from app.configs import policy
from app.core.audit import service as audit
from app.core.audit.models import AuditOutcome
from app.core.auth import otp, tokens, two_factor
from app.core.auth import repository as repo
from app.core.auth.models import AuthProvider, Credential, IdentifierType, Profile, User, UserStatus
from app.core.auth.otp import Purpose
from app.core.auth.repository import AuthUser, normalize_email, normalize_phone
from app.core.auth.tokens import AuthTokens, unauthorized
from app.database.session import utcnow
from app.infrastructure.cache import cache, key
from app.locals import msg


@dataclass
class LoginResult:
    tokens: AuthTokens | None = None
    user: AuthUser | None = None
    challenge: dict | None = None


async def finish_login(db: AsyncSession, user_id: str) -> LoginResult:
    """Asks for a second factor when one is on (only verified accounts can have one), else starts a session."""
    if await repo.is_account_verified(db, user_id):
        methods = await repo.enabled_methods(db, user_id)
        if methods:
            return LoginResult(challenge=await two_factor.issue_challenge(user_id, methods))
    user = await repo.find_auth_user(db, user_id)
    if not user:
        raise unauthorized(msg.auth.account_no_longer_available)
    return LoginResult(tokens=await tokens.issue(db, user_id), user=user)


async def register(db: AsyncSession, *, email: str | None, phone: str | None, password: str, name: str | None) -> LoginResult:
    email = normalize_email(email) if email else None
    phone = normalize_phone(phone) if phone else None
    if email and await repo.find_identifier(db, IdentifierType.EMAIL, email):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.email_already_registered)
    if phone and await repo.find_identifier(db, IdentifierType.PHONE, phone):
        raise HTTPException(status.HTTP_409_CONFLICT, msg.auth.phone_already_registered)
    provider_id = email or phone
    assert provider_id

    password_hash = await hash_secret(password)
    user = User()
    db.add(user)
    await db.flush()
    db.add(Credential(user_id=user.id, provider=AuthProvider.EMAIL, provider_id=provider_id, password_hash=password_hash))
    if name:
        db.add(Profile(user_id=user.id, name=name))
    if email:
        db.add(repo.new_identifier(user.id, IdentifierType.EMAIL, email, primary=True, verified=False))
    if phone:
        db.add(repo.new_identifier(user.id, IdentifierType.PHONE, phone, primary=True, verified=False))
    await db.commit()

    for purpose, channel, destination in (
        (Purpose.REGISTER_VERIFY, "email", email),
        (Purpose.REGISTER_VERIFY_PHONE, "sms", phone),
    ):
        if destination:
            try:
                await otp.issue(user.id, purpose, channel, destination)
            except HTTPException:
                pass  # The account exists; the user can ask for a new code.

    auth_user = await repo.find_auth_user(db, user.id)
    issued = await tokens.issue(db, user.id)
    await audit.record(
        "register", user_id=user.id, resource_type="user", resource_id=user.id, metadata={"email": email, "phone": phone}
    )
    return LoginResult(tokens=issued, user=auth_user)


async def login(db: AsyncSession, *, email: str | None, phone: str | None, password: str) -> LoginResult:
    type_, value = repo.resolve_identifier(email or phone or "")
    identity_hash = sha256(value)
    fails_key = key(f"login:fail:{identity_hash}")

    if int(await cache.get(fails_key) or 0) >= policy.LOGIN_MAX_FAILS:
        await audit.record("login.lockout", outcome=AuditOutcome.FAILURE, metadata={"identityHash": identity_hash})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, msg.auth.too_many_failed_attempts)

    owner = await repo.find_active_owner(db, type_, value)
    user = owner[1] if owner and owner[1].status == UserStatus.ACTIVE else None
    credential = await repo.find_credential(db, user.id, AuthProvider.EMAIL) if user else None

    if not await verify_secret(password, credential.password_hash if credential else None) or not user or not credential:
        await cache.incr(fails_key, expire=policy.LOGIN_LOCKOUT_TTL)
        await audit.record(
            "login.fail", outcome=AuditOutcome.FAILURE, user_id=owner[1].id if owner else None,
            metadata={"identityHash": identity_hash},
        )  # fmt: skip
        raise unauthorized(msg.auth.invalid_credentials)

    await cache.delete(fails_key)
    credential.last_used_at = utcnow()
    await db.commit()
    result = await finish_login(db, user.id)
    if result.tokens:
        await audit.record("login.success", user_id=user.id, resource_type="user", resource_id=user.id)
    return result
