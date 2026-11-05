from dataclasses import dataclass

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.models import (
    Credential,
    IdentifierType,
    Profile,
    Role,
    Session,
    TwoFactorMethod,
    User,
    UserIdentifier,
)
from app.database.session import utcnow


@dataclass
class AuthUser:
    id: str
    role: Role
    name: str | None
    avatar: str | None
    email: str | None
    phone: str | None
    is_account_verified: bool


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    trimmed = phone.strip()
    digits = "".join(c for c in trimmed if c.isdigit())
    return f"+{digits}" if trimmed.startswith("+") else digits


def resolve_identifier(raw: str) -> tuple[IdentifierType, str]:
    raw = raw.strip()
    return (IdentifierType.EMAIL, normalize_email(raw)) if "@" in raw else (IdentifierType.PHONE, normalize_phone(raw))


# Users


async def find_user(db: AsyncSession, user_id: str) -> User | None:
    return await db.scalar(select(User).where(User.id == user_id, User.is_deleted.is_(False)))


async def find_auth_user(db: AsyncSession, user_id: str) -> AuthUser | None:
    user = await find_user(db, user_id)
    if not user:
        return None
    profile = await db.scalar(select(Profile).where(Profile.user_id == user_id))
    primaries = {i.type: i for i in await db.scalars(
        select(UserIdentifier).where(UserIdentifier.user_id == user_id, UserIdentifier.is_primary.is_(True))
    )}  # fmt: skip
    email, phone = primaries.get(IdentifierType.EMAIL), primaries.get(IdentifierType.PHONE)
    return AuthUser(
        id=user.id,
        role=user.role,
        name=profile.name if profile else None,
        avatar=profile.avatar_url if profile else None,
        email=email.value if email else None,
        phone=phone.value if phone else None,
        is_account_verified=any(i.is_verified for i in primaries.values()),
    )


# Identifiers


async def find_identifier(db: AsyncSession, type_: IdentifierType, value: str) -> UserIdentifier | None:
    return await db.scalar(select(UserIdentifier).where(UserIdentifier.type == type_, UserIdentifier.value == value))


async def find_identifier_by_id(db: AsyncSession, identifier_id: str) -> UserIdentifier | None:
    return await db.get(UserIdentifier, identifier_id)


async def find_active_owner(db: AsyncSession, type_: IdentifierType, value: str) -> tuple[UserIdentifier, User] | None:
    row = (await db.execute(
        select(UserIdentifier, User).join(User, User.id == UserIdentifier.user_id).where(
            UserIdentifier.type == type_, UserIdentifier.value == value, User.is_deleted.is_(False)
        )
    )).first()  # fmt: skip
    return (row[0], row[1]) if row else None


async def find_primary(db: AsyncSession, user_id: str, type_: IdentifierType) -> UserIdentifier | None:
    return await db.scalar(
        select(UserIdentifier).where(
            UserIdentifier.user_id == user_id, UserIdentifier.type == type_, UserIdentifier.is_primary.is_(True)
        )
    )


async def list_identifiers(db: AsyncSession, user_id: str, *, verified_only: bool = False) -> list[UserIdentifier]:
    stmt = select(UserIdentifier).where(UserIdentifier.user_id == user_id)
    if verified_only:
        stmt = stmt.where(UserIdentifier.is_verified.is_(True))
    order = (UserIdentifier.type, UserIdentifier.is_primary.desc(), UserIdentifier.created_at)
    return list(await db.scalars(stmt.order_by(*order)))


async def is_account_verified(db: AsyncSession, user_id: str) -> bool:
    count = await db.scalar(
        select(func.count()).select_from(UserIdentifier).where(
            UserIdentifier.user_id == user_id, UserIdentifier.is_primary.is_(True), UserIdentifier.is_verified.is_(True)
        )
    )  # fmt: skip
    return bool(count)


def new_identifier(user_id: str, type_: IdentifierType, value: str, *, primary: bool, verified: bool) -> UserIdentifier:
    return UserIdentifier(
        user_id=user_id, type=type_, value=value, is_primary=primary, is_verified=verified,
        verified_at=utcnow() if verified else None,
    )  # fmt: skip


async def lock_user(db: AsyncSession, user_id: str) -> None:
    """Serializes "keep at least one login or recovery method" checks for one user within a transaction."""
    await db.execute(select(User.id).where(User.id == user_id).with_for_update())


# Credentials


async def find_credential(db: AsyncSession, user_id: str, provider: str) -> Credential | None:
    return await db.scalar(select(Credential).where(Credential.user_id == user_id, Credential.provider == provider))


async def find_credential_by_identity(db: AsyncSession, provider: str, provider_id: str) -> Credential | None:
    return await db.scalar(select(Credential).where(Credential.provider == provider, Credential.provider_id == provider_id))


async def sync_email_credential(db: AsyncSession, user_id: str, email: str) -> None:
    credential = await find_credential(db, user_id, "EMAIL")
    if credential:
        credential.provider_id = email


# Sessions


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


# Two-factor


async def find_method(db: AsyncSession, user_id: str, type_: str) -> TwoFactorMethod | None:
    return await db.scalar(select(TwoFactorMethod).where(TwoFactorMethod.user_id == user_id, TwoFactorMethod.type == type_))


async def enabled_methods(db: AsyncSession, user_id: str) -> list[TwoFactorMethod]:
    return list(await db.scalars(
        select(TwoFactorMethod).where(TwoFactorMethod.user_id == user_id, TwoFactorMethod.is_enabled.is_(True))
        .order_by(TwoFactorMethod.is_primary.desc(), TwoFactorMethod.created_at)
    ))  # fmt: skip
