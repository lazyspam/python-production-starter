from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.models import IdentifierType, Profile, User
from app.core.auth.repositories import identifier as identifier_repo
from app.core.auth.types import AuthUser


async def find_user(db: AsyncSession, user_id: str) -> User | None:
    return await db.scalar(select(User).where(User.id == user_id, User.is_deleted.is_(False)))


async def get_user(db: AsyncSession, user_id: str) -> User | None:
    """Unlike find_user, also returns soft-deleted users."""
    return await db.get(User, user_id)


async def add_user(db: AsyncSession) -> User:
    user = User()
    db.add(user)
    return user


async def add_profile(db: AsyncSession, user_id: str, name: str) -> None:
    db.add(Profile(user_id=user_id, name=name))


async def lock_user(db: AsyncSession, user_id: str) -> None:
    """Serializes "keep at least one login or recovery method" checks for one user within a transaction."""
    await db.execute(select(User.id).where(User.id == user_id).with_for_update())


async def find_auth_user(db: AsyncSession, user_id: str) -> AuthUser | None:
    user = await find_user(db, user_id)
    if not user:
        return None
    profile = await db.scalar(select(Profile).where(Profile.user_id == user_id))
    primaries = {i.type: i for i in await identifier_repo.list_primaries(db, user_id)}
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
