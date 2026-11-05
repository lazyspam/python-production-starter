from datetime import datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.models import IdentifierType, User, UserIdentifier
from app.database.session import utcnow


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


async def list_primaries(db: AsyncSession, user_id: str) -> list[UserIdentifier]:
    return list(await db.scalars(
        select(UserIdentifier).where(UserIdentifier.user_id == user_id, UserIdentifier.is_primary.is_(True))
    ))  # fmt: skip


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


async def add_identifier(
    db: AsyncSession, user_id: str, type_: IdentifierType, value: str, *, primary: bool, verified: bool
) -> UserIdentifier:
    identifier = UserIdentifier(
        user_id=user_id, type=type_, value=value, is_primary=primary, is_verified=verified,
        verified_at=utcnow() if verified else None,
    )  # fmt: skip
    db.add(identifier)
    return identifier


async def delete_identifier(db: AsyncSession, identifier: UserIdentifier) -> None:
    await db.delete(identifier)


async def clear_primary(db: AsyncSession, user_id: str, type_: IdentifierType) -> None:
    await db.execute(
        update(UserIdentifier).where(UserIdentifier.user_id == user_id, UserIdentifier.type == type_).values(is_primary=False)
    )


async def delete_held_by_deleted_users(db: AsyncSession, deleted_before: datetime) -> int:
    deleted = select(User.id).where(User.is_deleted.is_(True), User.deleted_at <= deleted_before)
    result = await db.execute(delete(UserIdentifier).where(UserIdentifier.user_id.in_(deleted)))
    return result.rowcount  # type: ignore[attr-defined]
