from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.models import TwoFactorBackupCode, TwoFactorMethod
from app.database.session import utcnow


async def find_method(db: AsyncSession, user_id: str, type_: str) -> TwoFactorMethod | None:
    return await db.scalar(select(TwoFactorMethod).where(TwoFactorMethod.user_id == user_id, TwoFactorMethod.type == type_))


async def get_method(db: AsyncSession, method_id: str) -> TwoFactorMethod | None:
    return await db.get(TwoFactorMethod, method_id)


async def list_methods(db: AsyncSession, user_id: str) -> list[TwoFactorMethod]:
    return list(await db.scalars(
        select(TwoFactorMethod).where(TwoFactorMethod.user_id == user_id).order_by(TwoFactorMethod.created_at)
    ))  # fmt: skip


async def enabled_methods(db: AsyncSession, user_id: str) -> list[TwoFactorMethod]:
    return list(await db.scalars(
        select(TwoFactorMethod).where(TwoFactorMethod.user_id == user_id, TwoFactorMethod.is_enabled.is_(True))
        .order_by(TwoFactorMethod.is_primary.desc(), TwoFactorMethod.created_at)
    ))  # fmt: skip


async def add_method(db: AsyncSession, user_id: str, type_: str, **fields: str) -> TwoFactorMethod:
    method = TwoFactorMethod(user_id=user_id, type=type_, **fields)
    db.add(method)
    return method


async def delete_method(db: AsyncSession, method: TwoFactorMethod) -> None:
    await db.delete(method)


async def add_backup_codes(db: AsyncSession, user_id: str, code_hashes: list[str]) -> None:
    db.add_all(TwoFactorBackupCode(user_id=user_id, code_hash=code_hash) for code_hash in code_hashes)


async def delete_backup_codes(db: AsyncSession, user_id: str) -> None:
    await db.execute(delete(TwoFactorBackupCode).where(TwoFactorBackupCode.user_id == user_id))


async def count_backup_codes(db: AsyncSession, user_id: str) -> int:
    count = await db.scalar(
        select(func.count()).select_from(TwoFactorBackupCode).where(
            TwoFactorBackupCode.user_id == user_id, TwoFactorBackupCode.used_at.is_(None)
        )
    )  # fmt: skip
    return count or 0


async def claim_backup_code(db: AsyncSession, user_id: str, code_hash: str) -> bool:
    """Atomic: one UPDATE, so a code can't be spent twice by concurrent requests."""
    result = await db.execute(
        update(TwoFactorBackupCode).where(
            TwoFactorBackupCode.user_id == user_id,
            TwoFactorBackupCode.code_hash == code_hash,
            TwoFactorBackupCode.used_at.is_(None),
        ).values(used_at=utcnow())
    )  # fmt: skip
    return bool(result.rowcount)  # type: ignore[attr-defined]
