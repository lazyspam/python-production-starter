from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.files.models import FileObject


async def find_owned(db: AsyncSession, file_id: str, owner_id: str) -> FileObject | None:
    return await db.scalar(select(FileObject).where(FileObject.id == file_id, FileObject.owner_id == owner_id))


async def list_owned(db: AsyncSession, owner_id: str, limit: int) -> list[FileObject]:
    stmt = select(FileObject).where(FileObject.owner_id == owner_id).order_by(FileObject.created_at.desc())
    return list(await db.scalars(stmt.limit(limit)))


async def add_file(db: AsyncSession, **fields) -> FileObject:
    file = FileObject(**fields)
    db.add(file)
    return file


async def delete_file(db: AsyncSession, file: FileObject) -> None:
    await db.delete(file)
