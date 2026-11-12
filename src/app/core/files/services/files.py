import re
from datetime import timedelta
from uuid import UUID, uuid4

import structlog
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs.settings import get_settings
from app.core.files.constants import CLEANUP_BATCH, KEY_PREFIX, LIST_LIMIT, PENDING_UPLOAD_MIN_AGE
from app.core.files.models import FileObject, FileStatus, FileVisibility
from app.core.files.repositories import file as file_repo
from app.database.session import utcnow
from app.infrastructure import storage
from app.locals import msg

log = structlog.get_logger()


def build_object_key(owner_id: str, filename: str, visibility: FileVisibility) -> str:
    """Traversal-safe key; the random segment stops same-named uploads from clobbering each other.

    Public and private files live under separate prefixes, so a bucket policy can expose `uploads/public/*` only.
    """
    base = re.split(r"[\\/]", filename)[-1]
    name = re.sub(r"[^\w.-]+", "_", base)
    name = re.sub(r"_{2,}", "_", name).lstrip("._")[:100]
    return f"{KEY_PREFIX}/{visibility.lower()}/{owner_id}/{uuid4()}/{name or 'file'}"


async def _owned(db: AsyncSession, file_id: UUID, owner_id: str) -> FileObject:
    file = await file_repo.find_owned(db, str(file_id), owner_id)
    if file is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.files.file_not_found)
    return file


async def request_upload_url(
    db: AsyncSession, owner_id: str, filename: str, content_type: str, size: int, visibility: FileVisibility
) -> tuple[FileObject, dict]:
    s = get_settings()
    if size > s.s3_max_upload_bytes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.files.file_too_large)
    key = build_object_key(owner_id, filename, visibility)
    url = await storage.create_upload_url(key, content_type, size)
    file = await file_repo.add_file(
        db, owner_id=owner_id, key=key, bucket=s.s3_bucket, content_type=content_type,
        original_name=filename, visibility=visibility,
    )  # fmt: skip
    await db.commit()
    upload = {
        "url": url, "bucket": s.s3_bucket, "key": key, "expires_in": s.s3_upload_url_ttl_seconds,
        "headers": {"Content-Type": content_type, "Content-Length": str(size)},
    }  # fmt: skip
    return file, upload


async def complete_upload(db: AsyncSession, owner_id: str, file_id: UUID) -> FileObject:
    file = await _owned(db, file_id, owner_id)
    if file.status != FileStatus.UPLOADED:
        size = await storage.get_object_size(file.key)
        if size is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.files.upload_not_found_in_storage)
        file.size, file.status, file.confirmed_at = size, FileStatus.UPLOADED, utcnow()
        await db.commit()
    return file


async def download_url(db: AsyncSession, owner_id: str, file_id: UUID) -> dict:
    file = await _owned(db, file_id, owner_id)
    if file.status != FileStatus.UPLOADED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.files.file_not_uploaded)
    if file.visibility == FileVisibility.PUBLIC and (url := storage.public_url(file.key)):
        return {"url": url}
    return {
        "url": await storage.create_download_url(file.key),
        "expires_in": get_settings().s3_download_url_ttl_seconds,
    }


async def list_files(db: AsyncSession, owner_id: str) -> list[FileObject]:
    return await file_repo.list_owned(db, owner_id, LIST_LIMIT)


async def delete_file(db: AsyncSession, owner_id: str, file_id: UUID) -> str:
    file = await _owned(db, file_id, owner_id)
    await storage.delete_object(file.key)
    await file_repo.delete_file(db, file)
    await db.commit()
    return file.id


async def cleanup_pending(db: AsyncSession) -> int:
    """Removes uploads that were started but never confirmed, and their objects if the client uploaded anyway."""
    max_age = max(PENDING_UPLOAD_MIN_AGE, 2 * get_settings().s3_upload_url_ttl_seconds)
    stale = await file_repo.list_stale_pending(db, utcnow() - timedelta(seconds=max_age), CLEANUP_BATCH)
    removed = 0
    for file in stale:
        try:
            await storage.delete_object(file.key)
        except Exception:
            # Keep the row so the next run retries; dropping it would orphan the object.
            log.warning("pending_upload_object_delete_failed", key=file.key, exc_info=True)
            continue
        await file_repo.delete_file(db, file)
        removed += 1
    await db.commit()
    return removed
