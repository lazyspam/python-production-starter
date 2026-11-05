import re
from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import Field, StringConstraints, field_validator
from sqlalchemy import select

from app.common.schemas import Envelope, Schema
from app.configs.settings import get_settings
from app.core.auth.deps import Auth
from app.core.files.models import FileObject, FileStatus, FileVisibility
from app.database.session import Db, utcnow
from app.infrastructure import storage
from app.locals import msg

router = APIRouter(prefix="/files", tags=["files"])

KEY_PREFIX = "uploads"
LIST_LIMIT = 50
# Allowlist, not a UX hint: extend deliberately.
ALLOWED_CONTENT_TYPES = (
    "image/jpeg", "image/png", "image/webp", "image/gif", "image/avif", "application/pdf",
    "application/zip", "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain", "text/csv", "video/mp4", "video/webm", "audio/mpeg", "audio/webm",
)  # fmt: skip


class UploadUrlIn(Schema):
    filename: Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)]
    content_type: str
    size: Annotated[int, Field(ge=1)]
    visibility: FileVisibility = FileVisibility.PRIVATE

    @field_validator("content_type")
    @classmethod
    def _allowed(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ALLOWED_CONTENT_TYPES:
            raise ValueError(f"must be one of: {', '.join(ALLOWED_CONTENT_TYPES)}")
        return value


class FileOut(Schema):
    id: str
    key: str
    content_type: str
    size: int | None
    original_name: str | None
    status: FileStatus
    visibility: FileVisibility
    created_at: datetime


class PresignedUpload(Schema):
    url: str
    method: str = "PUT"
    bucket: str
    key: str
    headers: dict[str, str]
    expires_in: int


class UploadUrlOut(Schema):
    file: FileOut
    upload: PresignedUpload


class FileItemOut(Schema):
    file: FileOut


class DownloadUrlOut(Schema):
    url: str
    expires_in: int | None = None


class RemoveFileOut(Schema):
    id: str


def build_object_key(owner_id: str, filename: str) -> str:
    """Traversal-safe key; the random segment stops same-named uploads from clobbering each other."""
    base = re.split(r"[\\/]", filename)[-1]
    name = re.sub(r"[^\w.-]+", "_", base)
    name = re.sub(r"_{2,}", "_", name).lstrip("._")[:100]
    return f"{KEY_PREFIX}/{owner_id}/{uuid4()}/{name or 'file'}"


async def _owned(db: Db, file_id: UUID, owner_id: str) -> FileObject:
    file = await db.scalar(select(FileObject).where(FileObject.id == str(file_id), FileObject.owner_id == owner_id))
    if file is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, msg.files.file_not_found)
    return file


@router.post("/upload-url", status_code=201)
async def request_upload_url(body: UploadUrlIn, user: Auth, db: Db) -> Envelope[UploadUrlOut]:
    s = get_settings()
    if body.size > s.s3_max_upload_bytes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.files.file_too_large)
    key = build_object_key(user.sub, body.filename)
    url = await storage.create_upload_url(key, body.content_type, body.size)
    file = FileObject(
        owner_id=user.sub, key=key, bucket=s.s3_bucket, content_type=body.content_type,
        original_name=body.filename, visibility=body.visibility,
    )  # fmt: skip
    db.add(file)
    await db.commit()
    upload = PresignedUpload(
        url=url, bucket=s.s3_bucket, key=key, expires_in=s.s3_upload_url_ttl_seconds,
        headers={"Content-Type": body.content_type, "Content-Length": str(body.size)},
    )  # fmt: skip
    data = UploadUrlOut(file=FileOut.model_validate(file), upload=upload)
    return Envelope(status_code=201, message=msg.files.upload_url_created, data=data)


@router.post("/{id}/complete", status_code=201)
async def complete_upload(id: UUID, user: Auth, db: Db) -> Envelope[FileItemOut]:
    file = await _owned(db, id, user.sub)
    if file.status != FileStatus.UPLOADED:
        size = await storage.get_object_size(file.key)
        if size is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.files.upload_not_found_in_storage)
        file.size, file.status, file.confirmed_at = size, FileStatus.UPLOADED, utcnow()
        await db.commit()
    data = FileItemOut(file=FileOut.model_validate(file))
    return Envelope(status_code=201, message=msg.files.upload_confirmed, data=data)


@router.get("/{id}/download-url")
async def get_download_url(id: UUID, user: Auth, db: Db) -> Envelope[DownloadUrlOut]:
    file = await _owned(db, id, user.sub)
    if file.status != FileStatus.UPLOADED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg.files.file_not_uploaded)
    if file.visibility == FileVisibility.PUBLIC and (url := storage.public_url(file.key)):
        data = DownloadUrlOut(url=url)
    else:
        data = DownloadUrlOut(
            url=await storage.create_download_url(file.key),
            expires_in=get_settings().s3_download_url_ttl_seconds,
        )
    return Envelope(message=msg.files.download_url_created, data=data)


@router.get("")
async def list_files(user: Auth, db: Db) -> Envelope[list[FileOut]]:
    stmt = select(FileObject).where(FileObject.owner_id == user.sub).order_by(FileObject.created_at.desc())
    files = (await db.scalars(stmt.limit(LIST_LIMIT))).all()
    return Envelope(data=[FileOut.model_validate(f) for f in files])


@router.delete("/{id}")
async def delete_file(id: UUID, user: Auth, db: Db) -> Envelope[RemoveFileOut]:
    file = await _owned(db, id, user.sub)
    await storage.delete_object(file.key)
    await db.delete(file)
    await db.commit()
    return Envelope(message=msg.files.file_deleted, data=RemoveFileOut(id=file.id))
