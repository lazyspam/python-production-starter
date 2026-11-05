from datetime import datetime

from app.common.schemas import Schema
from app.core.files.models import FileStatus, FileVisibility


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
