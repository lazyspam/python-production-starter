from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, IdMixin, TimestampMixin


class FileStatus(StrEnum):
    PENDING = "PENDING"
    UPLOADED = "UPLOADED"


class FileVisibility(StrEnum):
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"


class FileObject(IdMixin, TimestampMixin, Base):
    """S3 object metadata. PENDING when the upload URL is issued, UPLOADED once the object is confirmed."""

    __tablename__ = "file_objects"

    owner_id: Mapped[str] = mapped_column(String(36), index=True)
    key: Mapped[str] = mapped_column(String(1024), unique=True)
    bucket: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    size: Mapped[int | None] = mapped_column(Integer)
    original_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[FileStatus] = mapped_column(Enum(FileStatus, name="file_status"), default=FileStatus.PENDING, index=True)
    visibility: Mapped[FileVisibility] = mapped_column(
        Enum(FileVisibility, name="file_visibility"), default=FileVisibility.PRIVATE
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
