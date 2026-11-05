from typing import Annotated

from pydantic import Field, StringConstraints, field_validator

from app.common.schemas import Schema
from app.core.files.constants import ALLOWED_CONTENT_TYPES
from app.core.files.models import FileVisibility


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
