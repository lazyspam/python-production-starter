from datetime import datetime

from app.common.schemas import Schema


class IdentifierOut(Schema):
    id: str
    type: str
    value: str
    is_primary: bool
    is_verified: bool
    verified_at: datetime | None
    created_at: datetime


class EmailChangedOut(Schema):
    user_id: str
    email: str
