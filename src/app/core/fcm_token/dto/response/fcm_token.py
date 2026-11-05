from datetime import datetime
from typing import Literal

from app.common.schemas import Schema


class FcmTokenOut(Schema):
    id: str
    user_id: str
    token: str
    device_id: str
    platform: Literal["ios", "android", "web"]
    last_seen_at: datetime


class RemoveFcmTokenOut(Schema):
    removed: bool
