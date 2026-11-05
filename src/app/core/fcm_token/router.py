from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter
from pydantic import StringConstraints
from sqlalchemy import delete, select

from app.common.schemas import Envelope, Schema
from app.core.auth.deps import Auth
from app.core.fcm_token.models import FcmToken
from app.database.session import Db, utcnow
from app.locals import msg

router = APIRouter(prefix="/fcm-tokens", tags=["fcm-tokens"])

Token = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9_:-]+$", max_length=1024)]


class RegisterFcmTokenIn(Schema):
    token: Token
    platform: Literal["ios", "android", "web"]
    device_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


class RemoveFcmTokenIn(Schema):
    token: Token


class FcmTokenOut(Schema):
    id: str
    user_id: str
    token: str
    device_id: str
    platform: Literal["ios", "android", "web"]
    last_seen_at: datetime


class RemoveFcmTokenOut(Schema):
    removed: bool


@router.post("", status_code=201)
async def register(body: RegisterFcmTokenIn, user: Auth, db: Db) -> Envelope[FcmTokenOut]:
    """Idempotent upsert keyed by device id and by the unique token."""
    by_token = await db.scalar(select(FcmToken).where(FcmToken.token == body.token))
    by_device = await db.scalar(select(FcmToken).where(FcmToken.user_id == user.sub, FcmToken.device_id == body.device_id))
    record = by_token or by_device
    if by_token and by_device and by_token.id != by_device.id:
        await db.delete(by_device)
        await db.flush()  # free the (user_id, device_id) slot before the token row takes it

    if record is None:
        record = FcmToken(token=body.token)
        db.add(record)
    record.user_id = user.sub
    record.token = body.token
    record.device_id = body.device_id
    record.platform = body.platform.upper()
    record.last_session_id = user.sid
    record.last_seen_at = utcnow()
    await db.commit()
    out = FcmTokenOut(
        id=record.id, user_id=record.user_id, token=record.token, device_id=record.device_id,
        platform=body.platform, last_seen_at=record.last_seen_at,
    )  # fmt: skip
    return Envelope(status_code=201, message=msg.fcm.token_synced, data=out)


@router.delete("")
async def remove(body: RemoveFcmTokenIn, user: Auth, db: Db) -> Envelope[RemoveFcmTokenOut]:
    """Best-effort unregister (e.g. on logout); only the caller's own token is deleted."""
    await db.execute(delete(FcmToken).where(FcmToken.user_id == user.sub, FcmToken.token == body.token))
    await db.commit()
    return Envelope(message=msg.fcm.token_removed, data=RemoveFcmTokenOut(removed=True))
