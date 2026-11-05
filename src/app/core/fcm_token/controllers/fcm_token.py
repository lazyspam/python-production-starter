from fastapi import APIRouter

from app.common.schemas import Envelope
from app.core.auth.deps import Auth
from app.core.fcm_token.dto.request.fcm_token import RegisterFcmTokenIn, RemoveFcmTokenIn
from app.core.fcm_token.dto.response.fcm_token import FcmTokenOut, RemoveFcmTokenOut
from app.core.fcm_token.services import fcm_token as fcm_token_service
from app.database.session import Db
from app.locals import msg

router = APIRouter(prefix="/fcm-tokens", tags=["fcm-tokens"])


@router.post("", status_code=201)
async def register(body: RegisterFcmTokenIn, user: Auth, db: Db) -> Envelope[FcmTokenOut]:
    record = await fcm_token_service.register(db, user.sub, user.sid, body.token, body.device_id, body.platform)
    out = FcmTokenOut(
        id=record.id, user_id=record.user_id, token=record.token, device_id=record.device_id,
        platform=body.platform, last_seen_at=record.last_seen_at,
    )  # fmt: skip
    return Envelope(status_code=201, message=msg.fcm.token_synced, data=out)


@router.delete("")
async def remove(body: RemoveFcmTokenIn, user: Auth, db: Db) -> Envelope[RemoveFcmTokenOut]:
    await fcm_token_service.remove(db, user.sub, body.token)
    return Envelope(message=msg.fcm.token_removed, data=RemoveFcmTokenOut(removed=True))
