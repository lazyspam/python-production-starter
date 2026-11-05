from fastapi import APIRouter

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.auth import password
from app.core.auth.deps import Auth, SudoConsume
from app.core.auth.schemas import ChangePasswordIn, ForgotIn, ForgotOut, PasswordIn, ResetCodeIn, ResetIn, SendResetIn
from app.database.session import Db
from app.locals import msg

router = APIRouter(prefix="/password")


@router.post("/forgot", dependencies=[limit(5)])
async def forgot(body: ForgotIn, db: Db) -> Envelope[ForgotOut]:
    data = ForgotOut.model_validate(await password.forgot(db, body.identifier))
    return Envelope(message=msg.auth.password_reset_channels, data=data)


@router.post("/forgot/send", dependencies=[limit(5)])
async def send(body: SendResetIn, db: Db) -> Envelope[None]:
    await password.send(db, body.reset_id, body.channel_id)
    return Envelope(message=msg.auth.password_reset_code_sent)


@router.post("/reset", dependencies=[limit(10)])
async def reset(body: ResetIn, db: Db) -> Envelope[None]:
    await password.reset_with_token(db, body.token, body.password)
    return Envelope(message=msg.auth.password_reset_successful)


@router.post("/reset/otp", dependencies=[limit(10)])
async def reset_otp(body: ResetCodeIn, db: Db) -> Envelope[None]:
    await password.reset_with_code(db, body.reset_id, body.code, body.password)
    return Envelope(message=msg.auth.password_reset_successful)


@router.patch("/change")
async def change(body: ChangePasswordIn, user: Auth, db: Db) -> Envelope[None]:
    await password.change(db, user.sub, body.current_password, body.new_password)
    return Envelope(message=msg.auth.password_changed)


@router.post("/set")
async def set_password(body: PasswordIn, user: SudoConsume, db: Db) -> Envelope[None]:
    await password.set_first(db, user.sub, body.password)
    return Envelope(message=msg.auth.password_set)
