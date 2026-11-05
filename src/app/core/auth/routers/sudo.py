from fastapi import APIRouter

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.auth import sudo
from app.core.auth.deps import AuthAny
from app.core.auth.schemas import (
    PasswordIn,
    SudoChannelIn,
    SudoCodeIn,
    SudoOptionsOut,
    SudoStatusOut,
    SudoTwoFactorIn,
    SudoTypeIn,
)
from app.database.session import Db
from app.locals import msg

# Unverified accounts can elevate too: without it they could never delete themselves.
router = APIRouter(prefix="/sudo")


def _elevated(grant: dict) -> Envelope[SudoStatusOut]:
    return Envelope(message=msg.auth.sudo_elevated, data=SudoStatusOut.model_validate(grant))


@router.get("")
async def get_status(user: AuthAny) -> Envelope[SudoStatusOut]:
    return Envelope(data=SudoStatusOut.model_validate(await sudo.status_of(user.sub, user.sid)))


@router.delete("")
async def clear(user: AuthAny) -> Envelope[None]:
    if user.sid:
        await sudo.clear(user.sub, user.sid)
    return Envelope(message=msg.auth.sudo_cleared)


@router.get("/options")
async def options(user: AuthAny, db: Db) -> Envelope[SudoOptionsOut]:
    return Envelope(data=SudoOptionsOut.model_validate({"methods": await sudo.list_options(db, user.sub)}))


@router.post("/password", dependencies=[limit(10)])
async def elevate_password(body: PasswordIn, user: AuthAny, db: Db) -> Envelope[SudoStatusOut]:
    return _elevated(await sudo.elevate_with_password(db, user.sub, user.sid, body.password))


@router.post("/otp/request", dependencies=[limit(10)])
async def request_otp(body: SudoChannelIn, user: AuthAny, db: Db) -> Envelope[None]:
    await sudo.request_otp(db, user.sub, body.channel)
    return Envelope(message=msg.auth.sudo_otp_sent)


@router.post("/otp/confirm", dependencies=[limit(10)])
async def confirm_otp(body: SudoCodeIn, user: AuthAny) -> Envelope[SudoStatusOut]:
    return _elevated(await sudo.elevate_with_otp(user.sub, user.sid, body.channel, body.code))


@router.post("/2fa/send", dependencies=[limit(10)])
async def send_two_factor(body: SudoTypeIn, user: AuthAny, db: Db) -> Envelope[None]:
    await sudo.request_two_factor_otp(db, user.sub, body.type)
    return Envelope(message=msg.auth.sudo_otp_sent)


@router.post("/2fa", dependencies=[limit(10)])
async def elevate_two_factor(body: SudoTwoFactorIn, user: AuthAny, db: Db) -> Envelope[SudoStatusOut]:
    return _elevated(await sudo.elevate_with_two_factor(db, user.sub, user.sid, body.type, body.code))
