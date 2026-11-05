from fastapi import APIRouter

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.auth import verify
from app.core.auth.deps import AuthAny
from app.core.auth.schemas import CodeIn, EmailCodeIn, EmailIn, PhoneCodeIn, PhoneIn, TokenIn, VerifiedOut
from app.database.session import Db
from app.locals import msg

router = APIRouter()


def _email_done(user: verify.AuthUser) -> Envelope[VerifiedOut]:
    return Envelope(message=msg.auth.email_verified, data=VerifiedOut.model_validate(user))


def _phone_done(user: verify.AuthUser) -> Envelope[VerifiedOut]:
    return Envelope(message=msg.auth.phone_verified, data=VerifiedOut.model_validate(user))


@router.post("/email/verify", dependencies=[limit(10)])
async def email_token(body: TokenIn, db: Db) -> Envelope[VerifiedOut]:
    return _email_done(await verify.confirm_token(db, body.token))


@router.post("/email/verify/otp", dependencies=[limit(10)])
async def email_code(body: EmailCodeIn, db: Db) -> Envelope[VerifiedOut]:
    return _email_done(await verify.confirm_code(db, verify.EMAIL, body.email, body.code))


@router.post("/email/verify/confirm", dependencies=[limit(10)])
async def email_code_session(body: CodeIn, user: AuthAny, db: Db) -> Envelope[VerifiedOut]:
    return _email_done(await verify.confirm_code_for_user(db, verify.EMAIL, user.sub, body.code))


@router.post("/email/verify/resend", dependencies=[limit(5)])
async def email_resend(body: EmailIn, db: Db) -> Envelope[None]:
    await verify.resend_to(db, verify.EMAIL, body.email)
    return Envelope(message=msg.auth.email_verification_sent)


@router.post("/email/verify/resend/me", dependencies=[limit(5)])
async def email_resend_me(user: AuthAny, db: Db) -> Envelope[None]:
    await verify.resend_for_user(db, verify.EMAIL, user.sub)
    return Envelope(message=msg.auth.email_verification_sent)


@router.post("/phone/verify/otp", dependencies=[limit(10)])
async def phone_code(body: PhoneCodeIn, db: Db) -> Envelope[VerifiedOut]:
    return _phone_done(await verify.confirm_code(db, verify.PHONE, body.phone, body.code))


@router.post("/phone/verify/confirm", dependencies=[limit(10)])
async def phone_code_session(body: CodeIn, user: AuthAny, db: Db) -> Envelope[VerifiedOut]:
    return _phone_done(await verify.confirm_code_for_user(db, verify.PHONE, user.sub, body.code))


@router.post("/phone/verify/resend", dependencies=[limit(5)])
async def phone_resend(body: PhoneIn, db: Db) -> Envelope[None]:
    await verify.resend_to(db, verify.PHONE, body.phone)
    return Envelope(message=msg.auth.phone_verification_sent)


@router.post("/phone/verify/resend/me", dependencies=[limit(5)])
async def phone_resend_me(user: AuthAny, db: Db) -> Envelope[None]:
    await verify.resend_for_user(db, verify.PHONE, user.sub)
    return Envelope(message=msg.auth.phone_verification_sent)
