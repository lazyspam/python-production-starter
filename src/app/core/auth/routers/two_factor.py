from fastapi import APIRouter, Request, Response

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.auth import repository as repo
from app.core.auth import two_factor
from app.core.auth.deps import Auth, Sudo, SudoConsume
from app.core.auth.models import TwoFactorType
from app.core.auth.routers.helpers import deliver_tokens, wants_bearer
from app.core.auth.schemas import (
    AuthEnvelope,
    BackupCodesOut,
    BackupCountOut,
    ChallengeSendIn,
    ChallengeVerifyIn,
    CodeIn,
    TotpEnrollmentOut,
    TwoFactorMethodOut,
)
from app.core.auth.tokens import unauthorized
from app.database.session import Db
from app.locals import msg

router = APIRouter(prefix="/2fa")


async def _first_backup_codes(db: Db, user_id: str) -> Envelope[BackupCodesOut]:
    """Backup codes are shown once, when the first method is confirmed."""
    codes = await two_factor.issue_backup_codes_if_none(db, user_id)
    return Envelope(data=BackupCodesOut(backup_codes=codes) if codes else None)


@router.get("/methods")
async def methods(user: Auth, db: Db) -> Envelope[list[TwoFactorMethodOut]]:
    rows = await two_factor.list_methods(db, user.sub)
    return Envelope(data=[TwoFactorMethodOut.model_validate(row) for row in rows])


@router.post("/enroll/totp")
async def enroll_totp(user: Sudo, db: Db) -> Envelope[TotpEnrollmentOut]:
    found = await repo.find_user(db, user.sub)
    if not found:
        raise unauthorized(msg.auth.user_not_found)
    return Envelope(data=TotpEnrollmentOut.model_validate(await two_factor.enroll_totp(db, found)))


@router.post("/enroll/totp/confirm")
async def confirm_totp(body: CodeIn, user: Auth, db: Db) -> Envelope[BackupCodesOut]:
    await two_factor.confirm_totp(db, user.sub, body.code)
    return await _first_backup_codes(db, user.sub)


@router.post("/enroll/email/request")
async def enroll_email(user: Sudo, db: Db) -> Envelope[None]:
    await two_factor.enroll_otp(db, user.sub, TwoFactorType.EMAIL_OTP)
    return Envelope(message=msg.auth.two_factor_code_sent)


@router.post("/enroll/email/confirm")
async def confirm_email(body: CodeIn, user: Auth, db: Db) -> Envelope[BackupCodesOut]:
    await two_factor.confirm_otp(db, user.sub, TwoFactorType.EMAIL_OTP, body.code)
    return await _first_backup_codes(db, user.sub)


@router.post("/enroll/sms/request")
async def enroll_sms(user: Sudo, db: Db) -> Envelope[None]:
    await two_factor.enroll_otp(db, user.sub, TwoFactorType.SMS_OTP)
    return Envelope(message=msg.auth.two_factor_code_sent)


@router.post("/enroll/sms/confirm")
async def confirm_sms(body: CodeIn, user: Auth, db: Db) -> Envelope[BackupCodesOut]:
    await two_factor.confirm_otp(db, user.sub, TwoFactorType.SMS_OTP, body.code)
    return await _first_backup_codes(db, user.sub)


@router.delete("/methods/{method_id}")
async def disable(method_id: str, user: SudoConsume, db: Db) -> Envelope[None]:
    await two_factor.disable(db, user.sub, method_id)
    return Envelope(message=msg.auth.two_factor_disabled)


@router.get("/backup-codes")
async def count_backup_codes(user: Auth, db: Db) -> Envelope[BackupCountOut]:
    return Envelope(data=BackupCountOut(remaining=await two_factor.count_backup_codes(db, user.sub)))


@router.post("/backup-codes/regenerate")
async def regenerate(user: SudoConsume, db: Db) -> Envelope[BackupCodesOut]:
    return Envelope(data=BackupCodesOut(backup_codes=await two_factor.regenerate_backup_codes(db, user.sub)))


@router.post("/challenge/send", dependencies=[limit(10)])
async def challenge_send(body: ChallengeSendIn, db: Db) -> Envelope[None]:
    await two_factor.send_challenge_code(db, body.challenge_id, body.type)
    return Envelope(message=msg.auth.two_factor_code_sent)


@router.post("/challenge/verify", dependencies=[limit(10)])
async def challenge_verify(body: ChallengeVerifyIn, request: Request, response: Response, db: Db) -> AuthEnvelope:
    issued = await two_factor.verify_challenge(db, body.challenge_id, body.type, body.code)
    return AuthEnvelope(message=msg.auth.logged_in_successfully, tokens=deliver_tokens(response, issued, wants_bearer(request)))
