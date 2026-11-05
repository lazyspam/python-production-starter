from fastapi import APIRouter, Response

from app.common.rate_limit import limit
from app.common.schemas import Envelope
from app.core.auth import identifiers
from app.core.auth import repository as repo
from app.core.auth.deps import Auth, AuthAny, Sudo, SudoConsume, SudoConsumeAny
from app.core.auth.routers.helpers import clear_auth_cookies
from app.core.auth.schemas import CodeIn, EmailChangedOut, EmailIn, IdentifierOut, PhoneIn, TokenIn
from app.database.session import Db
from app.locals import msg

router = APIRouter()


@router.get("/identifiers")
async def list_identifiers(user: AuthAny, db: Db) -> Envelope[list[IdentifierOut]]:
    rows = await repo.list_identifiers(db, user.sub)
    return Envelope(data=[IdentifierOut.model_validate(row) for row in rows])


@router.post("/identifiers/email")
async def add_email(body: EmailIn, user: Sudo, db: Db) -> Envelope[None]:
    await identifiers.request_add_email(db, user.sub, body.email)
    return Envelope(message=msg.auth.email_change_requested)


@router.post("/identifiers/email/confirm", dependencies=[limit(10)])
async def confirm_add_email(body: TokenIn, db: Db) -> Envelope[None]:
    await identifiers.confirm_add_email_token(db, body.token)
    return Envelope(message=msg.auth.email_added)


@router.post("/identifiers/email/confirm/otp")
async def confirm_add_email_otp(body: CodeIn, user: Auth, db: Db) -> Envelope[None]:
    await identifiers.confirm_add_email_code(db, user.sub, body.code)
    return Envelope(message=msg.auth.email_added)


@router.post("/identifiers/phone")
async def add_phone(body: PhoneIn, user: Sudo, db: Db) -> Envelope[None]:
    await identifiers.request_add_phone(db, user.sub, body.phone)
    return Envelope(message=msg.auth.phone_change_requested)


@router.post("/identifiers/phone/confirm")
async def confirm_add_phone(body: CodeIn, user: Auth, db: Db) -> Envelope[None]:
    await identifiers.confirm_add_phone(db, user.sub, body.code)
    return Envelope(message=msg.auth.phone_added)


@router.post("/identifiers/{identifier_id}/primary")
async def set_primary(identifier_id: str, user: SudoConsume, db: Db) -> Envelope[None]:
    await identifiers.set_primary(db, user.sub, identifier_id)
    return Envelope(message=msg.auth.primary_identifier_updated)


@router.delete("/identifiers/{identifier_id}")
async def remove(identifier_id: str, user: SudoConsume, db: Db) -> Envelope[None]:
    await identifiers.remove(db, user.sub, identifier_id)
    return Envelope(message=msg.auth.identifier_removed)


@router.post("/email/change/request")
async def request_email_change(body: EmailIn, user: Sudo, db: Db) -> Envelope[None]:
    await identifiers.request_email_change(db, user.sub, body.email)
    return Envelope(message=msg.auth.email_change_requested)


@router.post("/email/change/confirm", dependencies=[limit(10)])
async def confirm_email_change(body: TokenIn, db: Db) -> Envelope[EmailChangedOut]:
    result = await identifiers.confirm_email_change_token(db, body.token)
    return Envelope(message=msg.auth.email_changed, data=EmailChangedOut.model_validate(result))


@router.post("/email/change/confirm/otp")
async def confirm_email_change_otp(body: CodeIn, user: Auth, db: Db) -> Envelope[EmailChangedOut]:
    result = await identifiers.confirm_email_change_code(db, user.sub, body.code)
    return Envelope(message=msg.auth.email_changed, data=EmailChangedOut.model_validate(result))


@router.post("/phone/change/request")
async def request_phone_change(body: PhoneIn, user: Sudo, db: Db) -> Envelope[None]:
    await identifiers.request_phone_change(db, user.sub, body.phone)
    return Envelope(message=msg.auth.phone_change_requested)


@router.post("/phone/change/confirm")
async def confirm_phone_change(body: CodeIn, user: Auth, db: Db) -> Envelope[None]:
    await identifiers.confirm_phone_change(db, user.sub, body.code)
    return Envelope(message=msg.auth.phone_changed)


@router.post("/account/deactivate")
async def deactivate(user: SudoConsumeAny, response: Response, db: Db) -> Envelope[None]:
    await identifiers.deactivate(db, user.sub)
    clear_auth_cookies(response)
    return Envelope(message=msg.auth.account_deactivated)
