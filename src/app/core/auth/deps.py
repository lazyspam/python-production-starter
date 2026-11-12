from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer

from app.core.auth.constants import ACCESS_TOKEN_COOKIE
from app.core.auth.models import UserStatus
from app.core.auth.repositories import identifier as identifier_repo
from app.core.auth.repositories import user as user_repo
from app.core.auth.services import sudo
from app.core.auth.services.tokens import decode_access_token, is_session_revoked, unauthorized
from app.database.session import Db
from app.locals import msg

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    sub: str
    sid: str | None
    is_account_verified: bool


async def _current_user(request: Request, db: Db, credentials=Depends(_bearer)) -> CurrentUser:
    token = credentials.credentials if credentials else request.cookies.get(ACCESS_TOKEN_COOKIE)
    payload = decode_access_token(token) if token else None
    if not payload or (payload.get("sid") and await is_session_revoked(payload["sid"])):
        raise unauthorized(msg.auth.unauthorized)
    user = await user_repo.find_user(db, payload["sub"])
    if not user or user.status != UserStatus.ACTIVE:
        raise unauthorized(msg.auth.account_no_longer_available)
    return CurrentUser(user.id, payload.get("sid"), await identifier_repo.is_account_verified(db, user.id))


async def _verified_user(user: Annotated[CurrentUser, Depends(_current_user)]) -> CurrentUser:
    if not user.is_account_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, msg.auth.account_verification_required)
    return user


AuthAny = Annotated[CurrentUser, Depends(_current_user)]
"""Signed in, verified or not."""
Auth = Annotated[CurrentUser, Depends(_verified_user)]
"""Signed in with a verified account."""


async def _sudo(user: Auth) -> CurrentUser:
    await sudo.require(user.sub, user.sid)
    return user


async def _sudo_consume(user: Auth) -> AsyncIterator[CurrentUser]:
    await sudo.require(user.sub, user.sid)
    yield user
    await sudo.consume(user.sub, user.sid)


async def _sudo_consume_any(user: AuthAny) -> AsyncIterator[CurrentUser]:
    await sudo.require(user.sub, user.sid)
    yield user
    await sudo.consume(user.sub, user.sid)


Sudo = Annotated[CurrentUser, Depends(_sudo)]
"""Needs a live sudo grant."""
SudoConsume = Annotated[CurrentUser, Depends(_sudo_consume)]
"""Needs a live sudo grant and spends it when the action succeeds."""
SudoConsumeAny = Annotated[CurrentUser, Depends(_sudo_consume_any)]
"""The same for unverified accounts; account deletion must stay possible for them."""
