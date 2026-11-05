from typing import Self

from pydantic import EmailStr, model_validator

from app.common.schemas import Schema
from app.core.auth.dto.request.common import LongToken, OptionalName, Password, Phone
from app.locals import msg


class RegisterIn(Schema):
    email: EmailStr | None = None
    phone: Phone | None = None
    password: Password
    name: OptionalName = None

    @model_validator(mode="after")
    def _email_or_phone(self) -> Self:
        if not self.email and not self.phone:
            raise ValueError(msg.auth.email_or_phone_required)
        return self


class LoginIn(Schema):
    email: EmailStr | None = None
    phone: Phone | None = None
    password: Password

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if bool(self.email) == bool(self.phone):
            raise ValueError(msg.auth.email_or_phone_exactly_one)
        return self


class IdTokenIn(Schema):
    id_token: LongToken


class RefreshIn(Schema):
    refresh_token: LongToken | None = None
