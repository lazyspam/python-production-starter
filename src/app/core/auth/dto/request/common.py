from typing import Annotated, Literal

from pydantic import BeforeValidator, EmailStr, StringConstraints
from pydantic_extra_types.phone_numbers import PhoneNumber

from app.common.schemas import Schema


class Phone(PhoneNumber):
    phone_format = "E164"


Password = Annotated[str, StringConstraints(min_length=8, max_length=128)]
Code = Annotated[str, StringConstraints(pattern=r"^\d{4,10}$")]
LongToken = Annotated[str, StringConstraints(min_length=20)]
OptionalName = Annotated[str | None, StringConstraints(max_length=120), BeforeValidator(lambda v: v or None)]
Channel = Literal["email", "sms"]


class TokenIn(Schema):
    token: LongToken


class CodeIn(Schema):
    code: Code


class EmailIn(Schema):
    email: EmailStr


class PhoneIn(Schema):
    phone: Phone


class PasswordIn(Schema):
    password: Password
