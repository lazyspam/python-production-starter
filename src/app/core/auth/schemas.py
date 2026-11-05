from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, EmailStr, Field, StringConstraints, field_validator, model_validator
from pydantic_extra_types.phone_numbers import PhoneNumber

from app.common.mask import mask_email, mask_phone
from app.common.schemas import Envelope, Schema
from app.core.auth.models import Role, TwoFactorType
from app.locals import msg


class Phone(PhoneNumber):
    phone_format = "E164"


Password = Annotated[str, StringConstraints(min_length=8, max_length=128)]
Code = Annotated[str, StringConstraints(pattern=r"^\d{4,10}$")]
LongToken = Annotated[str, StringConstraints(min_length=20)]
OptionalName = Annotated[str | None, StringConstraints(max_length=120), BeforeValidator(lambda v: v or None)]
Channel = Literal["email", "sms"]


# Requests


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


class TokenIn(Schema):
    token: LongToken


class CodeIn(Schema):
    code: Code


class EmailIn(Schema):
    email: EmailStr


class PhoneIn(Schema):
    phone: Phone


class EmailCodeIn(EmailIn, CodeIn):
    pass


class PhoneCodeIn(PhoneIn, CodeIn):
    pass


class ForgotIn(Schema):
    identifier: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=320)]


class SendResetIn(Schema):
    reset_id: Annotated[str, StringConstraints(min_length=10)]
    channel_id: Annotated[str, StringConstraints(min_length=10)]


class ResetIn(Schema):
    token: LongToken
    password: Password


class ResetCodeIn(Schema):
    reset_id: Annotated[str, StringConstraints(min_length=10)]
    code: Code
    password: Password


class ChangePasswordIn(Schema):
    current_password: Password
    new_password: Password


class PasswordIn(Schema):
    password: Password


class SudoChannelIn(Schema):
    channel: Channel


class SudoCodeIn(SudoChannelIn, CodeIn):
    pass


class SudoTypeIn(Schema):
    type: TwoFactorType


class SudoTwoFactorIn(SudoTypeIn):
    code: Annotated[str, StringConstraints(min_length=4, max_length=128)]


class ChallengeSendIn(Schema):
    challenge_id: Annotated[str, StringConstraints(min_length=10)]
    type: TwoFactorType


class ChallengeVerifyIn(ChallengeSendIn):
    code: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{4,32}$")]


# Responses


class TokenOut(Schema):
    token: str
    expires_at: datetime


class TokensOut(Schema):
    access: TokenOut
    refresh: TokenOut


class AuthUserOut(Schema):
    id: str
    email: str | None
    name: str | None
    avatar: str | None
    role: Role
    phone: str | None
    is_account_verified: bool


class AuthEnvelope(Envelope[AuthUserOut]):
    """Login-style responses: the user, plus tokens for bearer clients or a 2FA challenge."""

    tokens: TokensOut | None = None
    challenge_id: str | None = None
    methods: list[TwoFactorType] | None = None


class SessionOut(Schema):
    id: str
    device_id: str | None
    device_label: str | None
    created_at: datetime
    expires_at: datetime
    current: bool


class SudoStatusOut(Schema):
    active: bool
    expires_at: int | None
    method: str | None


class SudoOptionOut(Schema):
    kind: Literal["password", "otp", "2fa"]
    channel: Channel | None = None
    type: TwoFactorType | None = None
    hint: str | None = None
    requires_send: bool | None = None


class SudoOptionsOut(Schema):
    methods: list[SudoOptionOut]


class IdentifierOut(Schema):
    id: str
    type: str
    value: str
    is_primary: bool
    is_verified: bool
    verified_at: datetime | None
    created_at: datetime


class EmailChangedOut(Schema):
    user_id: str
    email: str


class ChannelOut(Schema):
    id: str
    type: str
    hint: str


class ForgotOut(Schema):
    reset_id: str
    channels: list[ChannelOut]


class VerifiedOut(Schema):
    is_account_verified: bool


class TwoFactorMethodOut(Schema):
    id: str
    type: TwoFactorType
    is_enabled: bool
    is_primary: bool
    destination: str | None
    last_used_at: datetime | None
    verified_at: datetime | None
    created_at: datetime

    @model_validator(mode="after")
    def _mask_destination(self) -> Self:
        if self.destination:
            is_email = self.type == TwoFactorType.EMAIL_OTP
            self.destination = mask_email(self.destination) if is_email else mask_phone(self.destination)
        return self


class TotpEnrollmentOut(Schema):
    method_id: str
    secret: str
    otpauth_url: str
    qr_data_url: str


class BackupCodesOut(Schema):
    backup_codes: list[str] | None = Field(default=None)


class BackupCountOut(Schema):
    remaining: int

    @field_validator("remaining")
    @classmethod
    def _non_negative(cls, value: int) -> int:
        return max(0, value)
