from datetime import datetime
from typing import Self

from pydantic import Field, field_validator, model_validator

from app.common.mask import mask_email, mask_phone
from app.common.schemas import Schema
from app.core.auth.models import TwoFactorType


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
