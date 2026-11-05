from typing import Literal

from app.common.schemas import Schema
from app.core.auth.dto.request.common import Channel
from app.core.auth.models import TwoFactorType


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
