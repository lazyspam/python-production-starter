from datetime import datetime

from app.common.schemas import Envelope, Schema
from app.core.auth.models import Role, TwoFactorType


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
