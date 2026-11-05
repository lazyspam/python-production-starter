from dataclasses import dataclass

from app.core.auth.models import Role


@dataclass
class AuthUser:
    id: str
    role: Role
    name: str | None
    avatar: str | None
    email: str | None
    phone: str | None
    is_account_verified: bool
