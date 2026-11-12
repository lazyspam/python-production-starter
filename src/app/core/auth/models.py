from datetime import datetime
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, IdMixin, TimestampMixin


class Role(StrEnum):
    ADMIN = "ADMIN"
    USER = "USER"


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    BANNED = "BANNED"
    RESTRICTED = "RESTRICTED"
    SUSPENDED = "SUSPENDED"


class IdentifierType(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"


class AuthProvider(StrEnum):
    EMAIL = "EMAIL"
    GOOGLE = "GOOGLE"
    APPLE = "APPLE"


class TwoFactorType(StrEnum):
    TOTP = "TOTP"
    EMAIL_OTP = "EMAIL_OTP"
    SMS_OTP = "SMS_OTP"


def _user_fk() -> Mapped[str]:
    return mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)


class User(IdMixin, TimestampMixin, Base):
    __tablename__ = "users"

    role: Mapped[Role] = mapped_column(Enum(Role, name="role"), default=Role.USER)
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE)
    reason: Mapped[str | None] = mapped_column(String(500))
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Profile(IdMixin, TimestampMixin, Base):
    __tablename__ = "profiles"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    name: Mapped[str | None] = mapped_column(String(120))
    avatar_url: Mapped[str | None] = mapped_column(String(2048))
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON)


class Credential(IdMixin, TimestampMixin, Base):
    """One row per provider per user. EMAIL holds the password hash; GOOGLE and APPLE hold the provider's sub."""

    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("provider", "provider_id"), UniqueConstraint("user_id", "provider"))

    user_id: Mapped[str] = _user_fk()
    provider: Mapped[str] = mapped_column(String(16), default=AuthProvider.EMAIL)
    provider_id: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserIdentifier(IdMixin, TimestampMixin, Base):
    """Emails and phones: the source of truth for login, verification and recovery."""

    __tablename__ = "user_identifiers"
    __table_args__ = (UniqueConstraint("type", "value"), Index("ix_identifier_primary", "user_id", "type", "is_primary"))

    user_id: Mapped[str] = _user_fk()
    type: Mapped[IdentifierType] = mapped_column(Enum(IdentifierType, name="identifier_type"))
    value: Mapped[str] = mapped_column(String(320))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Session(IdMixin, Base):
    """Refresh-token audit trail. Access tokens are stateless; refresh tokens are stored only as SHA-256."""

    __tablename__ = "sessions"

    user_id: Mapped[str] = _user_fk()
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    device_id: Mapped[str | None] = mapped_column(String(255))
    device_label: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TwoFactorMethod(IdMixin, TimestampMixin, Base):
    __tablename__ = "two_factor_methods"
    __table_args__ = (UniqueConstraint("user_id", "type"),)

    user_id: Mapped[str] = _user_fk()
    type: Mapped[str] = mapped_column(String(16))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    secret: Mapped[str | None] = mapped_column(String(512))
    destination: Mapped[str | None] = mapped_column(String(320))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_totp_step: Mapped[int | None] = mapped_column(Integer)
    """Time step of the last accepted TOTP code; a code from the same or an earlier step is a replay."""
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TwoFactorBackupCode(IdMixin, Base):
    __tablename__ = "two_factor_backup_codes"

    user_id: Mapped[str] = _user_fk()
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
