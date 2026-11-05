"""Imports every model so Alembic and SQLAlchemy see the full schema. Add new modules' models here."""

from app.core.audit.models import Activity
from app.core.auth.models import Credential, Profile, Session, TwoFactorBackupCode, TwoFactorMethod, User, UserIdentifier
from app.core.fcm_token.models import FcmToken
from app.core.files.models import FileObject

__all__ = [
    "Activity", "Credential", "FcmToken", "FileObject", "Profile", "Session",
    "TwoFactorBackupCode", "TwoFactorMethod", "User", "UserIdentifier",
]  # fmt: skip
