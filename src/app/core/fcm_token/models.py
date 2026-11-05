from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, IdMixin, TimestampMixin, utcnow


class FcmToken(IdMixin, TimestampMixin, Base):
    __tablename__ = "fcm_tokens"
    __table_args__ = (UniqueConstraint("token"), UniqueConstraint("user_id", "device_id"))

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(1024))
    device_id: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(16))
    last_session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id", ondelete="SET NULL"))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
