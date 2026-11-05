from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, IdMixin


class AuditOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class Activity(IdMixin, Base):
    __tablename__ = "activities"
    __table_args__ = (
        Index("ix_activities_module_action", "module", "action", "created_at"),
        Index("ix_activities_user", "user_id", "created_at"),
        Index("ix_activities_resource", "resource_type", "resource_id", "created_at"),
        Index("ix_activities_created", "created_at"),
    )

    module: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    outcome: Mapped[AuditOutcome] = mapped_column(Enum(AuditOutcome, name="audit_outcome"))
    user_id: Mapped[str | None] = mapped_column(String(36))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
