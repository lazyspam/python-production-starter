from datetime import datetime

from sqlalchemy import null, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.models import Activity
from app.core.auth.models import User


async def add_activity(db: AsyncSession, data: dict) -> Activity:
    activity = Activity(**data)
    db.add(activity)
    return activity


async def scrub_deleted_users(db: AsyncSession, deleted_before: datetime) -> int:
    """Keeps the audit trail (action, outcome, time) but drops personal data of users deleted before the cutoff."""
    deleted = select(User.id).where(User.is_deleted.is_(True), User.deleted_at <= deleted_before)
    result = await db.execute(
        update(Activity)
        .where(
            Activity.user_id.in_(deleted),
            or_(Activity.metadata_.is_not(None), Activity.ip_address.is_not(None), Activity.user_agent.is_not(None)),
        )
        .values(metadata_=null(), ip_address=None, user_agent=None)
    )
    return getattr(result, "rowcount", 0)
