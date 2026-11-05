from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.models import Activity


async def add_activity(db: AsyncSession, data: dict) -> Activity:
    activity = Activity(**data)
    db.add(activity)
    return activity
