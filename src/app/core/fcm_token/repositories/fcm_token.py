from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.fcm_token.models import FcmToken


async def find_by_token(db: AsyncSession, token: str) -> FcmToken | None:
    return await db.scalar(select(FcmToken).where(FcmToken.token == token))


async def find_by_device(db: AsyncSession, user_id: str, device_id: str) -> FcmToken | None:
    return await db.scalar(select(FcmToken).where(FcmToken.user_id == user_id, FcmToken.device_id == device_id))


async def add_token(db: AsyncSession, token: str) -> FcmToken:
    record = FcmToken(token=token)
    db.add(record)
    return record


async def delete_token(db: AsyncSession, record: FcmToken) -> None:
    await db.delete(record)


async def delete_user_token(db: AsyncSession, user_id: str, token: str) -> None:
    await db.execute(delete(FcmToken).where(FcmToken.user_id == user_id, FcmToken.token == token))


async def delete_for_user(db: AsyncSession, user_id: str) -> None:
    await db.execute(delete(FcmToken).where(FcmToken.user_id == user_id))
