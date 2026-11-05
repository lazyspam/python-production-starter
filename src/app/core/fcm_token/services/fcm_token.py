from sqlalchemy.ext.asyncio import AsyncSession

from app.core.fcm_token.models import FcmToken
from app.core.fcm_token.repositories import fcm_token as fcm_token_repo
from app.database.session import utcnow


async def register(db: AsyncSession, user_id: str, session_id: str | None, token: str, device_id: str, platform: str) -> FcmToken:
    """Idempotent upsert keyed by device id and by the unique token."""
    by_token = await fcm_token_repo.find_by_token(db, token)
    by_device = await fcm_token_repo.find_by_device(db, user_id, device_id)
    record = by_token or by_device
    if by_token and by_device and by_token.id != by_device.id:
        await fcm_token_repo.delete_token(db, by_device)
        await db.flush()  # free the (user_id, device_id) slot before the token row takes it

    if record is None:
        record = await fcm_token_repo.add_token(db, token)
    record.user_id = user_id
    record.token = token
    record.device_id = device_id
    record.platform = platform.upper()
    record.last_session_id = session_id
    record.last_seen_at = utcnow()
    await db.commit()
    return record


async def remove(db: AsyncSession, user_id: str, token: str) -> None:
    """Best-effort unregister (e.g. on logout); only the caller's own token is deleted."""
    await fcm_token_repo.delete_user_token(db, user_id, token)
    await db.commit()
