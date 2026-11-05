from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.models import Credential


async def find_credential(db: AsyncSession, user_id: str, provider: str) -> Credential | None:
    return await db.scalar(select(Credential).where(Credential.user_id == user_id, Credential.provider == provider))


async def find_credential_by_identity(db: AsyncSession, provider: str, provider_id: str) -> Credential | None:
    return await db.scalar(select(Credential).where(Credential.provider == provider, Credential.provider_id == provider_id))


async def add_credential(
    db: AsyncSession, user_id: str, provider: str, provider_id: str, password_hash: str | None = None
) -> Credential:
    credential = Credential(user_id=user_id, provider=provider, provider_id=provider_id, password_hash=password_hash)
    db.add(credential)
    return credential


async def delete_credential(db: AsyncSession, credential: Credential) -> None:
    await db.delete(credential)


async def sync_email_credential(db: AsyncSession, user_id: str, email: str) -> None:
    credential = await find_credential(db, user_id, "EMAIL")
    if credential:
        credential.provider_id = email
