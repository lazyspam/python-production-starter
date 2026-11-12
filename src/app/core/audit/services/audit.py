from datetime import timedelta

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.configs import policy
from app.core.audit.models import AuditOutcome
from app.core.audit.repositories import activity as activity_repo
from app.database.session import SessionLocal, utcnow
from app.infrastructure.context import request_id, request_info
from app.infrastructure.queue import AUDIT_QUEUE, enqueue

log = structlog.get_logger()


async def record(
    action: str,
    *,
    module: str = "auth",
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Queues an audit row. Never raises: a broken audit pipeline must not break the action being audited."""
    info = request_info()
    data = {
        "module": module, "action": action, "outcome": outcome, "user_id": user_id,
        "resource_type": resource_type, "resource_id": resource_id, "metadata_": metadata,
        "ip_address": info.ip, "user_agent": info.user_agent, "request_id": request_id(),
    }  # fmt: skip
    try:
        await enqueue(AUDIT_QUEUE, "record", data)
    except Exception:
        log.exception("audit_enqueue_failed", action=action)


async def write(data: dict) -> None:
    async with SessionLocal() as db:
        await activity_repo.add_activity(db, data)
        await db.commit()


async def scrub_deleted_users(db: AsyncSession) -> int:
    """Strips personal data from audit rows of accounts deleted longer ago than the identifier grace period."""
    cutoff = utcnow() - timedelta(seconds=policy.IDENTIFIER_RECLAIM_GRACE)
    count = await activity_repo.scrub_deleted_users(db, cutoff)
    await db.commit()
    return count
