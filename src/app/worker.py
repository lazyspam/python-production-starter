"""Background jobs: `python -m app.worker`. Register new queues in PROCESSORS and maintenance jobs in MAINTENANCE.

`python -m app.worker --check` is the container healthcheck: it exits 0 while this container's worker heartbeat is fresh.
"""

import asyncio
import signal
import socket
import sys
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from bullmq import Job, Worker
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.services.audit import scrub_deleted_users
from app.core.audit.services.audit import write as write_audit
from app.core.auth.services.identifiers import reclaim_identifiers
from app.core.files.services.files import cleanup_pending
from app.database import models  # noqa: F401
from app.database.session import SessionLocal, engine
from app.infrastructure.cache import cache, key, setup_cache
from app.infrastructure.messaging import deliver_mail, deliver_sms
from app.infrastructure.observability import setup_logging
from app.infrastructure.queue import (
    AUDIT_QUEUE,
    MAIL_QUEUE,
    MAINTENANCE_QUEUE,
    SMS_QUEUE,
    close_queues,
    get_queue,
    worker_options,
)

log = structlog.get_logger()
DAY_MS = 24 * 3600 * 1000
HEARTBEAT_EVERY = 30
HEARTBEAT_TTL = 90


async def process_mail(job: Job, _token: str) -> None:
    await deliver_mail(**job.data)


async def process_sms(job: Job, _token: str) -> None:
    await deliver_sms(**job.data)


async def process_audit(job: Job, _token: str) -> None:
    await write_audit(job.data)


MAINTENANCE: dict[str, Callable[[AsyncSession], Awaitable[int]]] = {
    "reclaim": reclaim_identifiers,
    "scrub-audit": scrub_deleted_users,
    "cleanup-uploads": cleanup_pending,
}
"""Job name -> daily maintenance task. Each gets its own scheduler in `main`."""


async def process_maintenance(job: Job, _token: str) -> int:
    task = MAINTENANCE.get(job.name)
    if task is None:
        log.warning("unknown_maintenance_job", name=job.name)
        return 0
    async with SessionLocal() as db:
        return await task(db)


# bullmq annotates processors as returning a Future; any awaitable works.
PROCESSORS: dict[str, Callable[[Job, str], Any]] = {
    MAIL_QUEUE: process_mail,
    SMS_QUEUE: process_sms,
    AUDIT_QUEUE: process_audit,
    MAINTENANCE_QUEUE: process_maintenance,
}


def _heartbeat_key() -> str:
    return key(f"worker:heartbeat:{socket.gethostname()}")


async def _heartbeat(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await cache.set(_heartbeat_key(), 1, expire=HEARTBEAT_TTL)
        except Exception:
            log.warning("worker_heartbeat_failed", exc_info=True)
        try:
            await asyncio.wait_for(stop.wait(), HEARTBEAT_EVERY)
        except TimeoutError:
            pass


async def check() -> int:
    setup_cache()
    try:
        return 0 if await cache.get(_heartbeat_key()) else 1
    finally:
        await cache.close()


async def main() -> None:
    setup_logging()
    setup_cache()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    workers = [Worker(name, processor, worker_options()) for name, processor in PROCESSORS.items()]
    maintenance = get_queue(MAINTENANCE_QUEUE)
    for name in MAINTENANCE:
        # The first id predates the other jobs; kept so existing deployments don't get a duplicate scheduler.
        scheduler_id = "reclaim-identifiers" if name == "reclaim" else name
        await maintenance.upsertJobScheduler(scheduler_id, {"every": DAY_MS}, name)
    heartbeat = asyncio.create_task(_heartbeat(stop))
    log.info("worker_started", queues=list(PROCESSORS), maintenance=list(MAINTENANCE))

    await stop.wait()
    await heartbeat
    await asyncio.gather(*(worker.close() for worker in workers))
    await close_queues()
    await cache.close()
    await engine.dispose()


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        sys.exit(asyncio.run(check()))
    asyncio.run(main())
