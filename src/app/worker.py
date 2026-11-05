"""Background jobs: `python -m app.worker`. Register new queues in PROCESSORS."""

import asyncio
import signal

import structlog
from bullmq import Job, Worker

from app.core.audit.services.audit import write as write_audit
from app.core.auth.services.identifiers import reclaim_identifiers
from app.database import models  # noqa: F401
from app.database.session import SessionLocal, engine
from app.infrastructure.messaging import deliver_mail, deliver_sms
from app.infrastructure.observability import setup_logging
from app.infrastructure.queue import (
    AUDIT_QUEUE,
    MAIL_QUEUE,
    MAINTENANCE_QUEUE,
    SMS_QUEUE,
    close_queues,
    connection_options,
    get_queue,
)

log = structlog.get_logger()
DAY_MS = 24 * 3600 * 1000


async def process_mail(job: Job, _token: str) -> None:
    await deliver_mail(**job.data)


async def process_sms(job: Job, _token: str) -> None:
    await deliver_sms(**job.data)


async def process_audit(job: Job, _token: str) -> None:
    await write_audit(job.data)


async def process_maintenance(job: Job, _token: str) -> int:
    async with SessionLocal() as db:
        return await reclaim_identifiers(db)


PROCESSORS = {
    MAIL_QUEUE: process_mail,
    SMS_QUEUE: process_sms,
    AUDIT_QUEUE: process_audit,
    MAINTENANCE_QUEUE: process_maintenance,
}


async def main() -> None:
    setup_logging()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    workers = [Worker(name, processor, connection_options()) for name, processor in PROCESSORS.items()]
    await get_queue(MAINTENANCE_QUEUE).upsertJobScheduler("reclaim-identifiers", {"every": DAY_MS}, "reclaim")
    log.info("worker_started", queues=list(PROCESSORS))

    await stop.wait()
    await asyncio.gather(*(worker.close() for worker in workers))
    await close_queues()
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
