from bullmq import Queue

from app.configs.settings import get_settings

MAIL_QUEUE = "mail"
SMS_QUEUE = "sms"
AUDIT_QUEUE = "audit"
MAINTENANCE_QUEUE = "maintenance"

DEFAULT_JOB_OPTIONS = {
    "attempts": 5,
    "backoff": {"type": "exponential", "delay": 2000},
    "removeOnComplete": 1000,
    "removeOnFail": 5000,
}

_queues: dict[str, Queue] = {}


def connection_options() -> dict:
    settings = get_settings()
    return {"connection": settings.redis_url, "prefix": f"{settings.redis_key_prefix}bull"}


def get_queue(name: str) -> Queue:
    return _queues.setdefault(name, Queue(name, connection_options()))


async def enqueue(queue: str, job: str, data: dict) -> None:
    await get_queue(queue).add(job, data, DEFAULT_JOB_OPTIONS)


async def close_queues() -> None:
    for queue in _queues.values():
        await queue.close()
    _queues.clear()
