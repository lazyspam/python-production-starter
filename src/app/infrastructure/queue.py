from bullmq import Queue
from bullmq.types import JobOptions, QueueBaseOptions, WorkerOptions

from app.configs.settings import get_settings

MAIL_QUEUE = "mail"
SMS_QUEUE = "sms"
AUDIT_QUEUE = "audit"
MAINTENANCE_QUEUE = "maintenance"

DEFAULT_JOB_OPTIONS: JobOptions = {
    "attempts": 5,
    "backoff": {"type": "exponential", "delay": 2000},
    "removeOnComplete": 1000,
    "removeOnFail": 5000,
}

_queues: dict[str, Queue] = {}


def _prefix() -> str:
    return f"{get_settings().redis_key_prefix}bull"


def worker_options() -> WorkerOptions:
    return {"connection": get_settings().redis_url, "prefix": _prefix()}


def get_queue(name: str) -> Queue:
    if name not in _queues:
        options: QueueBaseOptions = {"connection": get_settings().redis_url, "prefix": _prefix()}
        _queues[name] = Queue(name, options)
    return _queues[name]


async def enqueue(queue: str, job: str, data: dict) -> None:
    await get_queue(queue).add(job, data, DEFAULT_JOB_OPTIONS)


async def close_queues() -> None:
    for queue in _queues.values():
        await queue.close()
    _queues.clear()
