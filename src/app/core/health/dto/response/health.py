from typing import Literal

from app.common.schemas import Schema


class Liveness(Schema):
    status: Literal["ok"] = "ok"
    uptime_seconds: int
    timestamp: str


class Checks(Schema):
    database: Literal["up", "down"]
    redis: Literal["up", "down"]


class Readiness(Liveness):
    checks: Checks
