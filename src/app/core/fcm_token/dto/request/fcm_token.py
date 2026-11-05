from typing import Annotated, Literal

from pydantic import StringConstraints

from app.common.schemas import Schema

Token = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9_:-]+$", max_length=1024)]


class RegisterFcmTokenIn(Schema):
    token: Token
    platform: Literal["ios", "android", "web"]
    device_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


class RemoveFcmTokenIn(Schema):
    token: Token
