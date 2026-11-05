from typing import Annotated

from pydantic import StringConstraints

from app.common.schemas import Schema
from app.core.auth.dto.request.common import Channel, CodeIn
from app.core.auth.models import TwoFactorType


class SudoChannelIn(Schema):
    channel: Channel


class SudoCodeIn(SudoChannelIn, CodeIn):
    pass


class SudoTypeIn(Schema):
    type: TwoFactorType


class SudoTwoFactorIn(SudoTypeIn):
    code: Annotated[str, StringConstraints(min_length=4, max_length=128)]
