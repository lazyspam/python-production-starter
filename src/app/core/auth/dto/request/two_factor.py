from typing import Annotated

from pydantic import StringConstraints

from app.common.schemas import Schema
from app.core.auth.models import TwoFactorType


class ChallengeSendIn(Schema):
    challenge_id: Annotated[str, StringConstraints(min_length=10)]
    type: TwoFactorType


class ChallengeVerifyIn(ChallengeSendIn):
    code: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{4,32}$")]
