from typing import Annotated

from pydantic import StringConstraints

from app.common.schemas import Schema
from app.core.auth.dto.request.common import Code, LongToken, Password


class ForgotIn(Schema):
    identifier: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=320)]


class SendResetIn(Schema):
    reset_id: Annotated[str, StringConstraints(min_length=10)]
    channel_id: Annotated[str, StringConstraints(min_length=10)]


class ResetIn(Schema):
    token: LongToken
    password: Password


class ResetCodeIn(Schema):
    reset_id: Annotated[str, StringConstraints(min_length=10)]
    code: Code
    password: Password


class ChangePasswordIn(Schema):
    current_password: Password
    new_password: Password
