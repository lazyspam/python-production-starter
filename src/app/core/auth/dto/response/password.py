from app.common.schemas import Schema


class ChannelOut(Schema):
    id: str
    type: str
    hint: str


class ForgotOut(Schema):
    reset_id: str
    channels: list[ChannelOut]
