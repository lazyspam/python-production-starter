from typing import Any

from pydantic import BaseModel, ConfigDict, SerializerFunctionWrapHandler, model_serializer
from pydantic.alias_generators import to_camel


class Schema(BaseModel):
    """API models: snake_case in Python, camelCase on the wire."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)


class Envelope[T](Schema):
    """Every success response. Top-level fields left as None are dropped; values inside `data` keep their nulls."""

    success: bool = True
    message: str = "Success"
    status_code: int = 200
    data: T | None = None

    @model_serializer(mode="wrap")
    def _drop_empty(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        return {k: v for k, v in handler(self).items() if v is not None}
