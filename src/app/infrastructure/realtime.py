"""Socket.IO, shared across instances through Redis. Clients connect with `auth: {token: <access token>}`."""

import socketio

from app.configs.settings import get_settings

sio = socketio.AsyncServer(
    async_mode="asgi",
    client_manager=socketio.AsyncRedisManager(get_settings().redis_url, channel=f"{get_settings().redis_key_prefix}socketio"),
    cors_allowed_origins=[get_settings().frontend_url],
)


def user_room(user_id: str) -> str:
    return f"user:{user_id}"


async def emit_to_user(user_id: str, event: str, data: dict) -> None:
    await sio.emit(event, data, room=user_room(user_id))


@sio.event
async def connect(sid: str, environ: dict, auth: dict | None) -> None:
    from app.core.auth.services.tokens import decode_access_token

    payload = decode_access_token((auth or {}).get("token", ""))
    if payload is None:
        raise socketio.exceptions.ConnectionRefusedError("unauthorized")
    await sio.enter_room(sid, user_room(payload["sub"]))
