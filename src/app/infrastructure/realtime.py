"""Socket.IO, shared across instances through Redis. Clients connect with `auth: {token: <access token>}`.

Each socket's id is kept in a Redis set per auth session. Revoking a session pops that set and calls `sio.disconnect`
for each socket: with the Redis manager that reaches whichever instance holds the socket. Rooms can't be used for this,
because a room's members are only known to the instance they are connected to.
"""

import socketio
from socketio.exceptions import ConnectionRefusedError as Refused

from app.configs.settings import get_settings
from app.database.session import SessionLocal
from app.infrastructure.cache import cache, key
from app.locals import msg

sio = socketio.AsyncServer(
    async_mode="asgi",
    client_manager=socketio.AsyncRedisManager(get_settings().redis_url, channel=f"{get_settings().redis_key_prefix}socketio"),
    cors_allowed_origins=[get_settings().frontend_url],
)


def user_room(user_id: str) -> str:
    return f"user:{user_id}"


def _sockets_key(session_id: str) -> str:
    return key(f"sockets:{session_id}")


async def emit_to_user(user_id: str, event: str, data: dict) -> None:
    await sio.emit(event, data, room=user_room(user_id))


async def disconnect_session(session_id: str) -> None:
    for socket_id in await cache.set_pop(_sockets_key(session_id), count=1000):
        await sio.disconnect(socket_id)


@sio.event
async def connect(sid: str, environ: dict, auth: dict | None) -> None:
    from app.core.auth.services.sessions import authorize_socket

    async with SessionLocal() as db:
        identity = await authorize_socket(db, (auth or {}).get("token", ""))
    if identity is None:
        raise Refused(msg.auth.unauthorized)
    user_id, session_id = identity
    await sio.save_session(sid, {"session_id": session_id})
    await cache.set_add(_sockets_key(session_id), sid, expire=get_settings().jwt_refresh_ttl_seconds)
    await sio.enter_room(sid, user_room(user_id))


@sio.event
async def disconnect(sid: str, *_: object) -> None:
    session = await sio.get_session(sid)
    if session_id := session.get("session_id"):
        await cache.set_remove(_sockets_key(session_id), sid)
