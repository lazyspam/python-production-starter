"""Redis cache through cashews. Business caching: `@cache(ttl="5m", key="thing:{id}")`, see README."""

from cashews import cache

from app.configs.settings import get_settings


def setup_cache() -> None:
    # suppress=False: a Redis outage must raise, or login lockouts and OTP checks would silently stop working.
    cache.setup(get_settings().redis_url, suppress=False, pickle_type="json", socket_connect_timeout=3)


def key(name: str) -> str:
    return f"{get_settings().redis_key_prefix}{name}"


async def take(name: str) -> dict | None:
    """Read and remove. `delete` is atomic, so only one concurrent caller gets the value."""
    value = await cache.get(name)
    return value if value is not None and await cache.delete(name) else None
