import hashlib
import secrets

from cryptography.fernet import Fernet
from fastapi.concurrency import run_in_threadpool
from pwdlib import PasswordHash

from app.configs.policy import OTP_LENGTH
from app.configs.settings import get_settings

_hasher = PasswordHash.recommended()
_DUMMY_HASH = _hasher.hash("timing-equalizer")


async def hash_secret(value: str) -> str:
    return await run_in_threadpool(_hasher.hash, value)


async def verify_secret(value: str, hashed: str | None) -> bool:
    """Checks against a dummy hash when there's nothing to compare, so unknown accounts take the same time."""
    matches = await run_in_threadpool(_hasher.verify, value, hashed or _DUMMY_HASH)
    return matches and hashed is not None


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def random_token(n_bytes: int = 32) -> str:
    return secrets.token_hex(n_bytes)


def random_code() -> str:
    return f"{secrets.randbelow(10**OTP_LENGTH):0{OTP_LENGTH}d}"


def encrypt(value: str) -> str:
    return Fernet(get_settings().auth_encryption_key).encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return Fernet(get_settings().auth_encryption_key).decrypt(value.encode()).decode()
