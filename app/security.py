from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import Settings


def _with_pepper(password: str, pepper: str) -> str:
    return f"{password}{pepper}"


def build_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        salt_len=16,
    )


def hash_password(password: str, settings: Settings, hasher: PasswordHasher) -> str:
    return hasher.hash(_with_pepper(password, settings.pepper))


def verify_password(
    password: str,
    hashed_password: str,
    settings: Settings,
    hasher: PasswordHasher,
) -> bool:
    try:
        return hasher.verify(hashed_password, _with_pepper(password, settings.pepper))
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False
