import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_env: str
    pepper: str
    docs_username: str
    docs_password: str
    rate_limit_requests: int
    rate_limit_window_seconds: int
    brute_force_max_failures: int
    brute_force_window_seconds: int
    brute_force_lock_seconds: int


def load_settings() -> Settings:
    return Settings(
        app_env=os.getenv("SAFEKEYS_ENV", "development"),
        pepper=os.getenv("SAFEKEYS_PEPPER", ""),
        docs_username=os.getenv("SAFEKEYS_DOCS_USERNAME", "admin"),
        docs_password=os.getenv("SAFEKEYS_DOCS_PASSWORD", "change-me"),
        rate_limit_requests=_env_int("SAFEKEYS_RATE_LIMIT_REQUESTS", 60),
        rate_limit_window_seconds=_env_int("SAFEKEYS_RATE_LIMIT_WINDOW_SECONDS", 60),
        brute_force_max_failures=_env_int("SAFEKEYS_BRUTE_FORCE_MAX_FAILURES", 5),
        brute_force_window_seconds=_env_int("SAFEKEYS_BRUTE_FORCE_WINDOW_SECONDS", 300),
        brute_force_lock_seconds=_env_int("SAFEKEYS_BRUTE_FORCE_LOCK_SECONDS", 600),
    )
