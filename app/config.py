import os
from typing import List, Optional

from pydantic import BaseModel


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _as_list(value: str | None) -> List[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


class AppConfig(BaseModel):
    # AI
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-1.5-flash"

    # Analysis limits
    analysis_timeout_seconds: int = 40
    max_url_length: int = 2048

    # Domain policy
    allow_domains: List[str] = []
    deny_domains: List[str] = []
    allow_private_ips: bool = False
    block_punycode: bool = True

    # Abuse protection
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60

    # Logging
    log_sample_rate: float = 1.0

    # Runtime artifacts
    screenshots_dir: str = "app/static/screenshots"

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls(
            gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
            analysis_timeout_seconds=int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "40")),
            max_url_length=int(os.getenv("MAX_URL_LENGTH", "2048")),
            allow_domains=_as_list(os.getenv("ALLOW_DOMAINS")),
            deny_domains=_as_list(os.getenv("DENY_DOMAINS")),
            allow_private_ips=_as_bool(os.getenv("ALLOW_PRIVATE_IPS")),
            block_punycode=_as_bool(os.getenv("BLOCK_PUNYCODE"), default=True),
            rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "30")),
            rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
            log_sample_rate=float(os.getenv("LOG_SAMPLE_RATE", "1.0")),
            screenshots_dir=os.getenv("SCREENSHOTS_DIR", "app/static/screenshots"),
        )
