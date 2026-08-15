"""
Application configuration for Sentinel AI Firewall.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from .env."""

    app_name: str = "Sentinel AI Firewall"
    app_version: str = "0.1.0"

    debug: bool = False

    host: str = "127.0.0.1"
    port: int = 8000

    log_level: str = "INFO"

    google_api_key: str = ""

    telemetry_poll_interval_seconds: float = 2.0
    telemetry_max_capacity: int = 10000

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()


settings = get_settings()