"""Dependency factory for telemetry service composition."""

from functools import lru_cache
from app.telemetry.service import TelemetryService

_global_telemetry_service: TelemetryService | None = None


def get_telemetry_service() -> TelemetryService:
    """Return singleton TelemetryService instance.

    FastAPI routes and application layers use this dependency factory to obtain
    the TelemetryService singleton instance.
    """
    global _global_telemetry_service
    if _global_telemetry_service is None:
        _global_telemetry_service = TelemetryService()
    return _global_telemetry_service
