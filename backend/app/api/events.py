"""API routes for telemetry events, behavioral baselines, and monitoring status."""

from typing import Any
from fastapi import APIRouter, Depends, Query, status

from app.dependencies.telemetry import get_telemetry_service
from app.schemas.events import EventType
from app.telemetry.service import TelemetryService

router = APIRouter(
    prefix="/events",
    tags=["Telemetry Events"],
)


@router.get(
    "/",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
)
def list_telemetry_events(
    limit: int = Query(default=100, ge=1, le=1000, description="Max events to return"),
    event_type: EventType | None = Query(default=None, description="Optional EventType filter"),
    process_id: int | None = Query(default=None, description="Optional PID filter"),
    telemetry_service: TelemetryService = Depends(get_telemetry_service),
) -> list[dict[str, Any]]:
    """Return recent normalized security telemetry events."""
    events = telemetry_service.get_events(
        limit=limit,
        event_type=event_type,
        process_id=process_id,
    )
    return [event.model_dump() for event in events]


@router.get(
    "/stats",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
)
def get_telemetry_stats(
    telemetry_service: TelemetryService = Depends(get_telemetry_service),
) -> dict[str, Any]:
    """Return telemetry repository and monitoring status statistics."""
    return telemetry_service.get_stats()


@router.get(
    "/baseline",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
)
def get_behavioral_baseline_summary(
    telemetry_service: TelemetryService = Depends(get_telemetry_service),
) -> dict[str, Any]:
    """Return Phase 2 Behavioral Baseline memory summary."""
    return telemetry_service.get_baseline_summary()
