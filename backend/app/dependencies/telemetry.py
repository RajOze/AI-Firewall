"""Telemetry dependency injection provider with wired EventDispatcher and subscribers."""

from __future__ import annotations

from app.events.dispatcher import EventDispatcher
from app.events.subscribers.behavioral import BehavioralSubscriber
from app.events.subscribers.repository import RepositorySubscriber
from app.events.types import EventTopic
from app.schemas.events import EventType
from app.telemetry.service import TelemetryService
from backend.security.behavior import BehaviorEngine
from database.repositories.event_repository import EventRepository

_telemetry_service: TelemetryService | None = None


def get_telemetry_service() -> TelemetryService:
    """Provide a singleton TelemetryService with wired EventDispatcher and subscribers."""
    global _telemetry_service
    if _telemetry_service is None:
        repository = EventRepository()
        behavior_engine = BehaviorEngine()
        dispatcher = EventDispatcher()

        # Wire decoupled background subscribers
        repo_subscriber = RepositorySubscriber(repository)
        behavioral_subscriber = BehavioralSubscriber(behavior_engine)

        dispatcher.subscribe(repo_subscriber, EventTopic.ALL)
        dispatcher.subscribe(behavioral_subscriber, EventType.NETWORK_CONNECTION)

        _telemetry_service = TelemetryService(
            repository=repository,
            behavior_engine=behavior_engine,
            dispatcher=dispatcher,
        )
    return _telemetry_service
