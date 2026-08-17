"""Decoupled subscriber for persisting security events into the repository."""

from __future__ import annotations

import logging
from typing import Any

from app.schemas.events import SecurityEvent
from database.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)


class RepositorySubscriber:
    """Subscriber that ingests security events into the EventRepository."""

    def __init__(self, repository: EventRepository) -> None:
        self._repository = repository

    async def handle_event(self, event: Any) -> None:
        """Receive and insert security events into storage."""
        if isinstance(event, (SecurityEvent,)):
            self._repository.add_event(event)
        elif hasattr(event, "event_type"):
            self._repository.add_event(event)
        else:
            logger.debug("Skipping unhandled repository event type: %s", type(event))
