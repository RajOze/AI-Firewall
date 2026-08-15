"""In-memory event repository for read-only Phase 1 Telemetry."""

from collections import deque
import threading
from typing import Any, Sequence

from app.schemas.events import EventType, SecurityEvent


class EventRepository:
    """Thread-safe in-memory ring-buffer event repository."""

    def __init__(self, max_capacity: int = 10000) -> None:
        self._max_capacity = max_capacity
        self._events: deque[SecurityEvent] = deque(maxlen=max_capacity)
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {
            EventType.PROCESS_START.value: 0,
            EventType.PROCESS_STOP.value: 0,
            EventType.NETWORK_CONNECTION.value: 0,
        }

    def add_event(self, event: SecurityEvent) -> None:
        """Add a single telemetry event to the repository."""
        with self._lock:
            self._events.appendleft(event)
            event_type_str = (
                event.event_type.value
                if isinstance(event.event_type, EventType)
                else str(event.event_type)
            )
            self._counts[event_type_str] = self._counts.get(event_type_str, 0) + 1

    def add_events(self, events: Sequence[SecurityEvent]) -> None:
        """Add multiple telemetry events to the repository."""
        with self._lock:
            for event in events:
                self._events.appendleft(event)
                event_type_str = (
                    event.event_type.value
                    if isinstance(event.event_type, EventType)
                    else str(event.event_type)
                )
                self._counts[event_type_str] = self._counts.get(event_type_str, 0) + 1

    def get_events(
        self,
        limit: int = 100,
        event_type: EventType | str | None = None,
        process_id: int | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve recent events matching optional filter criteria."""
        filter_type_str = None
        if event_type is not None:
            filter_type_str = (
                event_type.value if isinstance(event_type, EventType) else str(event_type)
            )

        result: list[SecurityEvent] = []
        with self._lock:
            for event in self._events:
                if len(result) >= limit:
                    break

                current_type_str = (
                    event.event_type.value
                    if isinstance(event.event_type, EventType)
                    else str(event.event_type)
                )
                if filter_type_str and current_type_str != filter_type_str:
                    continue

                if process_id is not None and getattr(event, "process_id", None) != process_id:
                    continue

                result.append(event)

        return result

    def get_stats(self) -> dict[str, Any]:
        """Return operational telemetry repository statistics."""
        with self._lock:
            current_count = len(self._events)
            oldest_ts = self._events[-1].timestamp if self._events else None
            newest_ts = self._events[0].timestamp if self._events else None
            counts_copy = dict(self._counts)

        return {
            "total_stored_events": current_count,
            "max_capacity": self._max_capacity,
            "counts_by_type": counts_copy,
            "oldest_event_timestamp": oldest_ts,
            "newest_event_timestamp": newest_ts,
        }

    def clear(self) -> None:
        """Clear all stored events and reset counters."""
        with self._lock:
            self._events.clear()
            for key in self._counts:
                self._counts[key] = 0
