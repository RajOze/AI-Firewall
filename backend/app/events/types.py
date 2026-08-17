"""Event Dispatcher Types, Protocols, and Metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Protocol, runtime_checkable

from app.schemas.events import EventType


class EventTopic(str, Enum):
    """Event topics supported by the dispatcher."""

    PROCESS_START = "PROCESS_START"
    PROCESS_STOP = "PROCESS_STOP"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SECURITY_FINDING = "SECURITY_FINDING"
    SYSTEM_METRIC = "SYSTEM_METRIC"
    ALL = "*"

    @classmethod
    def from_event_type(cls, event_type: EventType | str) -> str:
        """Convert an EventType enum or string to its topic name."""
        if isinstance(event_type, EventType):
            return event_type.value
        return str(event_type)


class DropPolicy(str, Enum):
    """Backpressure mitigation policies when the internal queue is saturated."""

    DROP_OLDEST = "DROP_OLDEST"
    DROP_NEWEST = "DROP_NEWEST"
    REJECT = "REJECT"


@runtime_checkable
class SubscriberProtocol(Protocol):
    """Protocol representing a subscriber capable of handling security events."""

    async def handle_event(self, event: Any) -> None:
        """Process a single event asynchronously."""
        ...


AsyncEventHandler = Callable[[Any], Awaitable[None]]
SubscriberTarget = SubscriberProtocol | AsyncEventHandler


@dataclass
class DispatcherMetrics:
    """Telemetry metrics tracking dispatcher throughput and backpressure."""

    published_count: int = 0
    delivered_count: int = 0
    dropped_count: int = 0
    error_count: int = 0
    queue_depth: int = 0
    max_capacity: int = 5000
    active_subscribers: int = 0
    errors_by_subscriber: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "published_count": self.published_count,
            "delivered_count": self.delivered_count,
            "dropped_count": self.dropped_count,
            "error_count": self.error_count,
            "queue_depth": self.queue_depth,
            "max_capacity": self.max_capacity,
            "active_subscribers": self.active_subscribers,
            "errors_by_subscriber": dict(self.errors_by_subscriber),
        }
