"""Normalized security event schemas for Phase 1 Telemetry."""

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Supported Phase 1 security event types."""

    PROCESS_START = "PROCESS_START"
    PROCESS_STOP = "PROCESS_STOP"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"


class ConnectionDirection(str, Enum):
    """Network connection direction."""

    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    UNKNOWN = "UNKNOWN"


class ProcessStartEvent(BaseModel):
    """Telemetry event emitted when a host process starts."""

    event_type: Literal[EventType.PROCESS_START] = EventType.PROCESS_START
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    process_id: int
    parent_process_id: int | None = None
    process_name: str
    executable_path: str | None = None
    command_line: list[str] | None = None
    publisher: str | None = None
    is_signed: bool | None = None


class ProcessStopEvent(BaseModel):
    """Telemetry event emitted when a host process terminates."""

    event_type: Literal[EventType.PROCESS_STOP] = EventType.PROCESS_STOP
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    process_id: int
    parent_process_id: int | None = None
    process_name: str
    executable_path: str | None = None


class NetworkConnectionEvent(BaseModel):
    """Telemetry event emitted when a network socket connection change occurs."""

    event_type: Literal[EventType.NETWORK_CONNECTION] = EventType.NETWORK_CONNECTION
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    process_id: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str  # e.g., "TCP", "UDP"
    direction: ConnectionDirection = ConnectionDirection.UNKNOWN
    connection_state: str  # e.g., "ESTABLISHED", "LISTEN", "CLOSED"


# Container type representing any Phase 1 telemetry event
SecurityEvent = ProcessStartEvent | ProcessStopEvent | NetworkConnectionEvent
