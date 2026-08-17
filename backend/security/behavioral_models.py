"""Behavioral Event and Memory Models for Phase 2 Engine."""

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Self

from app.schemas.events import (
    NetworkConnectionEvent,
    ProcessStartEvent,
    ProcessStopEvent,
    SecurityEvent,
)
from backend.security.models import EnrichedConnection


class BehaviorStatus(str, Enum):
    """Lifecycle statuses for learned behavioral patterns."""

    NEW = "NEW"
    OBSERVING = "OBSERVING"
    KNOWN_BENIGN = "KNOWN_BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"


VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "RAW", "UNKNOWN"}
VALID_DIRECTIONS = {"INBOUND", "OUTBOUND", "UNKNOWN"}


@dataclass
class BehavioralEvent:
    """Standardized Phase 2 Behavioral Event contract for feature extraction and self-learning baseline.

    Attributes:
        event_id: Unique event identifier string.
        timestamp: Epoch timestamp in seconds.
        event_type: Type of event ('PROCESS_START', 'PROCESS_STOP', 'NETWORK_CONNECTION').
        process_name: Name of process.
        process_id: Process Identifier.
        executable_path: Absolute path to process binary.
        executable_hash: SHA-256 hash string of executable binary.
        signed_status: True if binary is digitally signed, False if unsigned, None if unverified.
        parent_process_id: Parent Process Identifier.
        local_ip: Source IP address.
        local_port: Source port number (0..65535).
        remote_ip: Destination IP address.
        remote_port: Destination port number (0..65535).
        protocol: Transport layer protocol ('TCP', 'UDP', 'ICMP').
        direction: Connection direction ('INBOUND', 'OUTBOUND', 'UNKNOWN').
        connection_state: Socket connection state ('ESTABLISHED', 'LISTEN', etc.).
        bytes_sent: Volume of outbound bytes if available.
        bytes_received: Volume of inbound bytes if available.
        connection_frequency: Estimated connection rate (events/sec).
        metadata: Additional contextual key-value attributes.
    """

    timestamp: float
    event_type: str
    process_name: str
    process_id: int
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    executable_path: str | None = None
    executable_hash: str | None = None
    signed_status: bool | None = None
    parent_process_id: int | None = None
    local_ip: str | None = None
    local_port: int | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    protocol: str | None = "TCP"
    direction: str | None = "UNKNOWN"
    connection_state: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    connection_frequency: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize fields after initialization."""
        # Normalize protocol
        if self.protocol:
            norm_proto = str(self.protocol).upper()
            self.protocol = norm_proto if norm_proto in VALID_PROTOCOLS else "UNKNOWN"

        # Normalize direction
        if self.direction:
            norm_dir = str(self.direction).upper()
            self.direction = norm_dir if norm_dir in VALID_DIRECTIONS else "UNKNOWN"

        # Validate ports
        if self.local_port is not None and not (0 <= self.local_port <= 65535):
            raise ValueError(f"Invalid local_port out of range 0..65535: {self.local_port}")
        if self.remote_port is not None and not (0 <= self.remote_port <= 65535):
            raise ValueError(f"Invalid remote_port out of range 0..65535: {self.remote_port}")

        # Validate IPs
        if self.local_ip and self.local_ip != "*":
            self.local_ip = self._sanitize_ip(self.local_ip)
        if self.remote_ip and self.remote_ip != "*":
            self.remote_ip = self._sanitize_ip(self.remote_ip)

    @staticmethod
    def _sanitize_ip(ip_str: str) -> str:
        """Sanitize IP string or return 'invalid_ip' if malformed."""
        clean = ip_str.strip()
        # Basic IPv4 / IPv6 validation regex
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ipv4_pattern, clean) or ":" in clean:
            return clean
        return "invalid_ip"

    @property
    def behavior_identity_key(self) -> str:
        """Construct canonical behavior identity tuple key.

        Key format: process_name|executable_hash_or_path|remote_ip:remote_port|protocol|direction
        """
        exe_id = self.executable_hash or self.executable_path or "unknown"
        remote_target = f"{self.remote_ip or '0.0.0.0'}:{self.remote_port or 0}"
        return f"{self.process_name}|{exe_id}|{remote_target}|{self.protocol}|{self.direction}"

    @classmethod
    def from_enriched_connection(
        cls, enriched: EnrichedConnection, timestamp: float | None = None
    ) -> Self:
        """Construct BehavioralEvent from an EnrichedConnection object."""
        proc_info = enriched.process_info
        ts = timestamp if timestamp is not None else (
            proc_info.create_time if proc_info and proc_info.create_time else 0.0
        )
        if ts <= 0:
            import time
            ts = time.time()

        proc_name = proc_info.name if proc_info and proc_info.name else f"pid_{enriched.pid or 0}"
        exe_path = proc_info.exe_path if proc_info else None
        sha256 = proc_info.sha256 if proc_info else None
        signed = proc_info.is_signed if proc_info else None
        ppid = proc_info.parent_pid if proc_info else None

        return cls(
            timestamp=ts,
            event_type="NETWORK_CONNECTION",
            process_name=proc_name,
            process_id=enriched.pid or 0,
            executable_path=exe_path,
            executable_hash=sha256,
            signed_status=signed,
            parent_process_id=ppid,
            local_ip=enriched.laddr if enriched.laddr != "*" else None,
            local_port=enriched.lport if enriched.lport and enriched.lport > 0 else None,
            remote_ip=enriched.raddr if enriched.raddr != "*" else None,
            remote_port=enriched.rport if enriched.rport and enriched.rport > 0 else None,
            protocol=str(enriched.proto).upper() if enriched.proto else "TCP",
            direction="INBOUND" if str(enriched.status).upper() in ("LISTEN", "LISTENING") else "UNKNOWN",
            connection_state=enriched.status,
            metadata={"status": enriched.status},
        )

    @classmethod
    def from_security_event(cls, event: SecurityEvent) -> Self:
        """Construct BehavioralEvent from a Phase 1 SecurityEvent schema model."""
        import time
        from datetime import datetime

        try:
            dt = datetime.fromisoformat(event.timestamp)
            ts = dt.timestamp()
        except Exception:
            ts = time.time()

        if isinstance(event, ProcessStartEvent):
            return cls(
                timestamp=ts,
                event_type="PROCESS_START",
                process_name=event.process_name,
                process_id=event.process_id,
                parent_process_id=event.parent_process_id,
                executable_path=event.executable_path,
                signed_status=event.is_signed,
                metadata={"publisher": event.publisher, "command_line": event.command_line},
            )
        elif isinstance(event, ProcessStopEvent):
            return cls(
                timestamp=ts,
                event_type="PROCESS_STOP",
                process_name=event.process_name,
                process_id=event.process_id,
                parent_process_id=event.parent_process_id,
                executable_path=event.executable_path,
            )
        else:
            # NetworkConnectionEvent
            dir_str = (
                event.direction.value
                if hasattr(event.direction, "value")
                else str(event.direction)
            )
            return cls(
                timestamp=ts,
                event_type="NETWORK_CONNECTION",
                process_name=event.process_name or f"pid_{event.process_id or 0}",
                process_id=event.process_id or 0,
                executable_path=event.executable_path,
                local_ip=event.local_address,
                local_port=event.local_port,
                remote_ip=event.remote_address if event.remote_address != "*" else None,
                remote_port=event.remote_port if event.remote_port > 0 else None,
                protocol=str(event.protocol).upper() if event.protocol else "TCP",
                direction=str(dir_str).upper(),
                connection_state=event.connection_state,
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert behavioral event to a dictionary representation."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "executable_path": self.executable_path,
            "executable_hash": self.executable_hash,
            "signed_status": self.signed_status,
            "parent_process_id": self.parent_process_id,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
            "direction": self.direction,
            "connection_state": self.connection_state,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "connection_frequency": self.connection_frequency,
            "behavior_identity_key": self.behavior_identity_key,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BehavioralEvent":
        """Reconstruct BehavioralEvent from a dictionary."""
        return cls(
            event_id=data.get("event_id", f"evt_{uuid.uuid4().hex[:12]}"),
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            process_name=data["process_name"],
            process_id=data["process_id"],
            executable_path=data.get("executable_path"),
            executable_hash=data.get("executable_hash"),
            signed_status=data.get("signed_status"),
            parent_process_id=data.get("parent_process_id"),
            local_ip=data.get("local_ip"),
            local_port=data.get("local_port"),
            remote_ip=data.get("remote_ip"),
            remote_port=data.get("remote_port"),
            protocol=data.get("protocol", "TCP"),
            direction=data.get("direction", "UNKNOWN"),
            connection_state=data.get("connection_state"),
            bytes_sent=data.get("bytes_sent"),
            bytes_received=data.get("bytes_received"),
            connection_frequency=data.get("connection_frequency"),
            metadata=data.get("metadata", {}),
        )
