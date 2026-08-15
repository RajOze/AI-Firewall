"""Network Telemetry Monitor for tracking socket connection events."""

import logging
from typing import Any

from app.schemas.events import ConnectionDirection, NetworkConnectionEvent
from backend.security.providers.windows import WindowsProcessProvider
from network.monitor.tracker import _snapshot, compare_snapshots

logger = logging.getLogger(__name__)


def infer_direction(conn: dict[str, Any]) -> ConnectionDirection:
    """Infer network connection direction reliably from available socket information.

    If direction cannot be confidently determined from socket state, defaults to UNKNOWN
    to avoid manufacturing security telemetry.
    """
    status = str(conn.get("status", "")).upper()
    if status in ("LISTEN", "LISTENING"):
        return ConnectionDirection.INBOUND

    # For established/other active sockets, socket tuple alone does not prove who initiated connection
    return ConnectionDirection.UNKNOWN



class NetworkMonitor:
    """Monitors active host network connections and converts snapshot diffs into NetworkConnectionEvents."""

    def __init__(self, windows_provider: WindowsProcessProvider | None = None) -> None:
        self.windows_provider = windows_provider or WindowsProcessProvider()
        self._previous_snapshot: dict[tuple[str, str, int, str, int], dict[str, Any]] | None = None
        self._process_cache: dict[int, tuple[str | None, str | None]] = {}

    def _get_process_meta(self, pid: int | None) -> tuple[str | None, str | None]:
        """Resolve process_name and executable_path for PID with lightweight caching."""
        if pid is None or pid <= 0:
            return None, None

        if pid in self._process_cache:
            return self._process_cache[pid]

        try:
            proc_info = self.windows_provider.get_process_info(pid)
            name = proc_info.name
            exe = proc_info.exe_path
            self._process_cache[pid] = (name, exe)
            return name, exe
        except Exception:
            return None, None

    def poll(self) -> list[NetworkConnectionEvent]:
        """Poll host network connections and return normalized NetworkConnectionEvents."""
        events: list[NetworkConnectionEvent] = []
        current_snapshot = _snapshot()

        raw_events = compare_snapshots(self._previous_snapshot, current_snapshot)
        self._previous_snapshot = current_snapshot

        for raw in raw_events:
            conn = raw.get("connection")
            if not conn:
                continue

            pid = conn.get("pid")
            proc_name, exe_path = self._get_process_meta(pid)
            direction = infer_direction(conn)

            event = NetworkConnectionEvent(
                process_id=pid if pid and pid > 0 else None,
                process_name=proc_name,
                executable_path=exe_path,
                local_address=str(conn.get("laddr", "0.0.0.0")),
                local_port=int(conn.get("lport", 0)),
                remote_address=str(conn.get("raddr", "*")),
                remote_port=int(conn.get("rport", 0)),
                protocol=str(conn.get("proto", "TCP")).upper(),
                direction=direction,
                connection_state=str(conn.get("status", "UNKNOWN")).upper(),
            )
            events.append(event)

        return events
