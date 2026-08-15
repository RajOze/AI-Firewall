"""Unit tests for NetworkMonitor."""

from unittest.mock import MagicMock, patch
from app.schemas.events import ConnectionDirection, EventType
from app.telemetry.network_monitor import NetworkMonitor, infer_direction
from backend.security.models import ProcessInfo


def test_infer_direction_rules() -> None:
    """Verify socket direction inference logic."""
    assert infer_direction({"status": "LISTEN"}) == ConnectionDirection.INBOUND
    assert (
        infer_direction({"status": "ESTABLISHED", "raddr": "1.1.1.1", "rport": 443})
        == ConnectionDirection.UNKNOWN
    )
    assert (
        infer_direction({"status": "BOUND", "raddr": "*", "rport": 0})
        == ConnectionDirection.UNKNOWN
    )


def test_network_monitor_poll() -> None:
    """Verify network monitor diff processing and event creation."""
    mock_win_provider = MagicMock()
    mock_win_provider.get_process_info.return_value = ProcessInfo(
        pid=2000, name="web.exe", exe_path="C:\\Apps\\web.exe"
    )

    fake_connections = [
        {
            "proto": "TCP",
            "laddr": "127.0.0.1",
            "lport": 8080,
            "raddr": "93.184.216.34",
            "rport": 80,
            "status": "ESTABLISHED",
            "pid": 2000,
        }
    ]

    with patch("app.telemetry.network_monitor._snapshot") as mock_snap:
        mock_snap.return_value = {
            ("TCP", "127.0.0.1", 8080, "93.184.216.34", 80): fake_connections[0]
        }
        monitor = NetworkMonitor(windows_provider=mock_win_provider)
        events = monitor.poll()

        assert len(events) == 1
        event = events[0]
        assert event.event_type == EventType.NETWORK_CONNECTION
        assert event.process_id == 2000
        assert event.process_name == "web.exe"
        assert event.executable_path == "C:\\Apps\\web.exe"
        assert event.local_address == "127.0.0.1"
        assert event.local_port == 8080
        assert event.remote_address == "93.184.216.34"
        assert event.remote_port == 80
        assert event.protocol == "TCP"
        assert event.direction == ConnectionDirection.UNKNOWN
        assert event.connection_state == "ESTABLISHED"

