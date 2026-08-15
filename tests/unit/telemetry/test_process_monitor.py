"""Unit tests for ProcessMonitor."""

from unittest.mock import MagicMock, patch
from app.schemas.events import EventType
from app.telemetry.process_monitor import ProcessMonitor
from backend.security.models import ProcessInfo


def test_process_monitor_initialization() -> None:
    """Verify initial scan baseline suppresses backfill storm."""
    fake_proc = MagicMock()
    fake_proc.info = {"pid": 1234, "name": "system.exe", "ppid": 4}

    mock_win_provider = MagicMock()
    mock_win_provider.get_process_info.return_value = ProcessInfo(
        pid=1234, name="system.exe", parent_pid=4, exe_path="C:\\Windows\\system.exe"
    )

    with patch("psutil.process_iter", return_value=[fake_proc]):
        monitor = ProcessMonitor(windows_provider=mock_win_provider)
        events = monitor.poll()
        assert len(events) == 0  # Initial baseline scan yields no start/stop events
        assert 1234 in monitor._active_processes


def test_process_monitor_detects_start_and_stop() -> None:
    """Verify process start and stop detection on subsequent polls."""
    def get_info_mock(pid: int) -> ProcessInfo:
        if pid == 1000:
            return ProcessInfo(
                pid=1000,
                name="parent.exe",
                parent_pid=1,
                exe_path="C:\\Apps\\parent.exe",
            )
        return ProcessInfo(
            pid=5555,
            name="new_service.exe",
            parent_pid=1000,
            exe_path="C:\\Apps\\new_service.exe",
            cmdline=["new_service.exe", "--run"],
            publisher="Vendor",
            is_signed=True,
        )

    mock_win_provider = MagicMock()
    mock_win_provider.get_process_info.side_effect = get_info_mock


    proc_1 = MagicMock()
    proc_1.info = {"pid": 1000, "name": "parent.exe", "ppid": 1}

    with patch("psutil.process_iter", return_value=[proc_1]):
        monitor = ProcessMonitor(windows_provider=mock_win_provider)
        monitor.poll()  # Baseline: PID 1000 active

    # Poll 2: PID 1000 disappears, PID 5555 starts
    proc_2 = MagicMock()
    proc_2.info = {"pid": 5555, "name": "new_service.exe", "ppid": 1000}

    with patch("psutil.process_iter", return_value=[proc_2]):
        events = monitor.poll()
        assert len(events) == 2

        event_types = {e.event_type for e in events}
        assert EventType.PROCESS_START in event_types
        assert EventType.PROCESS_STOP in event_types

        start_event = [e for e in events if e.event_type == EventType.PROCESS_START][0]
        assert start_event.process_id == 5555
        assert start_event.process_name == "new_service.exe"
        assert start_event.publisher == "Vendor"

        stop_event = [e for e in events if e.event_type == EventType.PROCESS_STOP][0]
        assert stop_event.process_id == 1000
        assert stop_event.process_name == "parent.exe"
