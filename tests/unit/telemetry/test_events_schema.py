"""Unit tests for Phase 1 normalized event schemas."""

from app.schemas.events import (
    ConnectionDirection,
    EventType,
    NetworkConnectionEvent,
    ProcessStartEvent,
    ProcessStopEvent,
)


def test_process_start_event_schema() -> None:
    """Verify ProcessStartEvent serializes with required fields and defaults."""
    event = ProcessStartEvent(
        process_id=1234,
        parent_process_id=1000,
        process_name="test_app.exe",
        executable_path="C:\\Program Files\\Test\\test_app.exe",
        command_line=["test_app.exe", "--flag"],
        publisher="Test Vendor Inc.",
        is_signed=True,
    )
    assert event.event_type == EventType.PROCESS_START
    assert event.process_id == 1234
    assert event.parent_process_id == 1000
    assert event.process_name == "test_app.exe"
    assert event.executable_path == "C:\\Program Files\\Test\\test_app.exe"
    assert event.command_line == ["test_app.exe", "--flag"]
    assert event.publisher == "Test Vendor Inc."
    assert event.is_signed is True
    assert isinstance(event.timestamp, str)


def test_process_stop_event_schema() -> None:
    """Verify ProcessStopEvent serializes with required fields."""
    event = ProcessStopEvent(
        process_id=1234,
        parent_process_id=1000,
        process_name="test_app.exe",
        executable_path="C:\\Program Files\\Test\\test_app.exe",
    )
    assert event.event_type == EventType.PROCESS_STOP
    assert event.process_id == 1234
    assert event.process_name == "test_app.exe"


def test_network_connection_event_schema() -> None:
    """Verify NetworkConnectionEvent serializes with required network metadata."""
    event = NetworkConnectionEvent(
        process_id=5678,
        process_name="chrome.exe",
        executable_path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
        local_address="192.168.1.50",
        local_port=54321,
        remote_address="142.250.190.46",
        remote_port=443,
        protocol="TCP",
        direction=ConnectionDirection.OUTBOUND,
        connection_state="ESTABLISHED",
    )
    assert event.event_type == EventType.NETWORK_CONNECTION
    assert event.process_id == 5678
    assert event.process_name == "chrome.exe"
    assert event.local_address == "192.168.1.50"
    assert event.local_port == 54321
    assert event.remote_address == "142.250.190.46"
    assert event.remote_port == 443
    assert event.protocol == "TCP"
    assert event.direction == ConnectionDirection.OUTBOUND
    assert event.connection_state == "ESTABLISHED"
