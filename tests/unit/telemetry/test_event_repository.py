"""Unit tests for EventRepository."""

from app.schemas.events import (
    ConnectionDirection,
    EventType,
    NetworkConnectionEvent,
    ProcessStartEvent,
    ProcessStopEvent,
)
from database.repositories.event_repository import EventRepository


def test_repository_add_and_get_events() -> None:
    """Verify storing and querying events from repository."""
    repo = EventRepository(max_capacity=10)

    p_start = ProcessStartEvent(
        process_id=100, process_name="init.exe", parent_process_id=0
    )
    p_stop = ProcessStopEvent(process_id=100, process_name="init.exe")
    net_conn = NetworkConnectionEvent(
        local_address="127.0.0.1",
        local_port=8000,
        remote_address="*",
        remote_port=0,
        protocol="TCP",
        direction=ConnectionDirection.INBOUND,
        connection_state="LISTEN",
    )

    repo.add_events([p_start, p_stop, net_conn])

    all_events = repo.get_events(limit=10)
    assert len(all_events) == 3

    proc_starts = repo.get_events(event_type=EventType.PROCESS_START)
    assert len(proc_starts) == 1
    assert proc_starts[0].process_id == 100

    by_pid = repo.get_events(process_id=100)
    assert len(by_pid) == 2


def test_repository_capacity_limit() -> None:
    """Verify repository enforces max capacity ring-buffer behavior."""
    repo = EventRepository(max_capacity=3)
    for i in range(5):
        repo.add_event(
            ProcessStartEvent(process_id=i, process_name=f"proc_{i}.exe")
        )

    all_events = repo.get_events(limit=10)
    assert len(all_events) == 3
    # Recent items first
    pids = [e.process_id for e in all_events]
    assert pids == [4, 3, 2]


def test_repository_stats() -> None:
    """Verify operational statistics reporting."""
    repo = EventRepository(max_capacity=100)
    repo.add_event(ProcessStartEvent(process_id=1, process_name="a.exe"))
    repo.add_event(ProcessStopEvent(process_id=1, process_name="a.exe"))

    stats = repo.get_stats()
    assert stats["total_stored_events"] == 2
    assert stats["max_capacity"] == 100
    assert stats["counts_by_type"][EventType.PROCESS_START.value] == 1
    assert stats["counts_by_type"][EventType.PROCESS_STOP.value] == 1
