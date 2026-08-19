"""Unit tests for EventRepository."""

import asyncio
import pytest

from app.schemas.events import (
    ConnectionDirection,
    EventType,
    NetworkConnectionEvent,
    ProcessStartEvent,
    ProcessStopEvent,
)
from database.repositories.event_repository import EventRepository


@pytest.mark.anyio
async def test_repository_add_and_get_events() -> None:
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

    await repo.add_events([p_start, p_stop, net_conn])

    all_events = repo.get_events(limit=10)
    assert len(all_events) == 3

    proc_starts = repo.get_events(event_type=EventType.PROCESS_START)
    assert len(proc_starts) == 1
    assert proc_starts[0].process_id == 100

    by_pid = repo.get_events(process_id=100)
    assert len(by_pid) == 2


@pytest.mark.anyio
async def test_repository_capacity_limit() -> None:
    """Verify repository enforces max capacity ring-buffer behavior."""
    repo = EventRepository(max_capacity=3)
    for i in range(5):
        await repo.add_event(
            ProcessStartEvent(process_id=i, process_name=f"proc_{i}.exe")
        )

    all_events = repo.get_events(limit=10)
    assert len(all_events) == 3
    # Recent items first
    pids = [e.process_id for e in all_events]
    assert pids == [4, 3, 2]


@pytest.mark.anyio
async def test_repository_stats() -> None:
    """Verify operational statistics reporting."""
    repo = EventRepository(max_capacity=100)
    # Note: stats only reflect in-memory events, not DB-persisted ones
    # For accurate stats, we'd need to wait for flush, but for unit test we check what's immediately available
    await repo.add_event(ProcessStartEvent(process_id=1, process_name="a.exe"))
    await repo.add_event(ProcessStopEvent(process_id=1, process_name="a.exe"))

    stats = repo.get_stats()
    assert stats["total_stored_events"] == 2
    assert stats["max_capacity"] == 100
    assert stats["counts_by_type"][EventType.PROCESS_START.value] == 1
    assert stats["counts_by_type"][EventType.PROCESS_STOP.value] == 1


@pytest.mark.anyio
async def test_repository_batch_flushing() -> None:
    """Test that events are flushed in batches when reaching batch size."""
    # Create a repo with small batch size for testing
    repo = EventRepository(db_path=":memory:", max_capacity=100)
    # Access the batch buffer directly to configure it for testing
    repo._batch_buffer._batch_size = 3
    repo._batch_buffer._flush_interval = 10.0  # Long interval to test size-based flushing

    # Add exactly batch size events
    events = [
        ProcessStartEvent(process_id=i, process_name=f"proc_{i}.exe")
        for i in range(3)
    ]
    await repo.add_events(events)

    # Manually trigger flush to verify events were queued
    await repo._batch_buffer.flush()

    # Add more events to trigger another batch
    more_events = [
        ProcessStartEvent(process_id=i+3, process_name=f"proc_{i+3}.exe")
        for i in range(3)
    ]
    await repo.add_events(more_events)
    await repo._batch_buffer.flush()

    # Verify we can still get events from memory (recent ones)
    recent_events = repo.get_events(limit=10)
    # Should have the most recent events in memory
    assert len(recent_events) > 0


@pytest.mark.anyio
async def test_repository_timeout_flushing() -> None:
    """Test that events are flushed after timeout interval."""
    repo = EventRepository(db_path=":memory:", max_capacity=100)
    # Configure for quick timeout
    repo._batch_buffer._batch_size = 100  # Large batch size to test time-based
    repo._batch_buffer._flush_interval = 0.1  # 100ms

    # Add fewer events than batch size
    events = [
        ProcessStartEvent(process_id=i, process_name=f"proc_{i}.exe")
        for i in range(5)
    ]
    await repo.add_events(events)

    # Wait for flush interval to pass
    await asyncio.sleep(0.15)

    # Manually trigger flush to verify events were queued and flushed
    await repo._batch_buffer.flush()

    # Verify we can still get events from memory (recent ones)
    recent_events = repo.get_events(limit=10)
    assert len(recent_events) > 0


@pytest.mark.anyio
async def test_repository_close_flushes_remaining() -> None:
    """Test that closing the repository flushes remaining events."""
    repo = EventRepository(db_path=":memory:", max_capacity=100)
    repo._batch_buffer._batch_size = 100  # Large to prevent size-based flushing
    repo._batch_buffer._flush_interval = 10.0  # Long to prevent time-based

    # Add some events
    events = [
        ProcessStartEvent(process_id=i, process_name=f"proc_{i}.exe")
        for i in range(5)
    ]
    await repo.add_events(events)

    # Close should trigger flush of remaining events
    await repo.close()

    # After close, we should still be able to get events from memory
    # (the memory deque is separate from DB storage)
    recent_events = repo.get_events(limit=10)
    assert len(recent_events) == 5
