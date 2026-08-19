"""Event repository with SQLite WAL support and newest-first retrieval order."""
import asyncio
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Sequence
from backend.app.schemas.events import SecurityEvent

@dataclass
class QueuedEvent:
    """Represents an event queued for batch insertion."""
    event: SecurityEvent
    timestamp: float = field(default_factory=time.monotonic)


class SQLiteBatchBuffer:
    """Asynchronous batch buffer for SQLite that queues events and flushes atomically."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        batch_size: int = 100,
        flush_interval: float = 2.0,
    ) -> None:
        self._connection = connection
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._queue: list[QueuedEvent] = []
        self._lock = asyncio.Lock()
        self._last_flush = time.monotonic()
        self._flush_task: asyncio.Task | None = None
        self._stop_requested = False
        self._started = False

    async def start(self) -> None:
        """Start the background flush task."""
        if self._started:
            return
        self._started = True
        self._stop_requested = False
        try:
            # Check if we're in an event loop
            asyncio.get_running_loop()
            self._flush_task = asyncio.create_task(self._flush_loop())
        except RuntimeError:
            # No running loop, task will be started when needed
            pass

    async def stop(self) -> None:
        """Stop the background flush task and flush remaining events."""
        if not self._started:
            return
        self._stop_requested = True
        if self._flush_task and not self._flush_task.done():
            await self.flush()
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        self._started = False

    async def add_event(self, event: SecurityEvent) -> None:
        """Add an event to the batch queue."""
        async with self._lock:
            self._queue.append(QueuedEvent(event))
            if len(self._queue) >= self._batch_size:
                await self._flush_locked()

    async def flush(self) -> None:
        """Manually flush the batch queue."""
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Internal flush method assuming lock is already held."""
        if not self._queue:
            return

        # Prepare data for executemany
        events_to_flush = self._queue.copy()
        self._queue.clear()
        self._last_flush = time.monotonic()

        # Insert events into database
        placeholders = ", ".join(["(?, ?, ?, ?)"] * len(events_to_flush))
        query = f"""
            INSERT INTO security_events (event_id, timestamp, event_type, payload)
            VALUES {placeholders}
        """
        values = []
        for queued_event in events_to_flush:
            event = queued_event.event
            values.extend([
                getattr(event, "event_id", str(hash(str(event)))),
                getattr(event, "timestamp", ""),
                getattr(event, "event_type", "").value if hasattr(getattr(event, "event_type", ""), "value") else str(getattr(event, "event_type", "")),
                str(getattr(event, "payload", ""))
            ])

        cur = self._connection.cursor()
        cur.execute(query, values)
        self._connection.commit()

    async def _flush_loop(self) -> None:
        """Background loop that periodically flushes the batch."""
        while not self._stop_requested:
            await asyncio.sleep(self._flush_interval)
            async with self._lock:
                if (self._queue and
                    (time.monotonic() - self._last_flush) >= self._flush_interval):
                    await self._flush_locked()


class EventRepository:
    """Thread-safe event repository with SQLite WAL backing and newest-first event queries."""

    def __init__(self, db_path: str = ":memory:", max_capacity: int = 10000) -> None:
        self.max_capacity = max_capacity
        self.db_path = db_path
        self._lock = threading.Lock()
        self._memory_events = deque(maxlen=max_capacity)
        self._total_ingested = 0
        self._counts_by_type = {}
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._batch_buffer = SQLiteBatchBuffer(self._conn)
        self._init_db()
        # Don't start batch buffer here to avoid event loop issues
        # It will be started when first used or via explicit start

    def _init_db(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode = WAL;")
                cur.execute("PRAGMA synchronous = NORMAL;")
                cur.execute("PRAGMA temp_store = MEMORY;")
                cur.execute("PRAGMA cache_size = -8000;")
                cur.execute("PRAGMA wal_autocheckpoint = 1000;")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            self._conn.commit()

    def _track_event(self, event: SecurityEvent) -> None:
        self._memory_events.append(event)
        self._total_ingested += 1
        ev_type = getattr(event, "event_type", None)
        if hasattr(ev_type, "value"):
            ev_type = ev_type.value
        elif ev_type is not None:
            ev_type = str(ev_type)
        if ev_type:
            self._counts_by_type[ev_type] = self._counts_by_type.get(ev_type, 0) + 1

    async def _ensure_batch_buffer_started(self) -> None:
        """Ensure the batch buffer background task is started."""
        await self._batch_buffer.start()

    async def add_event(self, event: SecurityEvent) -> None:
        """Add an event to the repository asynchronously."""
        with self._lock:
            self._track_event(event)
        await self._ensure_batch_buffer_started()
        await self._batch_buffer.add_event(event)

    async def add_events(self, events: Sequence[SecurityEvent]) -> None:
        """Add multiple events to the repository asynchronously."""
        with self._lock:
            for ev in events:
                self._track_event(ev)
        await self._ensure_batch_buffer_started()
        for ev in events:
            await self._batch_buffer.add_event(ev)

    def get_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        process_id: int | None = None,
    ) -> list[SecurityEvent]:
        with self._lock:
            evts = list(reversed(self._memory_events))
            if event_type:
                target_type = event_type.value if hasattr(event_type, "value") else str(event_type)
                evts = [
                    e for e in evts
                    if (getattr(e, "event_type", None) == target_type or
                        getattr(getattr(e, "event_type", None), "value", None) == target_type)
                ]
            if process_id is not None:
                evts = [e for e in evts if getattr(e, "process_id", None) == process_id]
            return evts[:limit]

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_stored_events": len(self._memory_events),
                "total_ingested_events": self._total_ingested,
                "max_capacity": self.max_capacity,
                "counts_by_type": dict(self._counts_by_type),
            }

    async def close(self) -> None:
        """Close the repository and flush any pending events."""
        await self._batch_buffer.stop()
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
