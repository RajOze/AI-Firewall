"""Event repository with SQLite WAL support, batch buffering, and in-memory caching."""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
import sqlite3
import threading
import time
from typing import Any, Dict, List, Sequence


@dataclass
class QueuedEvent:
    """Represents an event queued for batch insertion."""

    event: Any
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
            asyncio.get_running_loop()
            self._flush_task = asyncio.create_task(self._flush_loop())
        except RuntimeError:
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

    async def add_event(self, event: Any) -> None:
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

        events_to_flush = self._queue.copy()
        self._queue.clear()
        self._last_flush = time.monotonic()

        query = """
            INSERT INTO security_events (event_id, timestamp, event_type, payload)
            VALUES (?, ?, ?, ?)
        """
        rows = []
        for queued_event in events_to_flush:
            event = queued_event.event
            if isinstance(event, dict):
                event_id = event.get("event_id", str(hash(str(event))))
                timestamp = str(event.get("timestamp", ""))
                event_type = str(event.get("type", event.get("event_type", "unknown")))
                payload = str(event)
            else:
                event_id = getattr(event, "event_id", str(hash(str(event))))
                timestamp = str(getattr(event, "timestamp", ""))
                raw_type = getattr(event, "event_type", getattr(event, "type", "unknown"))
                event_type = raw_type.value if hasattr(raw_type, "value") else str(raw_type)
                payload = str(getattr(event, "payload", event))
            rows.append((event_id, timestamp, event_type, payload))

        def _do_insert():
            cur = self._connection.cursor()
            cur.executemany(query, rows)
            self._connection.commit()

        await asyncio.to_thread(_do_insert)

    async def _flush_loop(self) -> None:
        """Background loop that periodically flushes the batch."""
        while not self._stop_requested:
            await asyncio.sleep(self._flush_interval)
            async with self._lock:
                if (
                    self._queue
                    and (time.monotonic() - self._last_flush) >= self._flush_interval
                ):
                    await self._flush_locked()


class EventRepository:
    """Thread-safe event repository with SQLite WAL backing and newest-first event queries."""

    def __init__(self, db_path: str = ":memory:", max_capacity: int = 10000) -> None:
        self.max_capacity = max_capacity
        self.db_path = db_path
        self._lock = threading.Lock()
        self._memory_events: deque[Any] = deque(maxlen=max_capacity)
        self._total_ingested: int = 0
        self._counts_by_type: Dict[str, int] = {}
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._batch_buffer = SQLiteBatchBuffer(self._conn)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode = WAL;")
                cur.execute("PRAGMA synchronous = NORMAL;")
                cur.execute("PRAGMA temp_store = MEMORY;")
                cur.execute("PRAGMA cache_size = -8000;")
                cur.execute("PRAGMA wal_autocheckpoint = 1000;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """
            )
            self._conn.commit()

    def _track_event(self, event: Any) -> None:
        """Track event in memory and increment counts."""
        self._memory_events.append(event)
        self._total_ingested += 1
        if isinstance(event, dict):
            event_type = str(event.get("type", event.get("event_type", "unknown")))
        else:
            raw_type = getattr(event, "event_type", getattr(event, "type", "unknown"))
            event_type = raw_type.value if hasattr(raw_type, "value") else str(raw_type)
        if event_type:
            self._counts_by_type[event_type] = self._counts_by_type.get(event_type, 0) + 1

    async def _ensure_batch_buffer_started(self) -> None:
        """Ensure the batch buffer background task is started."""
        await self._batch_buffer.start()

    async def save(self, event: Any) -> None:
        """Save a single event into repository storage."""
        with self._lock:
            self._track_event(event)
        await self._ensure_batch_buffer_started()
        await self._batch_buffer.add_event(event)

    async def add_event(self, event: Any) -> None:
        """Add a single event to the repository (mirrors save)."""
        await self.save(event)

    async def add_events(self, events: Sequence[Any]) -> None:
        """Add multiple events to the repository asynchronously."""
        with self._lock:
            for ev in events:
                self._track_event(ev)
        await self._ensure_batch_buffer_started()
        for ev in events:
            await self._batch_buffer.add_event(ev)

    async def get_all(self) -> List[Any]:
        """Return all events stored in memory."""
        with self._lock:
            return list(self._memory_events)

    def get_events(
        self,
        limit: int = 100,
        event_type: Any = None,
        process_id: int | None = None,
    ) -> List[Any]:
        """Retrieve recent events matching optional filter criteria (newest first)."""
        with self._lock:
            evts = list(reversed(self._memory_events))
            if event_type:
                target_type = (
                    event_type.value if hasattr(event_type, "value") else str(event_type)
                )
                filtered = []
                for e in evts:
                    if isinstance(e, dict):
                        e_type = str(e.get("type", e.get("event_type", "")))
                    else:
                        raw_type = getattr(e, "event_type", getattr(e, "type", ""))
                        e_type = raw_type.value if hasattr(raw_type, "value") else str(raw_type)
                    if e_type == target_type:
                        filtered.append(e)
                evts = filtered
            if process_id is not None:
                filtered = []
                for e in evts:
                    if isinstance(e, dict):
                        pid = e.get("process_id")
                    else:
                        pid = getattr(e, "process_id", None)
                    if pid == process_id:
                        filtered.append(e)
                evts = filtered
            return evts[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Return operational telemetry repository statistics."""
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
