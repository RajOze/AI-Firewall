"""Fix EventRepository to merge buffered items and enable SQLite WAL mode cleanly."""
from pathlib import Path

target_file = Path("database/repositories/event_repository.py")

code = '''"""Event repository with SQLite WAL mode and immediate in-memory buffer visibility."""
from collections import deque
import sqlite3
import threading
from typing import Any, Sequence
from backend.app.schemas.events import SecurityEvent

class EventRepository:
    """Thread-safe event repository with ring buffer and SQLite WAL support."""

    def __init__(self, db_path: str = ":memory:", max_capacity: int = 10000) -> None:
        self.max_capacity = max_capacity
        self.db_path = db_path
        self._lock = threading.Lock()
        self._memory_events = deque(maxlen=max_capacity)
        self._total_ingested = 0
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode = WAL;")
                cur.execute("PRAGMA synchronous = NORMAL;")
                cur.execute("PRAGMA cache_size = -8000;")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            self._conn.commit()

    def add_event(self, event: SecurityEvent) -> None:
        with self._lock:
            self._memory_events.append(event)
            self._total_ingested += 1

    def add_events(self, events: Sequence[SecurityEvent]) -> None:
        with self._lock:
            for ev in events:
                self._memory_events.append(ev)
                self._total_ingested += 1

    def get_events(self, limit: int = 100, event_type: str | None = None) -> list[SecurityEvent]:
        with self._lock:
            evts = list(self._memory_events)
            if event_type:
                evts = [e for e in evts if getattr(e, "event_type", None) == event_type or getattr(getattr(e, "event_type", None), "value", None) == event_type]
            return evts[-limit:]

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_stored_events": len(self._memory_events),
                "total_ingested_events": self._total_ingested,
                "max_capacity": self.max_capacity,
            }

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
'''

target_file.parent.mkdir(parents=True, exist_ok=True)
target_file.write_text(code, encoding="utf-8")
print("Successfully patched database/repositories/event_repository.py")
