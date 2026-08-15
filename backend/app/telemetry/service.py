"""Telemetry Orchestration Service for background telemetry collection."""

import asyncio
import logging
from typing import Any

from app.schemas.events import EventType, SecurityEvent
from app.telemetry.network_monitor import NetworkMonitor
from app.telemetry.process_monitor import ProcessMonitor
from database.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)


class TelemetryService:
    """Orchestrates Process and Network Telemetry monitors and manages event storage."""

    def __init__(
        self,
        repository: EventRepository | None = None,
        process_monitor: ProcessMonitor | None = None,
        network_monitor: NetworkMonitor | None = None,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        self.repository = repository or EventRepository()
        self.process_monitor = process_monitor or ProcessMonitor()
        self.network_monitor = network_monitor or NetworkMonitor()
        self.poll_interval_seconds = poll_interval_seconds
        self._is_running = False
        self._task: asyncio.Task | None = None

    def poll_once(self) -> list[SecurityEvent]:
        """Perform a single telemetry collection pass from process and network monitors."""
        collected_events: list[SecurityEvent] = []

        try:
            proc_events = self.process_monitor.poll()
            collected_events.extend(proc_events)
        except Exception as exc:
            logger.error("Error during ProcessMonitor poll: %s", exc)

        try:
            net_events = self.network_monitor.poll()
            collected_events.extend(net_events)
        except Exception as exc:
            logger.error("Error during NetworkMonitor poll: %s", exc)

        if collected_events:
            self.repository.add_events(collected_events)

        return collected_events

    async def start(self) -> None:
        """Start the background telemetry polling worker loop."""
        if self._is_running:
            logger.warning("TelemetryService background worker is already running.")
            return

        self._is_running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(
            "TelemetryService started with interval %s seconds.", self.poll_interval_seconds
        )

    async def stop(self) -> None:
        """Stop the background telemetry polling worker loop gracefully."""
        if not self._is_running:
            return

        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("TelemetryService background worker stopped.")

    async def _run_loop(self) -> None:
        """Async worker loop executing poll_once periodically without blocking asyncio thread."""
        while self._is_running:
            try:
                await asyncio.to_thread(self.poll_once)
            except Exception as exc:
                logger.error("Unexpected error in TelemetryService worker loop: %s", exc)

            await asyncio.sleep(self.poll_interval_seconds)

    def get_events(
        self,
        limit: int = 100,
        event_type: EventType | str | None = None,
        process_id: int | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve recent normalized telemetry events."""
        return self.repository.get_events(limit=limit, event_type=event_type, process_id=process_id)

    def get_stats(self) -> dict[str, Any]:
        """Retrieve repository and monitor telemetry statistics."""
        repo_stats = self.repository.get_stats()
        repo_stats["worker_running"] = self._is_running
        repo_stats["poll_interval_seconds"] = self.poll_interval_seconds
        return repo_stats
