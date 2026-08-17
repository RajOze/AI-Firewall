"""Telemetry Orchestration Service for background telemetry collection and Phase 2 Behavioral Engine integration."""

import asyncio
import logging
from typing import Any

from app.schemas.events import EventType, NetworkConnectionEvent, SecurityEvent
from app.telemetry.network_monitor import NetworkMonitor
from app.telemetry.process_monitor import ProcessMonitor
from backend.security.behavior import BehaviorEngine
from backend.security.models import EnrichedConnection, ProcessInfo
from database.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)


class TelemetryService:
    """Orchestrates Process and Network Telemetry monitors, Phase 2 Behavioral Engine, and manages event storage."""

    def __init__(
        self,
        repository: EventRepository | None = None,
        process_monitor: ProcessMonitor | None = None,
        network_monitor: NetworkMonitor | None = None,
        behavior_engine: BehaviorEngine | None = None,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        self.repository = repository or EventRepository()
        self.process_monitor = process_monitor or ProcessMonitor()
        self.network_monitor = network_monitor or NetworkMonitor()
        self.behavior_engine = behavior_engine or BehaviorEngine()
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

            # Evaluate collected events in Phase 2 Behavioral Baseline Engine
            for evt in collected_events:
                if isinstance(evt, NetworkConnectionEvent):
                    proc_info = ProcessInfo(
                        pid=evt.process_id or 0,
                        name=evt.process_name,
                        exe_path=evt.executable_path,
                    )
                    enriched = EnrichedConnection(
                        pid=evt.process_id,
                        proto=evt.protocol,
                        laddr=evt.local_address,
                        lport=evt.local_port,
                        raddr=evt.remote_address,
                        rport=evt.remote_port,
                        status=evt.connection_state,
                        process_info=proc_info,
                    )
                    try:
                        self.behavior_engine.evaluate_phase2(enriched)
                    except Exception as exc:
                        logger.debug("Error during Phase 2 evaluation of event: %s", exc)

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
        self.behavior_engine.baseline_engine.save()
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

    def get_baseline_summary(self) -> dict[str, Any]:
        """Retrieve Phase 2 behavioral baseline memory summary."""
        return self.behavior_engine.baseline_engine.get_summary()

    def get_stats(self) -> dict[str, Any]:
        """Retrieve repository, monitor telemetry, and baseline memory statistics."""
        repo_stats = self.repository.get_stats()
        repo_stats["worker_running"] = self._is_running
        repo_stats["poll_interval_seconds"] = self.poll_interval_seconds
        repo_stats["baseline_summary"] = self.get_baseline_summary()
        return repo_stats
