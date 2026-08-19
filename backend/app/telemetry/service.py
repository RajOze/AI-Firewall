"""Telemetry Orchestration Service with decoupled Asynchronous EventDispatcher integration."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from app.events.dispatcher import EventDispatcher
from app.schemas.events import EventType, NetworkConnectionEvent, SecurityEvent
from app.telemetry.network_monitor import NetworkMonitor
from app.telemetry.process_monitor import ProcessMonitor
from backend.security.behavior import BehaviorEngine
from backend.security.models import EnrichedConnection, ProcessInfo
from database.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)


class TelemetryService:
    """Orchestrates Process/Network Telemetry monitors, EventDispatcher, and manages event storage."""

    def __init__(
        self,
        repository: EventRepository | None = None,
        process_monitor: ProcessMonitor | None = None,
        network_monitor: NetworkMonitor | None = None,
        behavior_engine: BehaviorEngine | None = None,
        dispatcher: EventDispatcher | None = None,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        self.repository = repository or EventRepository()
        self.process_monitor = process_monitor or ProcessMonitor()
        self.network_monitor = network_monitor or NetworkMonitor()
        self.behavior_engine = behavior_engine or BehaviorEngine()
        self.dispatcher = dispatcher
        self.poll_interval_seconds = poll_interval_seconds
        self._is_running = False
        self._task: asyncio.Task | None = None
        self._lock = threading.Lock()
        # Mirror the repository's in-memory storage for direct access
        self._memory_events = self.repository._memory_events
        self._total_ingested = self.repository._total_ingested
        self._counts_by_type = self.repository._counts_by_type

    def poll_once(self) -> list[SecurityEvent]:
        """Perform a single non-blocking telemetry collection pass."""
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
            if self.dispatcher is not None:
                # Non-blocking async fan-out via EventDispatcher (< 0.1 ms latency)
                for evt in collected_events:
                    self.dispatcher.publish_nowait(evt)
            else:
                # Direct fallback when dispatcher is not supplied
                # Note: We're calling async method from sync context - we need to handle this
                # For now, we'll store in memory only and let the batch buffer handle persistence
                with self._lock:
                    for ev in collected_events:
                        self._track_event(ev)
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

    def _track_event(self, event: SecurityEvent) -> None:
        """Track event in memory and update counts (thread-safe)."""
        self._memory_events.append(event)
        self._total_ingested += 1
        ev_type = getattr(event, "event_type", None)
        if hasattr(ev_type, "value"):
            ev_type = ev_type.value
        elif ev_type is not None:
            ev_type = str(ev_type)
        if ev_type:
            self._counts_by_type[ev_type] = self._counts_by_type.get(ev_type, 0) + 1

    async def start(self) -> None:
        """Start background telemetry polling loop and dispatcher worker."""
        if self._is_running:
            logger.warning("TelemetryService background worker is already running.")
            return

        if self.dispatcher and not self.dispatcher.is_running:
            await self.dispatcher.start()

        self._is_running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(
            "TelemetryService started with interval %s seconds.", self.poll_interval_seconds
        )

    async def stop(self) -> None:
        """Gracefully stop background telemetry polling loop and drain queued events."""
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

        if self.dispatcher and self.dispatcher.is_running:
            await self.dispatcher.drain(timeout=3.0)
            await self.dispatcher.stop()

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
        """Retrieve repository, monitor telemetry, baseline memory, and dispatcher metrics."""
        repo_stats = self.repository.get_stats()
        repo_stats["worker_running"] = self._is_running
        repo_stats["poll_interval_seconds"] = self.poll_interval_seconds
        repo_stats["baseline_summary"] = self.get_baseline_summary()
        if self.dispatcher:
            repo_stats["dispatcher_metrics"] = self.dispatcher.metrics.to_dict()
        return repo_stats
