"""Decoupled subscriber feeding network telemetry to the Phase 2 Behavioral Engine."""

from __future__ import annotations

import logging
from typing import Any

from app.schemas.events import NetworkConnectionEvent
from backend.security.behavior import BehaviorEngine
from backend.security.models import EnrichedConnection, ProcessInfo

logger = logging.getLogger(__name__)


class BehavioralSubscriber:
    """Subscriber evaluating network events against Behavioral Baselines and Anomaly Engines."""

    def __init__(self, behavior_engine: BehaviorEngine) -> None:
        self._engine = behavior_engine

    async def handle_event(self, event: Any) -> None:
        """Convert incoming network events to EnrichedConnection and trigger evaluation."""
        if not isinstance(event, NetworkConnectionEvent):
            return

        proc_info = ProcessInfo(
            pid=event.process_id or 0,
            name=event.process_name,
            exe_path=event.executable_path,
        )
        enriched = EnrichedConnection(
            pid=event.process_id,
            proto=event.protocol,
            laddr=event.local_address,
            lport=event.local_port,
            raddr=event.remote_address,
            rport=event.remote_port,
            status=event.connection_state,
            process_info=proc_info,
        )

        try:
            self._engine.evaluate_phase2(enriched)
        except Exception as exc:
            logger.warning("Behavioral analysis failed on event: %s", exc)
