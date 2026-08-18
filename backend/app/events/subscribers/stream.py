"""StreamSubscriber bridging EventDispatcher to WebSocketConnectionManager."""
from __future__ import annotations

import logging
from typing import Any

from app.events.types import SubscriberProtocol
from app.stream.manager import WebSocketConnectionManager

logger = logging.getLogger(__name__)


class StreamSubscriber(SubscriberProtocol):
    """Consumes normalized security events from EventDispatcher and forwards to WebSocket clients."""

    def __init__(self, manager: WebSocketConnectionManager) -> None:
        self.manager = manager

    async def handle_event(self, event: Any) -> None:
        """Serialize event and broadcast to active stream connections."""
        try:
            topic = getattr(event, "event_type", "UNKNOWN")
            if hasattr(topic, "value"):
                topic = topic.value

            payload = event.model_dump() if hasattr(event, "model_dump") else dict(event)
            await self.manager.broadcast(topic=str(topic), payload=payload)
        except Exception as exc:
            logger.error("Error in StreamSubscriber broadcasting event: %s", exc)
