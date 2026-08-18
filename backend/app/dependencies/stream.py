"""Dependency injection providers for WebSocket streaming manager."""
from functools import lru_cache

from app.dependencies.telemetry import get_telemetry_service
from app.events.subscribers.stream import StreamSubscriber
from app.events.types import EventTopic
from app.stream.manager import WebSocketConnectionManager

_stream_manager: WebSocketConnectionManager | None = None


@lru_cache()
def get_stream_manager() -> WebSocketConnectionManager:
    """Return singleton WebSocketConnectionManager wired into the active EventDispatcher."""
    global _stream_manager
    if _stream_manager is None:
        _stream_manager = WebSocketConnectionManager()
        telemetry_service = get_telemetry_service()
        if telemetry_service.dispatcher is not None:
            subscriber = StreamSubscriber(_stream_manager)
            telemetry_service.dispatcher.subscribe(subscriber, EventTopic.ALL)
    return _stream_manager
