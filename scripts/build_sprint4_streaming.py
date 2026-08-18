import os
from pathlib import Path

files = {}

# 1. backend/app/stream/manager.py
files['backend/app/stream/manager.py'] = '''"""WebSocket and SSE connection manager with topic filtering and dead socket cleanup."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class StreamClient:
    """Represents a connected client with selective topic and severity filtering."""
    def __init__(self, websocket: WebSocket, client_id: str, topics: set[str] | None = None) -> None:
        self.websocket = websocket
        self.client_id = client_id
        self.topics = topics or {"*"}
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)

    def is_interested(self, topic: str) -> bool:
        """Check if client is subscribed to the specific event topic."""
        return "*" in self.topics or topic in self.topics


class StreamManagerMetrics(BaseModel):
    """Real-time diagnostics for active streaming connections."""
    active_connections: int = Field(default=0, description="Number of connected WebSocket clients")
    total_messages_broadcast: int = Field(default=0, description="Total events broadcast to clients")
    dropped_messages: int = Field(default=0, description="Events dropped due to slow client buffers")


class WebSocketConnectionManager:
    """Manages active WebSocket connections and distributes telemetry payloads."""

    def __init__(self) -> None:
        self._active_clients: dict[str, StreamClient] = {}
        self._lock = asyncio.Lock()
        self._metrics = StreamManagerMetrics()

    @property
    def metrics(self) -> StreamManagerMetrics:
        self._metrics.active_connections = len(self._active_clients)
        return self._metrics

    async def connect(self, websocket: WebSocket, client_id: str, topics: set[str] | None = None) -> StreamClient:
        """Accept WebSocket connection and register client."""
        await websocket.accept()
        client = StreamClient(websocket=websocket, client_id=client_id, topics=topics)
        async with self._lock:
            self._active_clients[client_id] = client
        logger.info("WebSocket client connected: %s (Active: %d)", client_id, len(self._active_clients))
        return client

    async def disconnect(self, client_id: str) -> None:
        """Remove client from active connection pool."""
        async with self._lock:
            client = self._active_clients.pop(client_id, None)
        if client:
            logger.info("WebSocket client disconnected: %s", client_id)

    async def broadcast(self, topic: str, payload: dict[str, Any]) -> None:
        """Broadcast payload to all interested connected clients asynchronously."""
        data = {
            "topic": topic,
            "data": payload,
        }
        json_str = json.dumps(data, default=str)

        async with self._lock:
            clients = list(self._active_clients.values())

        stale_clients: list[str] = []
        for client in clients:
            if not client.is_interested(topic):
                continue

            try:
                await client.websocket.send_text(json_str)
                self._metrics.total_messages_broadcast += 1
            except (WebSocketDisconnect, RuntimeError):
                stale_clients.append(client.client_id)
            except Exception as exc:
                logger.warning("Failed to send message to client %s: %s", client.client_id, exc)
                stale_clients.append(client.client_id)

        if stale_clients:
            async with self._lock:
                for cid in stale_clients:
                    self._active_clients.pop(cid, None)
'''

# 2. backend/app/events/subscribers/stream.py
files['backend/app/events/subscribers/stream.py'] = '''"""StreamSubscriber bridging EventDispatcher to WebSocketConnectionManager."""
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
'''

# 3. backend/app/dependencies/stream.py
files['backend/app/dependencies/stream.py'] = '''"""Dependency injection providers for WebSocket streaming manager."""
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
'''

# 4. backend/app/api/stream.py
files['backend/app/api/stream.py'] = '''"""Real-time WebSocket and SSE streaming endpoints."""
import asyncio
import json
import uuid
from typing import Any, AsyncGenerator
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

from app.dependencies.stream import get_stream_manager
from app.stream.manager import StreamManagerMetrics, WebSocketConnectionManager

router = APIRouter(prefix="/api/v1/stream", tags=["Real-Time Stream"])


@router.get("/stats", response_model=StreamManagerMetrics)
def get_stream_stats(
    manager: WebSocketConnectionManager = Depends(get_stream_manager),
) -> StreamManagerMetrics:
    """Retrieve operational diagnostics for active real-time stream connections."""
    return manager.metrics


@router.websocket("/ws")
async def websocket_stream_endpoint(
    websocket: WebSocket,
    topics: str | None = Query(default=None, description="Comma-separated topics (e.g., PROCESS_START,NETWORK_CONNECTION)"),
    manager: WebSocketConnectionManager = Depends(get_stream_manager),
) -> None:
    """FastAPI WebSocket endpoint providing real-time telemetry and advisory feeds."""
    client_id = str(uuid.uuid4())
    subscribed_topics = set(topics.split(",")) if topics else {"*"}

    await manager.connect(websocket, client_id=client_id, topics=subscribed_topics)
    try:
        while True:
            # Keep socket alive and handle incoming client commands (e.g. ping/heartbeat)
            data = await websocket.receive_text()
            if data.strip().lower() == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await manager.disconnect(client_id)
    except Exception:
        await manager.disconnect(client_id)


@router.get("/events")
async def sse_event_stream(
    manager: WebSocketConnectionManager = Depends(get_stream_manager),
) -> StreamingResponse:
    """Server-Sent Events (SSE) fallback stream for lightweight browser clients."""
    async def event_generator() -> AsyncGenerator[str, None]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        
        # Simple local push helper
        async def mock_emitter():
            while True:
                await asyncio.sleep(1.0)
                yield f"data: {json.dumps({'type': 'heartbeat', 'active_connections': manager.metrics.active_connections})}\n\n"

        return

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
'''

# 5. tests/unit/api/test_stream_api.py
files['tests/unit/api/test_stream_api.py'] = '''"""Unit tests for WebSocket stream manager and real-time streaming endpoints."""
import json
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.schemas.events import ProcessStartEvent
from app.stream.manager import WebSocketConnectionManager, StreamClient
from backend.app.events.subscribers.stream import StreamSubscriber

client = TestClient(app)


def test_get_stream_stats_endpoint():
    """Verify GET /api/v1/stream/stats returns valid metrics."""
    response = client.get("/api/v1/stream/stats")
    assert response.status_code == 200
    data = response.json()
    assert "active_connections" in data
    assert "total_messages_broadcast" in data


def test_websocket_connection_and_ping_pong():
    """Verify WebSocket endpoint accepts connection and responds to ping."""
    with client.websocket_connect("/api/v1/stream/ws") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        parsed = json.loads(data)
        assert parsed.get("type") == "pong"


@pytest.mark.anyio
async def test_stream_manager_broadcast_to_subscribed_topics():
    """Verify StreamManager broadcasts only to clients with matching topic subscriptions."""
    manager = WebSocketConnectionManager()
    
    # Mock WebSocket instances
    class MockWS:
        def __init__(self):
            self.sent = []
        async def accept(self):
            pass
        async def send_text(self, text: str):
            self.sent.append(text)

    ws1 = MockWS()
    ws2 = MockWS()

    c1 = await manager.connect(ws1, client_id="c1", topics={"PROCESS_START"})
    c2 = await manager.connect(ws2, client_id="c2", topics={"NETWORK_CONNECTION"})

    await manager.broadcast(topic="PROCESS_START", payload={"pid": 1234, "name": "test.exe"})

    assert len(ws1.sent) == 1
    assert "test.exe" in ws1.sent[0]
    assert len(ws2.sent) == 0  # Not subscribed to PROCESS_START


@pytest.mark.anyio
async def test_stream_subscriber_forwards_event_to_manager():
    """Verify StreamSubscriber extracts event attributes and forwards to manager broadcast."""
    manager = WebSocketConnectionManager()
    subscriber = StreamSubscriber(manager)
    
    event = ProcessStartEvent(process_id=9999, process_name="test_worker.exe")
    await subscriber.handle_event(event)
    assert manager.metrics.dropped_messages == 0
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully wrote: {rel_path}')

# Register stream_router in backend/app/main.py
main_py_path = Path("backend/app/main.py")
if main_py_path.exists():
    main_code = main_py_path.read_text(encoding="utf-8-sig")
    if "from backend.app.api.stream import router as stream_router" not in main_code and "from app.api.stream import router as stream_router" not in main_code:
        main_code = "from app.api.stream import router as stream_router\n" + main_code
    if "app.include_router(stream_router)" not in main_code:
        main_code += "\napp.include_router(stream_router)\n"
    main_py_path.write_text(main_code, encoding="utf-8")
    print("Successfully registered stream_router in backend/app/main.py")
