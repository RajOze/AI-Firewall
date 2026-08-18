import os
from pathlib import Path

files = {}

# 1. backend/app/api/stream.py
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
        while True:
            await asyncio.sleep(1.0)
            data_payload = json.dumps({
                "type": "heartbeat",
                "active_connections": manager.metrics.active_connections
            })
            yield f"data: {data_payload}\\n\\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
'''

# 2. tests/unit/api/test_stream_api.py
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
    assert len(ws2.sent) == 0


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
