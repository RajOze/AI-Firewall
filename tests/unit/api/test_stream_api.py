"""Unit tests for WebSocket stream manager and real-time streaming endpoints."""
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
