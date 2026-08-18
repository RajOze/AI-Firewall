"""Real-time WebSocket and SSE streaming endpoints."""
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
            yield f"data: {data_payload}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
