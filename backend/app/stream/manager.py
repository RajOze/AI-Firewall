"""WebSocket and SSE connection manager with topic filtering and dead socket cleanup."""
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
