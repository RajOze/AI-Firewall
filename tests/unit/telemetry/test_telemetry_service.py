"""Unit tests for TelemetryService orchestration and API endpoints."""

import asyncio
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from app.events.dispatcher import EventDispatcher
from app.events.subscribers.behavioral import BehavioralSubscriber
from app.events.subscribers.repository import RepositorySubscriber
from app.events.types import EventTopic
from app.main import app
from app.schemas.events import EventType, NetworkConnectionEvent, ProcessStartEvent
from app.telemetry.service import TelemetryService
from backend.security.behavior import BehaviorEngine
from database.repositories.event_repository import EventRepository


def test_telemetry_service_poll_once():
    """Verify single polling pass collects from monitors and populates repository."""
    mock_proc_monitor = MagicMock()
    mock_net_monitor = MagicMock()

    proc_event = ProcessStartEvent(process_id=1234, process_name="test_proc.exe")
    net_event = NetworkConnectionEvent(
        protocol="TCP",
        local_address="127.0.0.1",
        local_port=8080,
        remote_address="1.1.1.1",
        remote_port=443,
        connection_state="ESTABLISHED",
        process_name="test_proc.exe",
    )

    mock_proc_monitor.poll.return_value = [proc_event]
    mock_net_monitor.poll.return_value = [net_event]

    repo = EventRepository()
    service = TelemetryService(
        repository=repo,
        process_monitor=mock_proc_monitor,
        network_monitor=mock_net_monitor,
    )

    events = service.poll_once()
    assert len(events) == 2
    assert len(repo.get_events()) == 2


def test_telemetry_service_with_event_dispatcher():
    """Verify TelemetryService non-blocking publish into EventDispatcher."""
    async def _test():
        mock_proc_monitor = MagicMock()
        mock_net_monitor = MagicMock()

        proc_event = ProcessStartEvent(process_id=5555, process_name="dispatcher_test.exe")
        net_event = NetworkConnectionEvent(
            protocol="TCP",
            local_address="10.0.0.1",
            local_port=12345,
            remote_address="8.8.4.4",
            remote_port=53,
            connection_state="ESTABLISHED",
            process_name="dispatcher_test.exe",
        )

        mock_proc_monitor.poll.return_value = [proc_event]
        mock_net_monitor.poll.return_value = [net_event]

        repo = EventRepository()
        engine = BehaviorEngine()
        dispatcher = EventDispatcher()

        dispatcher.subscribe(RepositorySubscriber(repo), EventTopic.ALL)
        dispatcher.subscribe(BehavioralSubscriber(engine), EventType.NETWORK_CONNECTION)

        service = TelemetryService(
            repository=repo,
            process_monitor=mock_proc_monitor,
            network_monitor=mock_net_monitor,
            behavior_engine=engine,
            dispatcher=dispatcher,
        )

        await dispatcher.start()
        service.poll_once()
        await dispatcher.drain()
        await dispatcher.stop()

        events = repo.get_events()
        assert len(events) == 2
        assert service.get_stats()["dispatcher_metrics"]["delivered_count"] >= 2

    asyncio.run(_test())


def test_get_events_api_endpoint():
    """Verify /events returns event list with 200 OK."""
    client = TestClient(app)
    response = client.get("/events?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_events_api_filter_by_type():
    """Verify /events supports filtering by event_type query param."""
    client = TestClient(app)
    response = client.get("/events?event_type=PROCESS_START")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_stats_api_endpoint():
    """Verify /events/stats returns telemetry stats and baseline summary."""
    client = TestClient(app)
    response = client.get("/events/stats")
    assert response.status_code == 200
    data = response.json()
    assert "counts_by_type" in data
    assert "total_stored_events" in data
    assert "baseline_summary" in data
