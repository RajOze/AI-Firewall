"""Unit tests for TelemetryService and telemetry API routes."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from app.dependencies.telemetry import get_telemetry_service
from app.main import app
from app.schemas.events import ConnectionDirection, NetworkConnectionEvent, ProcessStartEvent
from app.telemetry.service import TelemetryService
from database.repositories.event_repository import EventRepository


@pytest.fixture
def fake_telemetry_service():
    """Fixture producing a TelemetryService with a pre-populated repository."""
    repo = EventRepository()
    repo.add_event(
        ProcessStartEvent(
            process_id=999,
            process_name="test_runner.exe",
            executable_path="C:\\Test\\test_runner.exe",
            command_line=["test_runner.exe"],
        )
    )
    repo.add_event(
        NetworkConnectionEvent(
            process_id=999,
            process_name="test_runner.exe",
            local_address="127.0.0.1",
            local_port=5000,
            remote_address="1.1.1.1",
            remote_port=53,
            protocol="UDP",
            direction=ConnectionDirection.OUTBOUND,
            connection_state="ESTABLISHED",
        )
    )

    mock_proc_mon = MagicMock()
    mock_proc_mon.poll.return_value = []
    mock_net_mon = MagicMock()
    mock_net_mon.poll.return_value = []

    service = TelemetryService(
        repository=repo,
        process_monitor=mock_proc_mon,
        network_monitor=mock_net_mon,
        poll_interval_seconds=1.0,
    )
    return service


def test_telemetry_service_poll_once(fake_telemetry_service: TelemetryService) -> None:
    """Verify poll_once calls monitors and updates repository."""
    collected = fake_telemetry_service.poll_once()
    assert isinstance(collected, list)
    fake_telemetry_service.process_monitor.poll.assert_called_once()
    fake_telemetry_service.network_monitor.poll.assert_called_once()


def test_get_events_api_endpoint(fake_telemetry_service: TelemetryService) -> None:
    """Verify GET /events returns stored normalized events."""
    app.dependency_overrides[get_telemetry_service] = lambda: fake_telemetry_service

    with TestClient(app) as client:
        response = client.get("/events/")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        pids = [item["process_id"] for item in data if "process_id" in item]
        assert pids == [999, 999]

    app.dependency_overrides.clear()


def test_get_events_api_filter_by_type(fake_telemetry_service: TelemetryService) -> None:
    """Verify GET /events with event_type query parameter."""
    app.dependency_overrides[get_telemetry_service] = lambda: fake_telemetry_service

    with TestClient(app) as client:
        response = client.get("/events/?event_type=PROCESS_START")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["event_type"] == "PROCESS_START"
        assert data[0]["process_name"] == "test_runner.exe"

    app.dependency_overrides.clear()


def test_get_stats_api_endpoint(fake_telemetry_service: TelemetryService) -> None:
    """Verify GET /events/stats returns telemetry repository stats."""
    app.dependency_overrides[get_telemetry_service] = lambda: fake_telemetry_service

    with TestClient(app) as client:
        response = client.get("/events/stats")
        assert response.status_code == 200
        stats = response.json()
        assert stats["total_stored_events"] == 2
        assert "counts_by_type" in stats
        assert stats["worker_running"] is False

    app.dependency_overrides.clear()
