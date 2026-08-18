"""Unit tests for AI Advisory REST API endpoints and isolation invariants."""
from unittest.mock import AsyncMock
import pytest
from starlette.testclient import TestClient

from backend.ai.providers.base import ProviderHealth, ProviderStatus
from backend.ai.router import AIRouter
from backend.ai.schemas import AdvisoryAction, ThreatAdvisory, ThreatSeverity
from backend.app.dependencies.ai import get_ai_router
from backend.app.main import app

client = TestClient(app)


def test_get_providers_health_endpoint():
    """Verify GET /api/v1/ai/providers/health returns valid diagnostics."""
    response = client.get("/api/v1/ai/providers/health")
    assert response.status_code == 200
    data = response.json()
    assert "local-heuristic:deterministic-v1" in data
    assert data["local-heuristic:deterministic-v1"]["status"] == "ONLINE"


def test_evaluate_threat_advisory_endpoint_fallback():
    """Verify POST /api/v1/ai/advisory/evaluate generates deterministic advisory via fallback."""
    payload = {
        "process_name": "cmd.exe",
        "process_id": 4321,
        "destination_ip": "198.51.100.22",
        "destination_port": 4444,
        "protocol": "TCP",
        "fusion_risk_score": 85.0,
        "max_z_score": 6.5,
        "anomaly_score": 0.8,
        "behavior_findings": ["BEACON_BURST_DETECTED"],
    }
    response = client.post("/api/v1/ai/advisory/evaluate?force_fallback=true", json=payload)
    assert response.status_code == 200
    advisory = response.json()
    assert advisory["process_name"] == "cmd.exe"
    assert advisory["severity"] == ThreatSeverity.CRITICAL.value
    assert advisory["recommended_action"] == AdvisoryAction.BLOCK_RECOMMENDED.value
    assert advisory["is_advisory_only"] is True
    assert advisory["is_fallback"] is True


def test_evaluate_threat_advisory_dependency_override():
    """Verify AIRouter dependency override functions properly in test harnesses."""
    mock_router = AsyncMock(spec=AIRouter)
    mock_advisory = ThreatAdvisory(
        process_name="notepad.exe",
        severity=ThreatSeverity.INFORMATIONAL,
        confidence_score=0.99,
        recommended_action=AdvisoryAction.ALLOW,
        summary="Benign editor activity.",
        detailed_reasoning="Normal baseline metrics.",
        provider_name="mock-ai-provider",
        inference_latency_ms=1.5,
        is_fallback=False,
    )
    mock_router.analyze_threat.return_value = mock_advisory
    app.dependency_overrides[get_ai_router] = lambda: mock_router

    try:
        payload = {"process_name": "notepad.exe"}
        response = client.post("/api/v1/ai/advisory/evaluate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["provider_name"] == "mock-ai-provider"
        assert data["severity"] == "INFORMATIONAL"
        assert data["recommended_action"] == "ALLOW"
    finally:
        app.dependency_overrides.pop(get_ai_router, None)


def test_advisory_api_strict_isolation_invariant():
    """Verify that the AI Advisory endpoint is purely advisory and contains no OS mutation execution handles."""
    import inspect
    from backend.app.api import advisory

    source = inspect.getsource(advisory)
    assert "add_rule" not in source
    assert "remove_rule" not in source
    assert "subprocess" not in source
    assert "powershell" not in source
