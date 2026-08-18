import os
import re
from pathlib import Path

files = {}

# 1. backend/app/dependencies/ai.py
files['backend/app/dependencies/ai.py'] = '''"""FastAPI dependency provider for AIRouter."""
from functools import lru_cache

from backend.ai.router import AIRouter


@lru_cache()
def get_ai_router() -> AIRouter:
    """Return a cached singleton instance of AIRouter."""
    return AIRouter()
'''

# 2. backend/app/api/advisory.py
files['backend/app/api/advisory.py'] = '''"""Advisory Threat Reasoning API Endpoints.

Provides advisory-only threat intelligence and provider health status.
Guarantees strict data isolation: endpoints never invoke firewall mutation actions.
"""
from typing import Any
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from backend.ai.providers.base import ProviderHealth
from backend.ai.router import AIRouter
from backend.ai.schemas import ThreatAdvisory
from backend.app.dependencies.ai import get_ai_router

router = APIRouter(prefix="/api/v1/ai", tags=["AI Advisory"])


class ThreatEvaluationRequest(BaseModel):
    """Payload schema for requesting an AI threat advisory evaluation."""
    process_name: str = Field(..., min_length=1, description="Binary or process name under evaluation")
    process_id: int | None = Field(default=None, description="Process ID if available")
    destination_ip: str | None = Field(default=None, description="Remote destination IP")
    destination_port: int | None = Field(default=None, ge=1, le=65535, description="Remote destination port")
    protocol: str = Field(default="TCP", description="Network protocol")
    fusion_risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Compound behavioral risk score")
    max_z_score: float = Field(default=0.0, ge=0.0, description="Maximum statistical baseline z-score")
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Isolation Forest anomaly score")
    reputation_score: float = Field(default=50.0, ge=0.0, le=100.0, description="Process reputation score")
    behavior_findings: list[str] = Field(default_factory=list, description="Heuristic behavioral rule triggers")
    extra_context: dict[str, Any] = Field(default_factory=dict, description="Supplementary telemetry context")


@router.get("/providers/health", response_model=dict[str, ProviderHealth])
async def get_providers_health(
    router_service: AIRouter = Depends(get_ai_router),
) -> dict[str, ProviderHealth]:
    """Retrieve operational readiness and latency diagnostics for all AI providers."""
    return await router_service.get_providers_health()


@router.post("/advisory/evaluate", response_model=ThreatAdvisory)
async def evaluate_threat_advisory(
    request: ThreatEvaluationRequest,
    force_fallback: bool = Query(default=False, description="Force deterministic offline fallback engine"),
    router_service: AIRouter = Depends(get_ai_router),
) -> ThreatAdvisory:
    """Analyze behavioral telemetry and return an immutable structured ThreatAdvisory."""
    context = request.model_dump()
    if request.extra_context:
        context.update(request.extra_context)
    return await router_service.analyze_threat(context=context, force_fallback=force_fallback)
'''

# 3. tests/unit/api/test_advisory_api.py
files['tests/unit/api/test_advisory_api.py'] = '''"""Unit tests for AI Advisory REST API endpoints and isolation invariants."""
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
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully wrote: {rel_path}')

# Update backend/app/main.py to include advisory_router
main_py_path = Path("backend/app/main.py")
if main_py_path.exists():
    main_code = main_py_path.read_text(encoding="utf-8")
    if "from backend.app.api.advisory import router as advisory_router" not in main_code:
        # Add import
        main_code = "from backend.app.api.advisory import router as advisory_router\n" + main_code
        # Add include_router
        if "app.include_router(advisory_router)" not in main_code:
            main_code += "\napp.include_router(advisory_router)\n"
        main_py_path.write_text(main_code, encoding="utf-8")
        print("Successfully registered advisory_router in backend/app/main.py")
    else:
        print("advisory_router is already registered in backend/app/main.py")
