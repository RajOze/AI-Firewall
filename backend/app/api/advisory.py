"""Advisory Threat Reasoning API Endpoints.

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
