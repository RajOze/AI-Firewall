"""Policy Configuration & Autonomous Enforcement API Endpoints."""
from fastapi import APIRouter, Depends

from backend.ai.schemas import ThreatAdvisory
from backend.app.dependencies.policy import get_autonomous_enforcer, get_policy_engine
from backend.policy.engine import PolicyEngine
from backend.policy.enforcer import AutonomousEnforcer
from backend.policy.models import PolicyConfig, PolicyDecision

router = APIRouter(prefix="/api/v1/policy", tags=["Policy Engine"])


@router.get("/config", response_model=PolicyConfig)
def get_policy_configuration(
    engine: PolicyEngine = Depends(get_policy_engine),
) -> PolicyConfig:
    """Retrieve active deterministic policy configuration."""
    return engine.config


@router.put("/config", response_model=PolicyConfig)
def update_policy_configuration(
    new_config: PolicyConfig,
    engine: PolicyEngine = Depends(get_policy_engine),
) -> PolicyConfig:
    """Update policy enforcement thresholds and modes."""
    engine.config = new_config
    return engine.config


@router.post("/evaluate-and-enforce", response_model=PolicyDecision)
async def evaluate_and_enforce_advisory(
    advisory: ThreatAdvisory,
    enforcer: AutonomousEnforcer = Depends(get_autonomous_enforcer),
) -> PolicyDecision:
    """Evaluate ThreatAdvisory through Policy Engine and enforce firewall mutation if warranted."""
    return await enforcer.evaluate_and_enforce(advisory)
