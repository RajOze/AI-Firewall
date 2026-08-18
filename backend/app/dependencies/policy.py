"""FastAPI dependency providers for Policy Engine & Autonomous Enforcer."""
from functools import lru_cache
from fastapi import Depends

from app.dependencies.firewall import get_firewall_service
from app.firewall.service import FirewallService
from backend.policy.engine import PolicyEngine
from backend.policy.enforcer import AutonomousEnforcer
from backend.policy.models import PolicyConfig


@lru_cache()
def get_policy_engine() -> PolicyEngine:
    """Return a cached singleton instance of PolicyEngine."""
    return PolicyEngine(config=PolicyConfig())


def get_autonomous_enforcer(
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    firewall_service: FirewallService = Depends(get_firewall_service),
) -> AutonomousEnforcer:
    """Return AutonomousEnforcer configured with policy engine and firewall service."""
    return AutonomousEnforcer(policy_engine=policy_engine, firewall_service=firewall_service)
