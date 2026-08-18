"""Autonomous Enforcer executing deterministic policy decisions on the Firewall."""
import hashlib
import logging
from typing import Any

from app.firewall.models import FirewallAction, FirewallDirection, FirewallRule
from app.firewall.service import FirewallService
from backend.ai.schemas import ThreatAdvisory
from backend.policy.engine import PolicyEngine
from backend.policy.models import PolicyAction, PolicyDecision

logger = logging.getLogger(__name__)


class AutonomousEnforcer:
    """Bridges PolicyEngine decisions with FirewallService rule creation."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        firewall_service: FirewallService,
    ) -> None:
        self.policy_engine = policy_engine
        self.firewall_service = firewall_service

    def _generate_rule_name(self, decision: PolicyDecision) -> str:
        """Generate safe, deterministic, namespaced rule name."""
        seed = f"{decision.process_name}:{decision.destination_ip}:{decision.destination_port}"
        hash_suffix = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
        port_part = f"-{decision.destination_port}" if decision.destination_port else ""
        return f"AI-Firewall-Block-{decision.process_name}{port_part}-{hash_suffix}"

    async def evaluate_and_enforce(self, advisory: ThreatAdvisory) -> PolicyDecision:
        """Evaluate advisory and execute firewall block if mandated by policy."""
        decision = self.policy_engine.evaluate_advisory(advisory)

        if decision.action == PolicyAction.ENFORCE_BLOCK:
            rule_name = self._generate_rule_name(decision)
            rule = FirewallRule(
                name=rule_name,
                direction=FirewallDirection.OUTBOUND,
                action=FirewallAction.BLOCK,
                remote_address=decision.destination_ip,
                description=f"Autonomous block triggered by {advisory.provider_name}. Reason: {advisory.summary}",
            )
            try:
                self.firewall_service.add_rule(rule)
                decision.is_blocked = True
                decision.mutation_rule_name = rule_name
                logger.info("Successfully enforced autonomous firewall block rule: %s", rule_name)
            except Exception as exc:
                logger.error("Failed to enforce firewall rule %s: %s", rule_name, exc)
                decision.is_blocked = False
                decision.reason += f" (Firewall enforcement failed: {exc})"

        return decision
