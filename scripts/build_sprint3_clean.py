import os
from pathlib import Path

files = {}

# 1. backend/policy/models.py
files['backend/policy/models.py'] = '''"""Pydantic schemas for Policy Engine configuration and deterministic decisions."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from pydantic import BaseModel, Field

from backend.ai.schemas import ThreatSeverity


class EnforcementMode(str, Enum):
    """Operational enforcement level for firewall mutations."""
    MANUAL = "MANUAL"                   # Strictly audit; all actions require manual admin trigger
    SEMI_AUTOMATIC = "SEMI_AUTOMATIC"   # Auto-alerts created; mutations queued for approval
    FULL_AUTONOMOUS = "FULL_AUTONOMOUS" # Critical/High threats meeting threshold are blocked immediately


class PolicyAction(str, Enum):
    """Deterministic policy actions."""
    ENFORCE_BLOCK = "ENFORCE_BLOCK"
    QUEUE_FOR_APPROVAL = "QUEUE_FOR_APPROVAL"
    MONITOR_ONLY = "MONITOR_ONLY"
    IGNORE_WHITELISTED = "IGNORE_WHITELISTED"
    RATE_LIMITED = "RATE_LIMITED"


class PolicyConfig(BaseModel):
    """Configuration settings for deterministic policy evaluation."""
    enforcement_mode: EnforcementMode = Field(
        default=EnforcementMode.FULL_AUTONOMOUS,
        description="Global enforcement policy mode",
    )
    auto_block_min_severity: ThreatSeverity = Field(
        default=ThreatSeverity.HIGH,
        description="Minimum threat severity required for autonomous blocking",
    )
    auto_block_min_confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required for autonomous blocking",
    )
    max_blocks_per_minute: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Rate limit bounding maximum autonomous rule mutations per minute",
    )
    cooldown_period_sec: float = Field(
        default=60.0,
        ge=0.0,
        description="Cooldown window in seconds to prevent repetitive rule mutations on same target",
    )
    enable_system_whitelist: bool = Field(
        default=True,
        description="Safety invariant: always True to protect OS critical binaries",
    )


class PolicyDecision(BaseModel):
    """Deterministic evaluation outcome produced by the Policy Engine."""
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Target Context
    process_name: str = Field(description="Evaluated process name")
    process_id: int | None = Field(default=None, description="Operating system PID")
    destination_ip: str | None = Field(default=None, description="Destination IP")
    destination_port: int | None = Field(default=None, description="Destination Port")

    # Input Advisory Reference
    advisory_id: str | None = Field(default=None, description="ID of ThreatAdvisory that triggered evaluation")
    advisory_severity: ThreatSeverity = Field(description="Severity assessed by AI")
    advisory_confidence: float = Field(description="Confidence score assessed by AI")

    # Policy Result
    action: PolicyAction = Field(description="Deterministic policy action")
    reason: str = Field(description="Explanation of policy rule matching or safety guardrail trigger")
    is_blocked: bool = Field(default=False, description="True if firewall block mutation was enacted")
    mutation_rule_name: str | None = Field(default=None, description="Firewall rule name if created")
'''

# 2. backend/policy/whitelist.py
files['backend/policy/whitelist.py'] = '''"""System-critical process and network whitelist definitions."""
from typing import Final
import ipaddress

SYSTEM_CRITICAL_PROCESSES: Final[set[str]] = {
    "ntoskrnl.exe",
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "spoolsv.exe",
    "dwm.exe",
    "fontdrvhost.exe",
}

WHITELISTED_IPS: Final[set[str]] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


def is_system_critical_process(process_name: str | None) -> bool:
    """Check if process is an immutable Windows OS component."""
    if not process_name:
        return False
    clean_name = process_name.strip().lower()
    if clean_name.endswith(".exe"):
        clean_name = clean_name
    return clean_name in SYSTEM_CRITICAL_PROCESSES or f"{clean_name}.exe" in SYSTEM_CRITICAL_PROCESSES


def is_whitelisted_ip(ip_str: str | None) -> bool:
    """Check if IP address is loopback, local, or infrastructure whitelisted."""
    if not ip_str:
        return False
    ip_clean = ip_str.strip()
    if ip_clean in WHITELISTED_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        return ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified
    except ValueError:
        return False
'''

# 3. backend/policy/engine.py
files['backend/policy/engine.py'] = '''"""Deterministic Policy Engine evaluating Threat Advisories against security rules."""
from collections import deque
import logging
import time

from backend.ai.schemas import ThreatAdvisory, ThreatSeverity
from backend.policy.models import EnforcementMode, PolicyAction, PolicyConfig, PolicyDecision
from backend.policy.whitelist import is_system_critical_process, is_whitelisted_ip

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Evaluates ThreatAdvisories and enforces deterministic safety policies."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self._block_history: deque[float] = deque()
        self._cooldown_map: dict[str, float] = {}

    def _get_target_key(self, process_name: str, dest_ip: str | None, dest_port: int | None) -> str:
        return f"{process_name}:{dest_ip or '*'}:{dest_port or '*'}"

    def _check_rate_limit(self, now: float) -> bool:
        """Return True if under rate limit; False if rate limit exceeded."""
        one_min_ago = now - 60.0
        while self._block_history and self._block_history[0] < one_min_ago:
            self._block_history.popleft()
        return len(self._block_history) < self.config.max_blocks_per_minute

    def _check_cooldown(self, target_key: str, now: float) -> bool:
        """Return True if cooldown active (block should be skipped); False if cooldown expired."""
        last_block = self._cooldown_map.get(target_key)
        if last_block is not None and (now - last_block) < self.config.cooldown_period_sec:
            return True
        return False

    def evaluate_advisory(self, advisory: ThreatAdvisory) -> PolicyDecision:
        """Evaluate a ThreatAdvisory and produce a deterministic PolicyDecision."""
        now = time.time()
        process_name = advisory.process_name
        dest_ip = advisory.destination_ip
        dest_port = advisory.destination_port
        target_key = self._get_target_key(process_name, dest_ip, dest_port)

        # 1. System Critical Process Guardrail
        if self.config.enable_system_whitelist and is_system_critical_process(process_name):
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.IGNORE_WHITELISTED,
                reason=f"Process '{process_name}' is protected by System Critical Whitelist.",
            )

        # 2. Whitelisted IP Guardrail
        if is_whitelisted_ip(dest_ip):
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.IGNORE_WHITELISTED,
                reason=f"Target IP '{dest_ip}' is protected by Network Whitelist.",
            )

        # 3. Severity Rank Assessment
        severity_ranks = {
            ThreatSeverity.INFORMATIONAL: 0,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        advisory_rank = severity_ranks.get(advisory.severity, 0)
        threshold_rank = severity_ranks.get(self.config.auto_block_min_severity, 3)

        meets_severity = advisory_rank >= threshold_rank
        meets_confidence = advisory.confidence_score >= self.config.auto_block_min_confidence

        if not (meets_severity and meets_confidence):
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.MONITOR_ONLY,
                reason=(
                    f"Threat does not meet auto-block threshold "
                    f"(Severity: {advisory.severity.value}/{self.config.auto_block_min_severity.value}, "
                    f"Confidence: {advisory.confidence_score:.2f}/{self.config.auto_block_min_confidence:.2f})."
                ),
            )

        # 4. Handle Policy Modes
        if self.config.enforcement_mode == EnforcementMode.MANUAL:
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.MONITOR_ONLY,
                reason="Policy mode is MANUAL; automated firewall mutations disabled.",
            )

        if self.config.enforcement_mode == EnforcementMode.SEMI_AUTOMATIC:
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.QUEUE_FOR_APPROVAL,
                reason="Policy mode is SEMI_AUTOMATIC; mutation queued for admin approval.",
            )

        # 5. Full Autonomous Mode: Cooldown & Rate Limit Guards
        if self._check_cooldown(target_key, now):
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.RATE_LIMITED,
                reason=f"Target '{target_key}' is in cooldown window.",
            )

        if not self._check_rate_limit(now):
            return PolicyDecision(
                process_name=process_name,
                process_id=advisory.process_id,
                destination_ip=dest_ip,
                destination_port=dest_port,
                advisory_id=advisory.advisory_id,
                advisory_severity=advisory.severity,
                advisory_confidence=advisory.confidence_score,
                action=PolicyAction.RATE_LIMITED,
                reason=f"Rate limit of {self.config.max_blocks_per_minute} mutations/min exceeded.",
            )

        # Passed all guardrails -> ENFORCE_BLOCK
        self._block_history.append(now)
        self._cooldown_map[target_key] = now

        return PolicyDecision(
            process_name=process_name,
            process_id=advisory.process_id,
            destination_ip=dest_ip,
            destination_port=dest_port,
            advisory_id=advisory.advisory_id,
            advisory_severity=advisory.severity,
            advisory_confidence=advisory.confidence_score,
            action=PolicyAction.ENFORCE_BLOCK,
            reason=(
                f"Autonomous block criteria satisfied (Severity: {advisory.severity.value}, "
                f"Confidence: {advisory.confidence_score:.2f})."
            ),
        )
'''

# 4. backend/policy/enforcer.py
files['backend/policy/enforcer.py'] = '''"""Autonomous Enforcer executing deterministic policy decisions on the Firewall."""
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
'''

# 5. backend/policy/__init__.py
files['backend/policy/__init__.py'] = '''"""Deterministic Policy Engine & Autonomous Enforcement Package."""
from backend.policy.engine import PolicyEngine
from backend.policy.enforcer import AutonomousEnforcer
from backend.policy.models import EnforcementMode, PolicyAction, PolicyConfig, PolicyDecision
from backend.policy.whitelist import is_system_critical_process, is_whitelisted_ip

__all__ = [
    "PolicyEngine",
    "AutonomousEnforcer",
    "PolicyConfig",
    "PolicyDecision",
    "EnforcementMode",
    "PolicyAction",
    "is_system_critical_process",
    "is_whitelisted_ip",
]
'''

# 6. backend/app/dependencies/policy.py
files['backend/app/dependencies/policy.py'] = '''"""FastAPI dependency providers for Policy Engine & Autonomous Enforcer."""
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
'''

# 7. backend/app/api/policy.py
files['backend/app/api/policy.py'] = '''"""Policy Configuration & Autonomous Enforcement API Endpoints."""
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
'''

# 8. tests/unit/policy/__init__.py
files['tests/unit/policy/__init__.py'] = ''

# 9. tests/unit/policy/test_policy_engine.py
files['tests/unit/policy/test_policy_engine.py'] = '''"""Unit tests for PolicyEngine, Whitelist Guardrails, and AutonomousEnforcer."""
from unittest.mock import MagicMock
import pytest

from app.firewall.service import FirewallService
from backend.ai.schemas import AdvisoryAction, ThreatAdvisory, ThreatSeverity
from backend.policy.engine import PolicyEngine
from backend.policy.enforcer import AutonomousEnforcer
from backend.policy.models import EnforcementMode, PolicyAction, PolicyConfig
from backend.policy.whitelist import is_system_critical_process, is_whitelisted_ip


def test_whitelist_detection_system_critical():
    assert is_system_critical_process("svchost.exe") is True
    assert is_system_critical_process("csrss.exe") is True
    assert is_system_critical_process("SYSTEM") is True
    assert is_system_critical_process("malware.exe") is False


def test_whitelist_detection_ip_and_loopback():
    assert is_whitelisted_ip("127.0.0.1") is True
    assert is_whitelisted_ip("::1") is True
    assert is_whitelisted_ip("198.51.100.1") is False


def test_policy_engine_protects_system_critical_process():
    engine = PolicyEngine()
    advisory = ThreatAdvisory(
        process_name="svchost.exe",
        severity=ThreatSeverity.CRITICAL,
        confidence_score=1.0,
        recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
        summary="C2 attack vector",
        detailed_reasoning="Critical anomaly",
        provider_name="test",
        inference_latency_ms=1.0,
    )
    decision = engine.evaluate_advisory(advisory)
    assert decision.action == PolicyAction.IGNORE_WHITELISTED
    assert decision.is_blocked is False
    assert "System Critical Whitelist" in decision.reason


def test_policy_engine_protects_whitelisted_ip():
    engine = PolicyEngine()
    advisory = ThreatAdvisory(
        process_name="unknown_malware.exe",
        destination_ip="127.0.0.1",
        severity=ThreatSeverity.CRITICAL,
        confidence_score=0.99,
        recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
        summary="Local connection",
        detailed_reasoning="Anomaly",
        provider_name="test",
        inference_latency_ms=1.0,
    )
    decision = engine.evaluate_advisory(advisory)
    assert decision.action == PolicyAction.IGNORE_WHITELISTED
    assert decision.is_blocked is False


def test_policy_engine_full_autonomous_block_success():
    engine = PolicyEngine(config=PolicyConfig(enforcement_mode=EnforcementMode.FULL_AUTONOMOUS))
    advisory = ThreatAdvisory(
        process_name="ransomware.exe",
        destination_ip="185.220.101.5",
        destination_port=4444,
        severity=ThreatSeverity.HIGH,
        confidence_score=0.92,
        recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
        summary="Ransomware C2 beacon",
        detailed_reasoning="Baseline max z-score exceeded",
        provider_name="gemini",
        inference_latency_ms=10.0,
    )
    decision = engine.evaluate_advisory(advisory)
    assert decision.action == PolicyAction.ENFORCE_BLOCK


def test_policy_engine_semi_automatic_mode_queues_for_approval():
    engine = PolicyEngine(config=PolicyConfig(enforcement_mode=EnforcementMode.SEMI_AUTOMATIC))
    advisory = ThreatAdvisory(
        process_name="cryptominer.exe",
        destination_ip="198.51.100.55",
        severity=ThreatSeverity.CRITICAL,
        confidence_score=0.95,
        recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
        summary="Cryptominer pool connection",
        detailed_reasoning="Mining signature",
        provider_name="local",
        inference_latency_ms=2.0,
    )
    decision = engine.evaluate_advisory(advisory)
    assert decision.action == PolicyAction.QUEUE_FOR_APPROVAL
    assert decision.is_blocked is False


def test_policy_engine_cooldown_and_rate_limiting():
    engine = PolicyEngine(config=PolicyConfig(max_blocks_per_minute=2, cooldown_period_sec=10.0))
    advisory = ThreatAdvisory(
        process_name="scanner.exe",
        destination_ip="203.0.113.1",
        severity=ThreatSeverity.CRITICAL,
        confidence_score=0.95,
        recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
        summary="Scan detected",
        detailed_reasoning="Rapid syn flood",
        provider_name="test",
        inference_latency_ms=1.0,
    )

    decision_1 = engine.evaluate_advisory(advisory)
    assert decision_1.action == PolicyAction.ENFORCE_BLOCK

    decision_2 = engine.evaluate_advisory(advisory)
    assert decision_2.action == PolicyAction.RATE_LIMITED
    assert "cooldown" in decision_2.reason


@pytest.mark.anyio
async def test_autonomous_enforcer_executes_firewall_rule():
    mock_firewall = MagicMock(spec=FirewallService)
    engine = PolicyEngine(config=PolicyConfig(enforcement_mode=EnforcementMode.FULL_AUTONOMOUS))
    enforcer = AutonomousEnforcer(policy_engine=engine, firewall_service=mock_firewall)

    advisory = ThreatAdvisory(
        process_name="bad_actor.exe",
        destination_ip="198.51.100.99",
        destination_port=9001,
        severity=ThreatSeverity.CRITICAL,
        confidence_score=0.99,
        recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
        summary="Active infiltration",
        detailed_reasoning="Z-Score 8.0",
        provider_name="test",
        inference_latency_ms=2.0,
    )

    decision = await enforcer.evaluate_and_enforce(advisory)
    assert decision.is_blocked is True
    assert decision.mutation_rule_name is not None
    assert decision.mutation_rule_name.startswith("AI-Firewall-Block-bad_actor.exe")
    assert mock_firewall.add_rule.called
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully wrote: {rel_path}')

# Register policy_router in backend/app/main.py cleanly
main_py_path = Path("backend/app/main.py")
if main_py_path.exists():
    main_code = main_py_path.read_text(encoding="utf-8-sig").replace("\ufeff", "")
    if "from backend.app.api.policy import router as policy_router" not in main_code:
        main_code = "from backend.app.api.policy import router as policy_router\n" + main_code
    if "app.include_router(policy_router)" not in main_code:
        main_code += "\napp.include_router(policy_router)\n"
    main_py_path.write_text(main_code, encoding="utf-8")
    print("Successfully registered policy_router in backend/app/main.py")
