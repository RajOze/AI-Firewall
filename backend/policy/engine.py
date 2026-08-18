"""Deterministic Policy Engine evaluating Threat Advisories against security rules."""
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
