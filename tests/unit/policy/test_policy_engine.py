"""Unit tests for PolicyEngine, Whitelist Guardrails, and AutonomousEnforcer."""
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
