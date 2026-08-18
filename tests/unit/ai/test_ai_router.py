"""Unit tests for AI Schemas, Providers, and AIRouter orchestration."""
import asyncio
import json
from unittest.mock import AsyncMock, patch
import pytest
import httpx

from backend.ai.providers.base import ProviderStatus
from backend.ai.providers.gemini_provider import GeminiFlashProvider
from backend.ai.providers.local_fallback import LocalFallbackProvider
from backend.ai.router import AIRouter
from backend.ai.schemas import (
    AdvisoryAction,
    MITRETechnique,
    ThreatAdvisory,
    ThreatEvidence,
    ThreatSeverity,
)


def test_threat_advisory_schema_defaults_and_validation():
    advisory = ThreatAdvisory(
        process_name="svchost.exe",
        destination_ip="1.1.1.1",
        destination_port=443,
        severity=ThreatSeverity.LOW,
        confidence_score=0.9,
        recommended_action=AdvisoryAction.ALLOW,
        summary="Standard HTTPS connection.",
        detailed_reasoning="Normal behavioral baseline observed.",
        provider_name="test-provider",
        inference_latency_ms=12.5,
    )
    assert advisory.is_advisory_only is True
    assert advisory.severity == ThreatSeverity.LOW
    assert len(advisory.advisory_id) > 0


def test_threat_advisory_guardrail_invariant():
    with pytest.raises(ValueError, match="Safety guardrail violation"):
        ThreatAdvisory(
            process_name="malware.exe",
            severity=ThreatSeverity.CRITICAL,
            confidence_score=1.0,
            recommended_action=AdvisoryAction.BLOCK_RECOMMENDED,
            summary="Attack detected",
            detailed_reasoning="Malicious payload",
            provider_name="test",
            inference_latency_ms=1.0,
            is_advisory_only=False,
        )


@pytest.mark.anyio
async def test_local_fallback_provider_heuristic_critical():
    provider = LocalFallbackProvider()
    context = {
        "process_name": "mimikatz.exe",
        "process_id": 9999,
        "destination_ip": "185.220.101.5",
        "destination_port": 4444,
        "protocol": "TCP",
        "fusion_risk_score": 88.5,
        "max_z_score": 7.2,
        "anomaly_score": 0.85,
        "behavior_findings": ["BEACON_DETECTED_INTERVAL_2S"],
    }

    advisory = await provider.generate_advisory(context)
    assert advisory.severity == ThreatSeverity.CRITICAL
    assert advisory.recommended_action == AdvisoryAction.BLOCK_RECOMMENDED
    assert advisory.is_fallback is True
    assert any(m.technique_id == "T1071.001" for m in advisory.mitre_mappings)
    assert len(advisory.evidence) >= 2


@pytest.mark.anyio
async def test_local_fallback_provider_heuristic_informational():
    provider = LocalFallbackProvider()
    context = {
        "process_name": "chrome.exe",
        "process_id": 1234,
        "destination_ip": "142.250.190.46",
        "destination_port": 443,
        "fusion_risk_score": 5.0,
        "max_z_score": 0.4,
    }
    advisory = await provider.generate_advisory(context)
    assert advisory.severity == ThreatSeverity.INFORMATIONAL
    assert advisory.recommended_action == AdvisoryAction.ALLOW


@pytest.mark.anyio
async def test_gemini_flash_provider_mocked_success():
    provider = GeminiFlashProvider(api_key="valid-test-key")

    mock_gemini_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "severity": "HIGH",
                                "confidence_score": 0.94,
                                "recommended_action": "BLOCK_RECOMMENDED",
                                "summary": "Unusual outbound beacon detected from PowerShell.",
                                "detailed_reasoning": "Connection frequency is 5 standard deviations above baseline.",
                                "mitre_mappings": [
                                    {
                                        "technique_id": "T1059.001",
                                        "technique_name": "PowerShell",
                                        "tactic": "Execution",
                                        "reference_url": "https://attack.mitre.org/techniques/T1059/001/"
                                    }
                                ],
                                "evidence": [
                                    {
                                        "source": "baseline_z_score",
                                        "metric_name": "frequency",
                                        "observed_value": 5.2,
                                        "threshold_or_baseline": 3.0,
                                        "anomaly_contribution": 0.8
                                    }
                                ]
                            })
                        }
                    ]
                }
            }
        ]
    }

    mock_resp = httpx.Response(status_code=200, json=mock_gemini_payload, request=httpx.Request("POST", "http://test"))

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        context = {
            "process_name": "powershell.exe",
            "destination_ip": "198.51.100.1",
            "destination_port": 8443,
        }
        advisory = await provider.generate_advisory(context)
        assert advisory.severity == ThreatSeverity.HIGH
        assert advisory.recommended_action == AdvisoryAction.BLOCK_RECOMMENDED
        assert advisory.is_fallback is False
        assert advisory.provider_name.startswith("gemini:")


@pytest.mark.anyio
async def test_ai_router_automatic_fallback_on_gemini_timeout():
    gemini_mock = AsyncMock(spec=GeminiFlashProvider)
    gemini_mock.provider_name = "gemini:gemini-2.5-flash"

    async def _hang(*args, **kwargs):
        await asyncio.sleep(2.0)

    gemini_mock.generate_advisory.side_effect = _hang

    router = AIRouter(primary_provider=gemini_mock, default_timeout_sec=0.1)

    context = {
        "process_name": "test_app.exe",
        "fusion_risk_score": 75.0,
        "max_z_score": 4.5,
    }

    advisory = await router.analyze_threat(context)
    assert advisory is not None
    assert advisory.is_fallback is True
    assert advisory.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)


@pytest.mark.anyio
async def test_ai_router_health_checks():
    router = AIRouter()
    health_map = await router.get_providers_health()
    assert "local-heuristic:deterministic-v1" in health_map
    assert health_map["local-heuristic:deterministic-v1"].status == ProviderStatus.ONLINE
