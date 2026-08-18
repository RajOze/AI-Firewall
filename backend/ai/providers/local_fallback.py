"""Local Fallback Provider for offline resilience and deterministic threat reasoning."""
import time
from typing import Any

from backend.ai.providers.base import BaseAIProvider, ProviderHealth, ProviderStatus
from backend.ai.schemas import (
    AdvisoryAction,
    MITRETechnique,
    ThreatAdvisory,
    ThreatEvidence,
    ThreatSeverity,
)


class LocalFallbackProvider(BaseAIProvider):
    @property
    def provider_name(self) -> str:
        return "local-heuristic:deterministic-v1"

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(
            provider_name=self.provider_name,
            status=ProviderStatus.ONLINE,
            latency_ms=0.1,
            message="Local fallback engine ready",
        )

    async def generate_advisory(self, context: dict[str, Any]) -> ThreatAdvisory:
        start = time.perf_counter()

        fusion_score = float(context.get("fusion_risk_score", 0.0))
        anomaly_score = float(context.get("anomaly_score", 0.0))
        max_z_score = float(context.get("max_z_score", 0.0))
        reputation_score = float(context.get("reputation_score", 0.0))
        findings = context.get("behavior_findings", [])
        process_name = context.get("process_name", "unknown.exe")
        dest_ip = context.get("destination_ip")
        dest_port = context.get("destination_port")
        protocol = context.get("protocol", "TCP")

        evidence: list[ThreatEvidence] = []
        mitre_mappings: list[MITRETechnique] = []

        if max_z_score >= 3.0:
            evidence.append(
                ThreatEvidence(
                    source="baseline_z_score",
                    metric_name="max_behavioral_z_score",
                    observed_value=round(max_z_score, 2),
                    threshold_or_baseline=3.0,
                    anomaly_contribution=min(1.0, max_z_score / 10.0),
                )
            )

        if anomaly_score > 0.5:
            evidence.append(
                ThreatEvidence(
                    source="anomaly_forest",
                    metric_name="isolation_forest_score",
                    observed_value=round(anomaly_score, 3),
                    threshold_or_baseline=0.5,
                    anomaly_contribution=anomaly_score,
                )
            )

        for finding in findings:
            finding_str = str(finding)
            evidence.append(
                ThreatEvidence(
                    source="rule_engine",
                    metric_name="behavior_finding",
                    observed_value=finding_str,
                    anomaly_contribution=0.7,
                )
            )
            if "BEACON" in finding_str.upper():
                mitre_mappings.append(
                    MITRETechnique(
                        technique_id="T1071.001",
                        technique_name="Web Protocols: Regular C2 Beaconing",
                        tactic="Command and Control",
                        reference_url="https://attack.mitre.org/techniques/T1071/001/",
                    )
                )
            elif "PORT_SCAN" in finding_str.upper() or "EXPLOSION" in finding_str.upper():
                mitre_mappings.append(
                    MITRETechnique(
                        technique_id="T1046",
                        technique_name="Network Service Discovery",
                        tactic="Discovery",
                        reference_url="https://attack.mitre.org/techniques/T1046/",
                    )
                )

        if fusion_score >= 80.0 or max_z_score >= 6.0:
            severity = ThreatSeverity.CRITICAL
            recommended_action = AdvisoryAction.BLOCK_RECOMMENDED
            confidence = 0.92
            summary = f"Critical behavioral anomaly detected for {process_name} exhibiting extreme baseline deviation."
        elif fusion_score >= 60.0 or max_z_score >= 4.0:
            severity = ThreatSeverity.HIGH
            recommended_action = AdvisoryAction.BLOCK_RECOMMENDED
            confidence = 0.85
            summary = f"High threat probability for {process_name} connecting to {dest_ip}:{dest_port}."
        elif fusion_score >= 35.0 or max_z_score >= 3.0:
            severity = ThreatSeverity.MEDIUM
            recommended_action = AdvisoryAction.ALERT
            confidence = 0.75
            summary = f"Suspicious network pattern identified for {process_name}. Elevated risk score {fusion_score:.1f}."
        elif fusion_score >= 15.0:
            severity = ThreatSeverity.LOW
            recommended_action = AdvisoryAction.MONITOR
            confidence = 0.70
            summary = f"Minor statistical divergence observed for {process_name}; continued monitoring recommended."
        else:
            severity = ThreatSeverity.INFORMATIONAL
            recommended_action = AdvisoryAction.ALLOW
            confidence = 0.95
            summary = f"Routine network activity for {process_name} within expected parameters."

        detailed_reasoning = (
            f"Deterministic offline analysis evaluated process '{process_name}' "
            f"targeting {dest_ip}:{dest_port} ({protocol}). "
            f"Metrics: RiskFusion={fusion_score:.1f}/100, AnomalyScore={anomaly_score:.2f}, "
            f"MaxZScore={max_z_score:.2f}, Reputation={reputation_score:.1f}."
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return ThreatAdvisory(
            process_name=process_name,
            process_id=context.get("process_id"),
            destination_ip=dest_ip,
            destination_port=dest_port,
            protocol=protocol,
            severity=severity,
            confidence_score=confidence,
            recommended_action=recommended_action,
            summary=summary,
            detailed_reasoning=detailed_reasoning,
            mitre_mappings=mitre_mappings,
            evidence=evidence,
            provider_name=self.provider_name,
            inference_latency_ms=round(elapsed_ms, 2),
            is_fallback=True,
            is_advisory_only=True,
        )
