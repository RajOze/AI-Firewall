"""Deterministic Risk Fusion Engine for Phase 2 Behavioral Threat Integration."""

from dataclasses import dataclass, field
from typing import Any

from backend.security.anomaly import AnomalyResult
from backend.security.behavioral_models import BehavioralEvent
from backend.security.models import ProcessInfo


@dataclass
class RiskFusionResult:
    """Unified risk assessment output from RiskFusionEngine.

    Attributes:
        risk_score: Normalized threat score clamped between 0.0 (safe) and 1.0 (critical threat).
        risk_level: Rating category ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        confidence: Combined confidence score (0.0 to 1.0).
        recommendation: Enforcement recommendation ('Allow', 'Monitor', 'Warn', 'Block').
        anomaly_score: Component anomaly score.
        process_risk: Component process risk score.
        network_risk: Component network risk score.
        reason_codes: Aggregated explainable reason codes.
        explainable_payload: Structured JSON-serializable dictionary.
    """

    risk_score: float
    risk_level: str
    confidence: float
    recommendation: str
    anomaly_score: float
    process_risk: float
    network_risk: float
    reason_codes: list[str] = field(default_factory=list)
    explainable_payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert risk fusion result to an explainable JSON dictionary representation."""
        return {
            "anomaly_score": round(self.anomaly_score, 2),
            "confidence": round(self.confidence, 2),
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "recommendation": self.recommendation,
            "reason_codes": self.reason_codes,
            "explainable_payload": self.explainable_payload,
        }


class RiskFusionEngine:
    """Fuses anomaly scores, process risk, and network risk into an explainable Threat Assessment."""

    HIGH_RISK_PORTS = {22, 23, 135, 139, 445, 3389, 4444, 6667, 8080}

    def fuse(
        self,
        anomaly_result: AnomalyResult,
        event: BehavioralEvent,
        process_info: ProcessInfo | None = None,
    ) -> RiskFusionResult:
        """Fuse inputs deterministically into a RiskFusionResult."""
        reason_codes = list(anomaly_result.reason_codes)

        # 1. Process Risk Score (0.0 to 1.0)
        p_risk = 0.0
        if process_info:
            if process_info.is_signed is False:
                p_risk += 0.35
                reason_codes.append("UNSIGNED_EXECUTABLE")
            if not process_info.publisher:
                p_risk += 0.20
                reason_codes.append("UNKNOWN_PUBLISHER")
            if process_info.is_elevated:
                p_risk += 0.15
                reason_codes.append("ELEVATED_PROCESS")
            if process_info.access_denied:
                p_risk += 0.15
                reason_codes.append("RESTRICTED_ACCESS_PROCESS")

        p_risk = min(1.0, max(0.0, p_risk))

        # 2. Network Risk Score (0.0 to 1.0)
        n_risk = 0.0
        if event.remote_port and event.remote_port in self.HIGH_RISK_PORTS:
            n_risk += 0.30
            reason_codes.append("SUSPICIOUS_PORT")

        n_risk = min(1.0, max(0.0, n_risk))

        # 3. Weighted Deterministic Risk Score (40% Anomaly, 35% Process, 25% Network)
        a_score = anomaly_result.anomaly_score
        weighted_risk = (0.40 * a_score) + (0.35 * p_risk) + (0.25 * n_risk)
        risk_score = min(1.0, max(0.0, weighted_risk))

        # 4. Risk Level & Recommendation (Phase 2 operates in OBSERVATION / SCORING mode)
        if risk_score >= 0.75:
            risk_level = "CRITICAL"
            recommendation = "Warn"
        elif risk_score >= 0.50:
            risk_level = "HIGH"
            recommendation = "Warn"
        elif risk_score >= 0.25:
            risk_level = "MEDIUM"
            recommendation = "Monitor"
        else:
            risk_level = "LOW"
            recommendation = "Allow"

        # Unique reason codes
        unique_reasons = list(dict.fromkeys(reason_codes))

        explainable_payload = {
            "component_scores": {
                "anomaly_score": round(a_score, 2),
                "process_risk": round(p_risk, 2),
                "network_risk": round(n_risk, 2),
            },
            "process_name": event.process_name,
            "remote_target": f"{event.remote_ip or '*'}:{event.remote_port or 0}",
        }

        return RiskFusionResult(
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            confidence=anomaly_result.confidence,
            recommendation=recommendation,
            anomaly_score=round(a_score, 2),
            process_risk=round(p_risk, 2),
            network_risk=round(n_risk, 2),
            reason_codes=unique_reasons,
            explainable_payload=explainable_payload,
        )
