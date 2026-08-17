"""Specialized Network Risk Model for Phase 2 Sentinel AI Firewall (P2.5 / M3).

Evaluates network-specific security risk signals (destination novelty/diversity,
suspicious ports, unexpected protocols, failed connection rates, traffic anomalies,
and P2.4 anomaly inputs) to produce explainable, bounded NetworkRiskResult assessments.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

import joblib

from backend.security.anomaly import AnomalyResult
from backend.security.base_model import BaseSecurityModel, ModelOutput
from backend.security.baseline import BaselineDeviation, BehavioralRecord
from backend.security.behavioral_models import BehaviorStatus
from backend.security.features import FEATURE_VERSION, BehavioralFeatures, FeatureVector

NETWORK_RISK_MODEL_VERSION = "0.1.0"

# Standard known high-risk / malicious ports (C2, reconnaissance, lateral movement)
HIGH_RISK_PORTS: set[int] = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    135,   # MS RPC / EPMAP
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
    139,   # NetBIOS Session
    445,   # SMB / EternalBlue
    1433,  # MS SQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    4444,  # Metasploit Default Listener
    5900,  # VNC
    6667,  # IRC / Botnet C2
    8080,  # HTTP Alternate / Proxy
}


@dataclass
class NetworkRiskResult:
    """Standardized output assessment contract from NetworkRiskModel (P2.5).

    Attributes:
        model_name: Name of the specialized risk model.
        model_version: Semantic version of the network risk model.
        feature_version: Version identifier of the feature schema used.
        behavior_identity_key: Canonical unique behavior key of evaluated event.
        risk_score: Normalized security risk score clamped between 0.0 (benign) and 1.0 (critical danger).
        confidence: Independent certainty metric (0.0 to 1.0), decoupled from risk score.
        reason_codes: Evidence-based explainable reason codes.
        contributing_signals: Dictionary of individual normalized signal components.
        timestamp: Epoch timestamp of evaluation.
        details: Empirical feature values, ports, IPs, and decision rationale.
    """

    behavior_identity_key: str
    risk_score: float
    confidence: float
    model_name: str = "network_risk_model"
    model_version: str = NETWORK_RISK_MODEL_VERSION
    feature_version: str = FEATURE_VERSION
    reason_codes: list[str] = field(default_factory=list)
    contributing_signals: dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert NetworkRiskResult to a JSON-serializable dictionary representation."""
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "behavior_identity_key": self.behavior_identity_key,
            "risk_score": round(self.risk_score, 2),
            "confidence": round(self.confidence, 2),
            "reason_codes": self.reason_codes,
            "contributing_signals": {
                k: round(v, 4) for k, v in self.contributing_signals.items()
            },
            "timestamp": self.timestamp,
            "details": self.details,
        }

    def explainable_payload(self) -> dict[str, Any]:
        """Return structured, non-sensitive payload for explainability and alerting."""
        return {
            "behavior_identity_key": self.behavior_identity_key,
            "risk_score": round(self.risk_score, 2),
            "confidence": round(self.confidence, 2),
            "reason_codes": self.reason_codes,
            "top_signals": sorted(
                self.contributing_signals.items(), key=lambda x: x[1], reverse=True
            )[:4],
            "details": self.details,
        }


class NetworkRiskModel(BaseSecurityModel):
    """Specialized Network Risk Model for Phase 2 (P2.5).

    Evaluates network security risk deterministically based on empirical features,
    baseline deviations, and anomaly inputs with configurable signal weights.
    """

    def __init__(
        self,
        model_version: str = NETWORK_RISK_MODEL_VERSION,
        feature_version: str = FEATURE_VERSION,
        w_dest: float = 0.20,
        w_port: float = 0.20,
        w_proto: float = 0.10,
        w_freq: float = 0.15,
        w_failed: float = 0.10,
        w_traffic: float = 0.10,
        w_anomaly: float = 0.15,
        high_risk_ports: set[int] | None = None,
    ) -> None:
        super().__init__(
            model_name="network_risk_model",
            model_version=model_version,
            feature_version=feature_version,
        )
        self.w_dest = w_dest
        self.w_port = w_port
        self.w_proto = w_proto
        self.w_freq = w_freq
        self.w_failed = w_failed
        self.w_traffic = w_traffic
        self.w_anomaly = w_anomaly
        self.high_risk_ports = high_risk_ports or set(HIGH_RISK_PORTS)

    def evaluate(
        self,
        features: FeatureVector | BehavioralFeatures,
        baseline_deviation: BaselineDeviation | None = None,
        record: BehavioralRecord | None = None,
        anomaly_result: AnomalyResult | None = None,
    ) -> NetworkRiskResult:
        """Evaluate network security risk from features, baseline metrics, and anomaly outputs.

        Args:
            features: Extracted FeatureVector or BehavioralFeatures contract.
            baseline_deviation: Optional BaselineDeviation from BehavioralBaselineEngine.
            record: Optional BehavioralRecord baseline memory.
            anomaly_result: Optional AnomalyResult from P2.4 AnomalyDetectionEngine.

        Returns:
            Standardized, bounded NetworkRiskResult.
        """
        reason_codes: list[str] = []
        signals: dict[str, float] = {}
        details: dict[str, Any] = {}

        key = getattr(features, "behavior_key", "")
        fv_version = getattr(features, "feature_version", FEATURE_VERSION)

        # ---------------------------------------------------------------------
        # 1. SCHEMA VERSION COMPATIBILITY CHECK
        # ---------------------------------------------------------------------
        if fv_version != self.feature_version:
            reason_codes.append("FEATURE_VERSION_MISMATCH")
            details["feature_version_mismatch"] = {
                "model_feature_version": self.feature_version,
                "event_feature_version": fv_version,
            }

        # Safe extraction helper for feature values dictionary
        f_vals = features.values if hasattr(features, "values") else getattr(features, "raw_features", {})

        # ---------------------------------------------------------------------
        # 2. DESTINATION SIGNALS (Novelty + Diversity + Target IP)
        # ---------------------------------------------------------------------
        is_new_dest = float(f_vals.get("is_new_destination", 0.0))
        unique_dests = float(f_vals.get("unique_destinations_count", 1.0))

        dest_novelty_score = 0.50 if is_new_dest >= 0.5 else 0.0
        dest_diversity_score = min(1.0, max(0.0, (unique_dests - 1.0) / 15.0))

        if is_new_dest >= 0.5:
            reason_codes.append("NEW_DESTINATION")
        if unique_dests >= 10.0:
            reason_codes.append("HIGH_DESTINATION_DIVERSITY")

        dest_risk = min(1.0, (dest_novelty_score * 0.60) + (dest_diversity_score * 0.40))
        signals["destination_risk"] = dest_risk

        # ---------------------------------------------------------------------
        # 3. PORT SIGNALS (High Risk Port + Novelty + Diversity)
        # ---------------------------------------------------------------------
        is_new_port = float(f_vals.get("is_new_port", 0.0))
        unique_ports = float(f_vals.get("unique_ports_count", 1.0))
        remote_port = getattr(features, "remote_port", 0) or 0

        is_high_risk_port = 1.0 if remote_port in self.high_risk_ports else 0.0
        port_novelty_score = 0.40 if is_new_port >= 0.5 else 0.0
        port_diversity_score = min(1.0, max(0.0, (unique_ports - 1.0) / 15.0))

        if is_high_risk_port:
            reason_codes.append("SUSPICIOUS_PORT")
        if is_new_port >= 0.5:
            reason_codes.append("NEW_PORT")
        if unique_ports >= 10.0:
            reason_codes.append("HIGH_PORT_DIVERSITY")

        if is_high_risk_port:
            port_risk = 1.0
        else:
            port_risk = min(1.0, (port_novelty_score * 0.60) + (port_diversity_score * 0.40))
        signals["port_risk"] = port_risk

        # ---------------------------------------------------------------------
        # 4. PROTOCOL SIGNALS (Novelty + Unknown Protocol)
        # ---------------------------------------------------------------------
        is_new_proto = float(f_vals.get("is_new_protocol", 0.0))
        proto_other = float(f_vals.get("proto_other", 0.0))

        if is_new_proto >= 0.5:
            reason_codes.append("NEW_PROTOCOL")
        if proto_other >= 0.5:
            reason_codes.append("UNEXPECTED_PROTOCOL")

        proto_risk = min(1.0, (is_new_proto * 0.50) + (proto_other * 0.70))
        signals["protocol_risk"] = proto_risk

        # ---------------------------------------------------------------------
        # 5. CONNECTION FREQUENCY & RECONNAISSANCE DYNAMICS
        # ---------------------------------------------------------------------
        conn_freq = float(f_vals.get("connection_frequency", 1.0))
        proc_freq = float(f_vals.get("process_frequency", 0.2))

        # Check statistical deviation if available
        freq_z = 0.0
        if baseline_deviation and "connection_frequency" in baseline_deviation.feature_deviations:
            freq_z = baseline_deviation.feature_deviations["connection_frequency"].z_score

        freq_score = min(1.0, max(conn_freq / 25.0, freq_z / 6.0))
        if conn_freq >= 15.0 or freq_z >= 3.0:
            reason_codes.append("HIGH_CONNECTION_FREQUENCY")

        signals["frequency_risk"] = freq_score

        # ---------------------------------------------------------------------
        # 6. FAILED CONNECTION RATE / SCANNING BEHAVIOR
        # ---------------------------------------------------------------------
        failed_rate = float(f_vals.get("failed_connection_rate", 0.0))
        if failed_rate >= 0.30:
            reason_codes.append("HIGH_FAILED_CONNECTION_RATE")

        failed_risk = min(1.0, failed_rate * 1.25)
        signals["failed_connection_risk"] = failed_risk

        # ---------------------------------------------------------------------
        # 7. TRAFFIC VOLUME DYNAMICS
        # ---------------------------------------------------------------------
        sent_log = float(f_vals.get("bytes_sent_log", 0.0))
        recv_log = float(f_vals.get("bytes_received_log", 0.0))
        io_ratio = float(f_vals.get("inbound_outbound_ratio", 0.5))

        # Extreme exfiltration (high sent bytes with high outbound ratio)
        traffic_score = 0.0
        if sent_log >= 16.0:  # > 10 MB in single observation
            traffic_score = min(1.0, (sent_log - 14.0) / 6.0)

        # Baseline traffic z-score
        if baseline_deviation and "bytes_sent_log" in baseline_deviation.feature_deviations:
            sent_z = baseline_deviation.feature_deviations["bytes_sent_log"].z_score
            if sent_z >= 3.0:
                traffic_score = max(traffic_score, min(1.0, sent_z / 6.0))

        if traffic_score >= 0.50:
            reason_codes.append("TRAFFIC_VOLUME_ANOMALY")

        signals["traffic_risk"] = traffic_score

        # ---------------------------------------------------------------------
        # 8. P2.4 ANOMALY INPUT SIGNAL
        # ---------------------------------------------------------------------
        anomaly_score = 0.0
        if anomaly_result is not None:
            anomaly_score = anomaly_result.anomaly_score
            if anomaly_score >= 0.60:
                reason_codes.append("HIGH_ANOMALY_SCORE")
        elif baseline_deviation is not None:
            anomaly_score = min(1.0, baseline_deviation.avg_z_score / 4.0)

        signals["anomaly_signal"] = anomaly_score

        # ---------------------------------------------------------------------
        # 9. WEIGHTED DETERMINISTIC RISK CALCULATION & COMPOUND AMPLIFICATION
        # ---------------------------------------------------------------------
        raw_risk = (
            (self.w_dest * signals["destination_risk"])
            + (self.w_port * signals["port_risk"])
            + (self.w_proto * signals["protocol_risk"])
            + (self.w_freq * signals["frequency_risk"])
            + (self.w_failed * signals["failed_connection_risk"])
            + (self.w_traffic * signals["traffic_risk"])
            + (self.w_anomaly * signals["anomaly_signal"])
        )

        # Compound Threat Multipliers (co-occurring malicious indicators)
        compound_bonus = 0.0
        if is_high_risk_port and (failed_rate >= 0.50 or conn_freq >= 20.0 or anomaly_score >= 0.60):
            compound_bonus += 0.15
        if failed_rate >= 0.50 and conn_freq >= 20.0:
            compound_bonus += 0.10

        risk_score = min(1.0, max(0.0, round(raw_risk + compound_bonus, 4)))

        # ---------------------------------------------------------------------
        # 10. CONFIDENCE CALCULATION (Independent of Risk)
        # ---------------------------------------------------------------------
        obs_count = 0
        status = BehaviorStatus.NEW
        rec_conf = 0.10

        if record is not None:
            obs_count = record.observation_count
            status = record.status
            rec_conf = record.confidence
        elif baseline_deviation is not None:
            obs_count = baseline_deviation.observation_count
            status = baseline_deviation.status
            rec_conf = baseline_deviation.confidence

        if status == BehaviorStatus.QUARANTINED:
            confidence = 0.05
        elif status == BehaviorStatus.NEW or obs_count < 2:
            confidence = 0.30
        else:
            # Saturation formula modulated by observation count and baseline confidence
            sat = obs_count / (obs_count + 5.0)
            confidence = min(0.95, max(0.20, rec_conf * 0.70 + sat * 0.30))
            if anomaly_result is not None:
                confidence = min(0.95, confidence + 0.05)

        if confidence < 0.35 and "LOW_BASELINE_CONFIDENCE" not in reason_codes:
            reason_codes.append("LOW_BASELINE_CONFIDENCE")

        if risk_score >= 0.50 and not any(
            r in reason_codes
            for r in (
                "SUSPICIOUS_PORT",
                "HIGH_CONNECTION_FREQUENCY",
                "HIGH_FAILED_CONNECTION_RATE",
                "TRAFFIC_VOLUME_ANOMALY",
                "HIGH_DESTINATION_DIVERSITY",
                "HIGH_PORT_DIVERSITY",
            )
        ):
            reason_codes.append("UNUSUAL_NETWORK_BEHAVIOR")

        unique_reasons = list(dict.fromkeys(reason_codes))

        details["remote_port"] = remote_port
        details["is_high_risk_port"] = bool(is_high_risk_port)
        details["observation_count"] = obs_count
        details["failed_connection_rate"] = failed_rate
        details["connection_frequency"] = conn_freq

        return NetworkRiskResult(
            behavior_identity_key=key,
            risk_score=round(risk_score, 2),
            confidence=round(confidence, 2),
            model_name=self.model_name,
            model_version=self.model_version,
            feature_version=self.feature_version,
            reason_codes=unique_reasons,
            contributing_signals=signals,
            timestamp=time.time(),
            details=details,
        )

    # BaseSecurityModel abstract interface implementations
    def fit(self, X: Any, y: Any = None) -> Self:
        """Fit method stub for future supervised ML network risk classifier."""
        return self

    def predict(self, X: Any) -> list[int]:
        """Predict binary high-risk classification (1 = high risk, 0 = normal)."""
        if isinstance(X, (FeatureVector, BehavioralFeatures)):
            res = self.evaluate(X)
            return [1 if res.risk_score >= 0.50 else 0]
        if isinstance(X, list):
            return [1 if self.evaluate(item).risk_score >= 0.50 else 0 for item in X]
        return [0]

    def score(self, X: Any) -> list[ModelOutput] | ModelOutput:
        """Generate standardized ModelOutput scores."""
        is_single = isinstance(X, (FeatureVector, BehavioralFeatures))
        items = [X] if is_single else X
        outputs: list[ModelOutput] = []

        for item in items:
            res = self.evaluate(item)
            out = ModelOutput(
                model_name=self.model_name,
                model_version=self.model_version,
                score=res.risk_score,
                confidence=res.confidence,
                reason_codes=res.reason_codes,
                feature_version=self.feature_version,
                details=res.contributing_signals,
            )
            outputs.append(out)

        return outputs[0] if is_single else outputs

    def save(self, path: str | Path) -> None:
        """Persist model configuration and metadata using joblib."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "weights": {
                "w_dest": self.w_dest,
                "w_port": self.w_port,
                "w_proto": self.w_proto,
                "w_freq": self.w_freq,
                "w_failed": self.w_failed,
                "w_traffic": self.w_traffic,
                "w_anomaly": self.w_anomaly,
            },
            "high_risk_ports": list(self.high_risk_ports),
        }
        joblib.dump(payload, p)

    @classmethod
    def load(cls, path: str | Path) -> "NetworkRiskModel":
        """Load model configuration from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model artifact not found at: {path}")

        payload = joblib.load(p)
        weights = payload.get("weights", {})
        return cls(
            model_version=payload.get("model_version", NETWORK_RISK_MODEL_VERSION),
            feature_version=payload.get("feature_version", FEATURE_VERSION),
            w_dest=weights.get("w_dest", 0.20),
            w_port=weights.get("w_port", 0.20),
            w_proto=weights.get("w_proto", 0.10),
            w_freq=weights.get("w_freq", 0.15),
            w_failed=weights.get("w_failed", 0.10),
            w_traffic=weights.get("w_traffic", 0.10),
            w_anomaly=weights.get("w_anomaly", 0.15),
            high_risk_ports=set(payload.get("high_risk_ports", HIGH_RISK_PORTS)),
        )
