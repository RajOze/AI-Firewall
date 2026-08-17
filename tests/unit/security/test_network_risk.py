"""Comprehensive unit test suite for P2.5 Specialized Network Risk Model (M3)."""

import time
from pathlib import Path

import pytest

from backend.security.anomaly import AnomalyResult
from backend.security.baseline import BehavioralBaselineEngine, BehavioralRecord
from backend.security.behavioral_models import BehavioralEvent, BehaviorStatus
from backend.security.features import FEATURE_VERSION, FeatureExtractor, FeatureVector
from backend.security.network_risk import (
    HIGH_RISK_PORTS,
    NETWORK_RISK_MODEL_VERSION,
    NetworkRiskModel,
    NetworkRiskResult,
)


@pytest.fixture
def risk_model() -> NetworkRiskModel:
    """Fixture providing clean NetworkRiskModel instance."""
    return NetworkRiskModel()


@pytest.fixture
def baseline_engine() -> BehavioralBaselineEngine:
    """Fixture providing clean BehavioralBaselineEngine."""
    return BehavioralBaselineEngine()


def _make_vector(
    proc_name: str = "chrome.exe",
    remote_ip: str = "142.250.190.46",
    remote_port: int = 443,
    conn_freq: float = 1.0,
    bytes_sent: int = 1000,
    bytes_received: int = 5000,
    failed_rate: float = 0.0,
    unique_dests: float = 1.0,
    unique_ports: float = 1.0,
    is_new_dest: float = 0.0,
    is_new_port: float = 0.0,
    is_new_proto: float = 0.0,
    proto_other: float = 0.0,
    feature_version: str = "1.0",
) -> FeatureVector:
    evt = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name=proc_name,
        process_id=1000,
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol="TCP" if proto_other == 0.0 else "RAW",
        direction="OUTBOUND",
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(evt)
    fv.values["connection_frequency"] = conn_freq
    fv.values["failed_connection_rate"] = failed_rate
    fv.values["unique_destinations_count"] = unique_dests
    fv.values["unique_ports_count"] = unique_ports
    fv.values["is_new_destination"] = is_new_dest
    fv.values["is_new_port"] = is_new_port
    fv.values["is_new_protocol"] = is_new_proto
    fv.values["proto_other"] = proto_other
    fv.feature_version = feature_version
    fv.vector = [fv.values.get(k, 0.0) for k in fv.feature_names]
    return fv


# 1. Normal HTTPS connection behavior
def test_01_normal_https_behavior(risk_model: NetworkRiskModel, baseline_engine: BehavioralBaselineEngine):
    """Verify normal benign HTTPS traffic produces low risk score (<0.20) and high confidence."""
    fv = _make_vector()
    for _ in range(10):
        baseline_engine.update_baseline(fv, anomaly_score=0.05)

    rec = baseline_engine.get_record(fv.behavior_key)
    res = risk_model.evaluate(fv, record=rec)

    assert isinstance(res, NetworkRiskResult)
    assert res.risk_score < 0.20
    assert res.confidence >= 0.70
    assert "SUSPICIOUS_PORT" not in res.reason_codes
    assert "HIGH_ANOMALY_SCORE" not in res.reason_codes


# 2. New destination risk
def test_02_new_destination_risk(risk_model: NetworkRiskModel):
    """Verify communicating with a new destination flags NEW_DESTINATION and raises destination risk."""
    fv = _make_vector(remote_ip="198.51.100.99", is_new_dest=1.0)
    res = risk_model.evaluate(fv)

    assert "NEW_DESTINATION" in res.reason_codes
    assert res.contributing_signals["destination_risk"] >= 0.25


# 3. New port risk
def test_03_new_port_risk(risk_model: NetworkRiskModel):
    """Verify communicating on a new port flags NEW_PORT."""
    fv = _make_vector(remote_port=9090, is_new_port=1.0)
    res = risk_model.evaluate(fv)

    assert "NEW_PORT" in res.reason_codes
    assert res.contributing_signals["port_risk"] >= 0.10


# 4. Suspicious high-risk port
def test_04_suspicious_high_risk_port(risk_model: NetworkRiskModel):
    """Verify connection to high-risk port (4444 Metasploit / 3389 RDP) flags SUSPICIOUS_PORT and high port risk."""
    for port in (4444, 3389, 445):
        fv = _make_vector(remote_port=port)
        res = risk_model.evaluate(fv)

        assert "SUSPICIOUS_PORT" in res.reason_codes
        assert res.contributing_signals["port_risk"] >= 0.70


# 5. New and unexpected protocol
def test_05_new_and_unexpected_protocol(risk_model: NetworkRiskModel):
    """Verify unexpected/raw protocol flags NEW_PROTOCOL and UNEXPECTED_PROTOCOL."""
    fv = _make_vector(proto_other=1.0, is_new_proto=1.0)
    res = risk_model.evaluate(fv)

    assert "NEW_PROTOCOL" in res.reason_codes
    assert "UNEXPECTED_PROTOCOL" in res.reason_codes
    assert res.contributing_signals["protocol_risk"] >= 0.60


# 6. High connection frequency
def test_06_high_connection_frequency(risk_model: NetworkRiskModel):
    """Verify rapid connection rate flags HIGH_CONNECTION_FREQUENCY."""
    fv = _make_vector(conn_freq=50.0)
    res = risk_model.evaluate(fv)

    assert "HIGH_CONNECTION_FREQUENCY" in res.reason_codes
    assert res.contributing_signals["frequency_risk"] >= 0.60


# 7. High destination diversity
def test_07_high_destination_diversity(risk_model: NetworkRiskModel):
    """Verify communicating with many destinations in short window flags HIGH_DESTINATION_DIVERSITY."""
    fv = _make_vector(unique_dests=20.0)
    res = risk_model.evaluate(fv)

    assert "HIGH_DESTINATION_DIVERSITY" in res.reason_codes
    assert res.contributing_signals["destination_risk"] >= 0.40


# 8. High port diversity
def test_08_high_port_diversity(risk_model: NetworkRiskModel):
    """Verify communicating across many ports flags HIGH_PORT_DIVERSITY."""
    fv = _make_vector(unique_ports=25.0)
    res = risk_model.evaluate(fv)

    assert "HIGH_PORT_DIVERSITY" in res.reason_codes
    assert res.contributing_signals["port_risk"] >= 0.30


# 9. High failed connection rate
def test_09_high_failed_connection_rate(risk_model: NetworkRiskModel):
    """Verify high failed connection rate (reconnaissance/scanning) flags HIGH_FAILED_CONNECTION_RATE."""
    fv = _make_vector(failed_rate=0.80)
    res = risk_model.evaluate(fv)

    assert "HIGH_FAILED_CONNECTION_RATE" in res.reason_codes
    assert res.contributing_signals["failed_connection_risk"] >= 0.80


# 10. Traffic volume anomaly
def test_10_traffic_volume_anomaly(risk_model: NetworkRiskModel):
    """Verify massive outbound byte transfer flags TRAFFIC_VOLUME_ANOMALY."""
    fv = _make_vector(bytes_sent=100_000_000)  # > 100MB
    fv.values["bytes_sent_log"] = 18.5
    res = risk_model.evaluate(fv)

    assert "TRAFFIC_VOLUME_ANOMALY" in res.reason_codes
    assert res.contributing_signals["traffic_risk"] >= 0.50


# 11. Low baseline confidence
def test_11_low_baseline_confidence(risk_model: NetworkRiskModel, baseline_engine: BehavioralBaselineEngine):
    """Verify unestablished baseline records flag LOW_BASELINE_CONFIDENCE with low confidence value."""
    fv = _make_vector()
    # Baseline record has 0 observations
    rec = baseline_engine.get_record(fv.behavior_key)
    res = risk_model.evaluate(fv, record=rec)

    assert "LOW_BASELINE_CONFIDENCE" in res.reason_codes
    assert res.confidence <= 0.35


# 12. High anomaly signal integration
def test_12_high_anomaly_signal_integration(risk_model: NetworkRiskModel):
    """Verify P2.4 AnomalyResult input signal integrates cleanly and emits HIGH_ANOMALY_SCORE."""
    fv = _make_vector()
    anomaly_res = AnomalyResult(
        anomaly_score=0.85,
        confidence=0.80,
        statistical_score=0.80,
        behavior_identity_key=fv.behavior_key,
    )
    res = risk_model.evaluate(fv, anomaly_result=anomaly_res)

    assert "HIGH_ANOMALY_SCORE" in res.reason_codes
    assert res.contributing_signals["anomaly_signal"] == 0.85


# 13. Combined compound network threat
def test_13_combined_compound_network_threat(risk_model: NetworkRiskModel):
    """Verify multi-vector network threat produces critical risk score (>= 0.70)."""
    fv = _make_vector(
        remote_port=4444,
        conn_freq=30.0,
        failed_rate=0.75,
        unique_ports=15.0,
        is_new_dest=1.0,
        is_new_port=1.0,
    )
    anomaly_res = AnomalyResult(
        anomaly_score=0.90,
        confidence=0.85,
        behavior_identity_key=fv.behavior_key,
    )
    res = risk_model.evaluate(fv, anomaly_result=anomaly_res)

    assert res.risk_score >= 0.70
    assert "SUSPICIOUS_PORT" in res.reason_codes
    assert "HIGH_FAILED_CONNECTION_RATE" in res.reason_codes
    assert "HIGH_CONNECTION_FREQUENCY" in res.reason_codes


# 14. Risk score strict bounds
def test_14_risk_score_strict_bounds_zero_to_one(risk_model: NetworkRiskModel):
    """Verify risk scores strictly clamped between 0.0 and 1.0 even under extreme feature values."""
    extreme_vectors = [
        _make_vector(conn_freq=-1000.0, failed_rate=-5.0, bytes_sent=-100),
        _make_vector(conn_freq=1e9, failed_rate=100.0, bytes_sent=10**15),
    ]
    for fv in extreme_vectors:
        res = risk_model.evaluate(fv)
        assert 0.0 <= res.risk_score <= 1.0


# 15. Confidence strict bounds
def test_15_confidence_strict_bounds_zero_to_one(risk_model: NetworkRiskModel):
    """Verify confidence values strictly clamped between 0.0 and 1.0."""
    fv = _make_vector()
    res = risk_model.evaluate(fv)
    assert 0.0 <= res.confidence <= 1.0


# 16. Reason code evidence correctness
def test_16_reason_code_evidence_correctness(risk_model: NetworkRiskModel):
    """Verify reason codes are only emitted when supported by explicit feature evidence."""
    fv_clean = _make_vector(
        remote_port=443,
        conn_freq=1.0,
        failed_rate=0.0,
        unique_dests=1.0,
        unique_ports=1.0,
    )
    res = risk_model.evaluate(fv_clean)

    assert "SUSPICIOUS_PORT" not in res.reason_codes
    assert "HIGH_FAILED_CONNECTION_RATE" not in res.reason_codes
    assert "HIGH_CONNECTION_FREQUENCY" not in res.reason_codes
    assert "HIGH_DESTINATION_DIVERSITY" not in res.reason_codes
    assert "HIGH_PORT_DIVERSITY" not in res.reason_codes
    assert "TRAFFIC_VOLUME_ANOMALY" not in res.reason_codes


# 17. Deterministic reproducibility
def test_17_deterministic_reproducibility(risk_model: NetworkRiskModel):
    """Verify evaluating identical feature vector produces identical risk score and signals."""
    fv = _make_vector(remote_port=22, conn_freq=10.0, is_new_dest=1.0)
    res1 = risk_model.evaluate(fv)
    res2 = risk_model.evaluate(fv)

    assert res1.risk_score == res2.risk_score
    assert res1.confidence == res2.confidence
    assert res1.reason_codes == res2.reason_codes
    assert res1.contributing_signals == res2.contributing_signals


# 18. Feature version compatibility and safe fallback
def test_18_feature_version_compatibility_and_fallback(risk_model: NetworkRiskModel):
    """Verify mismatched schema version flags FEATURE_VERSION_MISMATCH and evaluates safely."""
    fv_mismatch = _make_vector(feature_version="99.0")
    res = risk_model.evaluate(fv_mismatch)

    assert "FEATURE_VERSION_MISMATCH" in res.reason_codes
    assert 0.0 <= res.risk_score <= 1.0


# 19. Missing and malformed telemetry resilience
def test_19_missing_and_malformed_telemetry_resilience(risk_model: NetworkRiskModel):
    """Verify partial or missing feature dictionary values evaluate safely without exception."""
    bare_fv = FeatureVector(
        behavior_identity_key="bare_proc|0.0.0.0:0|TCP",
        timestamp=time.time(),
        vector=[0.0] * 26,
        values={},
    )
    res = risk_model.evaluate(bare_fv)

    assert isinstance(res, NetworkRiskResult)
    assert 0.0 <= res.risk_score <= 1.0
    assert 0.0 <= res.confidence <= 1.0


# 20. Suspicious behavior does not modify baseline
def test_20_suspicious_behavior_does_not_modify_baseline(
    risk_model: NetworkRiskModel, baseline_engine: BehavioralBaselineEngine
):
    """Verify network risk evaluation is a pure read/scoring engine and never modifies baseline memory."""
    fv_normal = _make_vector(conn_freq=2.0)
    for _ in range(8):
        baseline_engine.update_baseline(fv_normal, anomaly_score=0.05)

    rec = baseline_engine.get_record(fv_normal.behavior_key)
    initial_count = rec.observation_count
    initial_mean = rec.metrics["connection_frequency"].mean

    # Evaluate high risk event
    fv_threat = _make_vector(remote_port=4444, conn_freq=100.0, failed_rate=0.90)
    res = risk_model.evaluate(fv_threat, record=rec)

    assert res.risk_score >= 0.50
    # Confirm baseline record remains completely unchanged by evaluate()
    assert rec.observation_count == initial_count
    assert rec.metrics["connection_frequency"].mean == initial_mean
