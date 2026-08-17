"""Comprehensive unit test suite for P2.4 Anomaly Detection Engine and IsolationForest."""

import math
import time
from pathlib import Path

import numpy as np
import pytest

from backend.security.anomaly import (
    ANOMALY_MODEL_VERSION,
    AnomalyDetectionEngine,
    AnomalyResult,
    IsolationForestAnomalyModel,
)
from backend.security.baseline import BehavioralBaselineEngine
from backend.security.behavioral_models import BehavioralEvent, BehaviorStatus
from backend.security.features import FEATURE_VERSION, FeatureExtractor, FeatureVector


@pytest.fixture
def baseline_engine() -> BehavioralBaselineEngine:
    """Fixture providing clean BehavioralBaselineEngine."""
    return BehavioralBaselineEngine()


@pytest.fixture
def trained_ml_model() -> IsolationForestAnomalyModel:
    """Fixture providing trained IsolationForest model on synthetic benign baseline data."""
    model = IsolationForestAnomalyModel(n_estimators=50, contamination=0.05, random_state=42)
    # Generate 100 synthetic benign feature vectors with normal variation
    extractor = FeatureExtractor()
    benign_vectors = []
    for i in range(100):
        evt = BehavioralEvent(
            timestamp=1700000000.0 + (i * 10),
            event_type="NETWORK_CONNECTION",
            process_name="chrome.exe" if i % 2 == 0 else "firefox.exe",
            process_id=1000 + (i % 5),
            remote_ip=f"142.250.190.{40 + (i % 10)}",
            remote_port=443 if i % 3 != 0 else 80,
            protocol="TCP",
            direction="OUTBOUND",
            bytes_sent=500 + (i * 20),
            bytes_received=2000 + (i * 50),
        )
        fv = extractor.extract(evt)
        fv.values["connection_frequency"] = 0.5 + ((i % 10) * 0.2)
        fv.vector = [fv.values.get(k, 0.0) for k in fv.feature_names]
        benign_vectors.append(fv)

    model.fit(benign_vectors)
    return model


def _make_vector(
    proc_name: str = "chrome.exe",
    remote_ip: str = "142.250.190.46",
    remote_port: int = 443,
    conn_freq: float = 1.0,
    bytes_sent: int = 1000,
    bytes_received: int = 5000,
    feature_version: str = "1.0",
    timestamp: float = 1700000025.0,
) -> FeatureVector:
    evt = BehavioralEvent(
        timestamp=timestamp,
        event_type="NETWORK_CONNECTION",
        process_name=proc_name,
        process_id=1000,
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol="TCP",
        direction="OUTBOUND",
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(evt)
    fv.values["connection_frequency"] = conn_freq
    fv.feature_version = feature_version
    fv.vector = [fv.values.get(k, 0.0) for k in fv.feature_names]
    return fv


# 1. Normal behavior detection
def test_01_normal_behavior_detection(baseline_engine: BehavioralBaselineEngine, trained_ml_model: IsolationForestAnomalyModel):
    """Verify normal established inlier behavior receives low anomaly score (<0.35)."""
    fv = _make_vector()
    # Establish baseline
    for _ in range(8):
        baseline_engine.update_baseline(fv, anomaly_score=0.1)

    engine = AnomalyDetectionEngine(ml_model=trained_ml_model)
    res = engine.detect(fv, baseline_engine=baseline_engine)

    assert isinstance(res, AnomalyResult)
    assert res.anomaly_score < 0.35
    assert res.confidence >= 0.70
    assert "ML_ANOMALY" not in res.reason_codes


# 2. Obvious statistical anomaly
def test_02_obvious_statistical_anomaly(baseline_engine: BehavioralBaselineEngine):
    """Verify large statistical deviation triggers HIGH_FREQUENCY and high score."""
    fv_normal = _make_vector(conn_freq=2.0)
    for _ in range(10):
        baseline_engine.update_baseline(fv_normal, anomaly_score=0.0)

    # Extreme frequency spike
    fv_anomaly = _make_vector(conn_freq=500.0)
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv_anomaly, baseline_engine=baseline_engine)

    assert res.statistical_score > 0.50
    assert "HIGH_FREQUENCY" in res.reason_codes


# 3. Obvious ML anomaly
def test_03_obvious_ml_anomaly(trained_ml_model: IsolationForestAnomalyModel):
    """Verify extreme synthetic outlier vector produces ML_ANOMALY."""
    fv_outlier = _make_vector(conn_freq=9999.0, bytes_sent=1_000_000_000)
    fv_outlier.vector = [9999.0] * len(fv_outlier.vector)  # Extreme synthetic point

    engine = AnomalyDetectionEngine(ml_model=trained_ml_model)
    res = engine.detect(fv_outlier, is_novel=False, record=None)

    assert res.ml_score is not None
    assert res.ml_score >= 0.50
    assert "ML_ANOMALY" in res.reason_codes


# 4. Combined anomaly fusion
def test_04_combined_anomaly_fusion(baseline_engine: BehavioralBaselineEngine, trained_ml_model: IsolationForestAnomalyModel):
    """Verify deterministic weighted fusion of statistical and ML scores."""
    fv = _make_vector()
    for _ in range(6):
        baseline_engine.update_baseline(fv)

    engine = AnomalyDetectionEngine(ml_model=trained_ml_model, weight_stat=0.60, weight_ml=0.40)
    res = engine.detect(fv, baseline_engine=baseline_engine)

    expected_fused = round((0.60 * res.statistical_score) + (0.40 * (res.ml_score or 0.0)), 2)
    assert abs(res.anomaly_score - expected_fused) <= 0.02


# 5. New behavior detection
def test_05_new_behavior_detection(baseline_engine: BehavioralBaselineEngine):
    """Verify first-time behavior receives NEW_BEHAVIOR_KEY and moderate initial score."""
    fv_new = _make_vector(proc_name="brand_new_app.exe", remote_ip="198.51.100.1")
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv_new, baseline_engine=baseline_engine)

    assert "NEW_BEHAVIOR_KEY" in res.reason_codes
    assert 0.30 <= res.anomaly_score <= 0.80
    assert res.confidence == 0.50


# 6. Low confidence baseline
def test_06_low_confidence_baseline(baseline_engine: BehavioralBaselineEngine):
    """Verify baseline record under initial observation flags LOW_BASELINE_CONFIDENCE."""
    fv = _make_vector()
    baseline_engine.update_baseline(fv)  # Count = 1 -> NEW state

    engine = AnomalyDetectionEngine()
    res = engine.detect(fv, baseline_engine=baseline_engine)

    assert "LOW_BASELINE_CONFIDENCE" in res.reason_codes
    assert res.confidence <= 0.50


# 7. Stable baseline high confidence
def test_07_stable_baseline_high_confidence(baseline_engine: BehavioralBaselineEngine):
    """Verify mature baseline with many observations yields confidence > 0.80."""
    fv = _make_vector()
    for _ in range(20):
        baseline_engine.update_baseline(fv, anomaly_score=0.05)

    engine = AnomalyDetectionEngine()
    res = engine.detect(fv, baseline_engine=baseline_engine)

    assert res.confidence >= 0.80
    assert "LOW_BASELINE_CONFIDENCE" not in res.reason_codes


# 8. High frequency behavior
def test_08_high_frequency_behavior(baseline_engine: BehavioralBaselineEngine):
    """Verify connection rate deviation flags HIGH_FREQUENCY."""
    fv = _make_vector(conn_freq=1.0)
    for _ in range(8):
        baseline_engine.update_baseline(fv)

    fv_fast = _make_vector(conn_freq=200.0)
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv_fast, baseline_engine=baseline_engine)

    assert "HIGH_FREQUENCY" in res.reason_codes


# 9. Traffic volume anomaly
def test_09_traffic_volume_anomaly(baseline_engine: BehavioralBaselineEngine):
    """Verify huge byte count deviation flags TRAFFIC_VOLUME_ANOMALY."""
    fv_normal = _make_vector(bytes_sent=100)
    for _ in range(8):
        baseline_engine.update_baseline(fv_normal)

    fv_heavy = _make_vector(bytes_sent=500_000_000)
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv_heavy, baseline_engine=baseline_engine)

    assert "TRAFFIC_VOLUME_ANOMALY" in res.reason_codes


# 10. New destination
def test_10_new_destination(baseline_engine: BehavioralBaselineEngine):
    """Verify communicating with a new destination flags NEW_DESTINATION."""
    fv = _make_vector(remote_ip="9.9.9.9")
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv, baseline_engine=baseline_engine)

    assert "NEW_DESTINATION" in res.reason_codes


# 11. New port
def test_11_new_port(baseline_engine: BehavioralBaselineEngine):
    """Verify communicating on an unseen port flags UNUSUAL_PORT."""
    fv = _make_vector(remote_port=6667)
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv, baseline_engine=baseline_engine)

    assert "UNUSUAL_PORT" in res.reason_codes


# 12. Feature version mismatch safe fallback
def test_12_feature_version_mismatch_safe_fallback(trained_ml_model: IsolationForestAnomalyModel):
    """Verify feature schema mismatch flags FEATURE_VERSION_MISMATCH and gracefully falls back."""
    fv_mismatch = _make_vector(feature_version="99.0")  # Incompatible schema

    engine = AnomalyDetectionEngine(ml_model=trained_ml_model)
    res = engine.detect(fv_mismatch, is_novel=False, record=None)

    assert "FEATURE_VERSION_MISMATCH" in res.reason_codes
    assert res.ml_score is None  # ML inference safely bypassed
    assert 0.0 <= res.anomaly_score <= 1.0


# 13. Model serialization with joblib
def test_13_model_serialization_joblib(trained_ml_model: IsolationForestAnomalyModel, tmp_path: Path):
    """Verify model persists to disk with all required metadata."""
    save_file = tmp_path / "iso_model.joblib"
    trained_ml_model.save(save_file)

    assert save_file.exists()
    assert save_file.stat().st_size > 0


# 14. Model reload integrity
def test_14_model_reload_integrity(trained_ml_model: IsolationForestAnomalyModel, tmp_path: Path):
    """Verify reloaded model reproduces exact predictions and decision scores."""
    save_file = tmp_path / "iso_model.joblib"
    trained_ml_model.save(save_file)

    loaded_model = IsolationForestAnomalyModel.load(save_file)
    assert loaded_model.model_version == trained_ml_model.model_version
    assert loaded_model.feature_version == trained_ml_model.feature_version
    assert loaded_model.training_sample_count == trained_ml_model.training_sample_count

    sample_fv = _make_vector()
    out1 = trained_ml_model.score(sample_fv)
    out2 = loaded_model.score(sample_fv)

    assert out1.score == out2.score
    assert out1.details["raw_decision_score"] == out2.details["raw_decision_score"]


# 15. Deterministic IsolationForest
def test_15_deterministic_isolation_forest(trained_ml_model: IsolationForestAnomalyModel):
    """Verify deterministic inference generates identical score for same input."""
    sample_fv = _make_vector()
    s1 = trained_ml_model.score(sample_fv)
    s2 = trained_ml_model.score(sample_fv)

    assert s1.score == s2.score


# 16. Insufficient training data rejection
def test_16_insufficient_training_data_rejection():
    """Verify fit() rejects training datasets with fewer than 10 samples."""
    model = IsolationForestAnomalyModel()
    small_dataset = [[1.0] * 26 for _ in range(5)]

    with pytest.raises(ValueError, match="Insufficient training samples"):
        model.fit(small_dataset)


# 17. Suspicious event does not poison baseline
def test_17_suspicious_event_does_not_poison_baseline(baseline_engine: BehavioralBaselineEngine):
    """Verify high anomaly score freezing protects baseline accumulators."""
    fv_normal = _make_vector(conn_freq=5.0)
    for _ in range(8):
        baseline_engine.update_baseline(fv_normal, anomaly_score=0.1)

    rec = baseline_engine.get_record(fv_normal.behavior_key)
    initial_mean = rec.metrics["connection_frequency"].mean

    # Detect high anomaly
    fv_attack = _make_vector(conn_freq=9999.0)
    engine = AnomalyDetectionEngine()
    res = engine.detect(fv_attack, baseline_engine=baseline_engine)

    assert res.anomaly_score >= 0.70
    # Update baseline with detected anomaly score -> triggers freeze
    baseline_engine.update_baseline(fv_attack, anomaly_score=res.anomaly_score)

    assert rec.status == BehaviorStatus.SUSPICIOUS
    assert rec.metrics["connection_frequency"].mean == initial_mean


# 18. Quarantined event does not poison baseline
def test_18_quarantined_event_does_not_poison_baseline(baseline_engine: BehavioralBaselineEngine):
    """Verify quarantined identity evaluation preserves frozen statistics."""
    fv = _make_vector()
    baseline_engine.update_baseline(fv)
    baseline_engine.quarantine_behavior(fv.behavior_key)

    engine = AnomalyDetectionEngine()
    res = engine.detect(fv, baseline_engine=baseline_engine)

    assert res.confidence == 0.05
    rec = baseline_engine.update_baseline(fv, anomaly_score=res.anomaly_score)
    assert rec.status == BehaviorStatus.QUARANTINED


# 19. Malformed incomplete feature vector
def test_19_malformed_incomplete_feature_vector(baseline_engine: BehavioralBaselineEngine):
    """Verify partial or missing feature properties evaluate safely without crashing."""
    bare_fv = FeatureVector(
        behavior_identity_key="bare_app|unknown|0.0.0.0:0|TCP|UNKNOWN",
        timestamp=time.time(),
        vector=[0.0] * 26,
        values={},
    )
    engine = AnomalyDetectionEngine()
    res = engine.detect(bare_fv, baseline_engine=baseline_engine)

    assert isinstance(res, AnomalyResult)
    assert 0.0 <= res.anomaly_score <= 1.0


# 20. Score always bounded zero to one
def test_20_score_always_bounded_zero_to_one(baseline_engine: BehavioralBaselineEngine, trained_ml_model: IsolationForestAnomalyModel):
    """Verify anomaly scores, statistical scores, and ML scores remain in [0.0, 1.0]."""
    engine = AnomalyDetectionEngine(ml_model=trained_ml_model)

    test_vectors = [
        _make_vector(conn_freq=-100.0, bytes_sent=-500),
        _make_vector(conn_freq=1e9, bytes_sent=10**12),
        _make_vector(proc_name="test.exe"),
    ]

    for fv in test_vectors:
        res = engine.detect(fv, baseline_engine=baseline_engine)
        assert 0.0 <= res.anomaly_score <= 1.0
        assert 0.0 <= res.statistical_score <= 1.0
        if res.ml_score is not None:
            assert 0.0 <= res.ml_score <= 1.0
        assert 0.0 <= res.confidence <= 1.0
