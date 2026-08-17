"""Comprehensive unit test suite for P2.3 Behavioral Baseline Engine."""

import math
import statistics
import time
from pathlib import Path

import pytest

from backend.security.baseline import (
    BASELINE_VERSION,
    BaselineMetric,
    BehavioralBaselineEngine,
    BehavioralRecord,
)
from backend.security.behavioral_models import BehavioralEvent, BehaviorStatus
from backend.security.features import FeatureExtractor, FeatureVector


@pytest.fixture
def baseline_engine(tmp_path: Path) -> BehavioralBaselineEngine:
    """Fixture providing clean BehavioralBaselineEngine instance with temporary storage."""
    storage_file = tmp_path / "baseline_memory.json"
    return BehavioralBaselineEngine(storage_path=storage_file)


@pytest.fixture
def extractor() -> FeatureExtractor:
    """Fixture providing clean FeatureExtractor instance."""
    return FeatureExtractor()


def _make_feature_vector(
    proc_name: str = "app.exe",
    remote_ip: str = "1.1.1.1",
    remote_port: int = 443,
    proto: str = "TCP",
    direction: str = "OUTBOUND",
    conn_freq: float = 1.0,
    bytes_sent: int = 1000,
    timestamp: float | None = None,
) -> FeatureVector:
    ts = timestamp or time.time()
    evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name=proc_name,
        process_id=100,
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol=proto,
        direction=direction,
        bytes_sent=bytes_sent,
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(evt)
    fv.values["connection_frequency"] = conn_freq
    return fv


# 1. First observation registration
def test_01_first_observation_registration(baseline_engine: BehavioralBaselineEngine):
    """Verify first observation registers record in NEW state without polluting statistics."""
    fv = _make_feature_vector()
    rec = baseline_engine.update_baseline(fv, anomaly_score=0.0)

    assert rec.status == BehaviorStatus.NEW
    assert rec.observation_count == 1
    assert rec.confidence == 0.10
    # First observation should NOT update Welford count for metric accumulators
    assert rec.metrics["connection_frequency"].count == 0


# 2. Repeated normal observations
def test_02_repeated_normal_observations(baseline_engine: BehavioralBaselineEngine):
    """Verify lifecycle state progression NEW -> OBSERVING -> KNOWN_BENIGN."""
    fv = _make_feature_vector()
    t0 = time.time()

    # Obs 1 -> NEW
    r1 = baseline_engine.update_baseline(fv, timestamp=t0)
    assert r1.status == BehaviorStatus.NEW

    # Obs 2 -> NEW
    r2 = baseline_engine.update_baseline(fv, timestamp=t0 + 1)
    assert r2.status == BehaviorStatus.NEW

    # Obs 3 -> OBSERVING
    r3 = baseline_engine.update_baseline(fv, timestamp=t0 + 2)
    assert r3.status == BehaviorStatus.OBSERVING
    assert r3.metrics["connection_frequency"].count == 1

    # Obs 4, 5 -> KNOWN_BENIGN
    baseline_engine.update_baseline(fv, timestamp=t0 + 3)
    r5 = baseline_engine.update_baseline(fv, timestamp=t0 + 4)
    assert r5.status == BehaviorStatus.KNOWN_BENIGN
    assert r5.confidence >= 0.70


# 3. Mean convergence
def test_03_mean_convergence():
    """Verify Welford running mean converges accurately to arithmetic mean."""
    values = [10.5, 12.0, 11.2, 13.8, 9.4, 15.1, 10.0]
    expected_mean = statistics.mean(values)

    metric = BaselineMetric()
    for v in values:
        metric.update(v)

    assert metric.count == len(values)
    assert pytest.approx(metric.mean, rel=1e-5) == expected_mean


# 4. Variance calculation
def test_04_variance_calculation():
    """Verify Welford sample variance matches true sample variance (N-1 divisor)."""
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    expected_variance = statistics.variance(values)

    metric = BaselineMetric()
    for v in values:
        metric.update(v)

    assert pytest.approx(metric.variance, rel=1e-5) == expected_variance


# 5. Standard deviation
def test_05_standard_deviation():
    """Verify sample standard deviation matches sqrt(variance)."""
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    expected_stddev = statistics.stdev(values)

    metric = BaselineMetric()
    for v in values:
        metric.update(v)

    assert pytest.approx(metric.stddev, rel=1e-5) == expected_stddev


# 6. Observation count tracking
def test_06_observation_count_tracking(baseline_engine: BehavioralBaselineEngine):
    """Verify observation counts and timestamps update properly across updates."""
    fv = _make_feature_vector()
    t0 = 1700000000.0

    for i in range(10):
        rec = baseline_engine.update_baseline(fv, timestamp=t0 + i)

    assert rec.observation_count == 10
    assert rec.first_seen == t0
    assert rec.last_seen == t0 + 9


# 7. Confidence progression
def test_07_confidence_progression(baseline_engine: BehavioralBaselineEngine):
    """Verify confidence score increases monotonically with validated observations."""
    fv = _make_feature_vector()
    confidences = []

    for i in range(15):
        rec = baseline_engine.update_baseline(fv, anomaly_score=0.0)
        confidences.append(rec.confidence)

    # Validate monotonic growth
    for i in range(1, len(confidences)):
        assert confidences[i] >= confidences[i - 1]
    assert confidences[-1] > 0.80


# 8. Multiple behavior identities
def test_08_multiple_behavior_identities(baseline_engine: BehavioralBaselineEngine):
    """Verify distinct process/endpoint identity keys maintain separate baseline records."""
    fv1 = _make_feature_vector(proc_name="browser.exe", remote_ip="1.1.1.1", remote_port=443)
    fv2 = _make_feature_vector(proc_name="updater.exe", remote_ip="8.8.8.8", remote_port=53)

    for _ in range(5):
        baseline_engine.update_baseline(fv1)
    for _ in range(3):
        baseline_engine.update_baseline(fv2)

    rec1 = baseline_engine.get_record(fv1.behavior_key)
    rec2 = baseline_engine.get_record(fv2.behavior_key)

    assert rec1 is not None and rec2 is not None
    assert rec1.behavior_key != rec2.behavior_key
    assert rec1.observation_count == 5
    assert rec2.observation_count == 3
    assert rec1.status == BehaviorStatus.KNOWN_BENIGN
    assert rec2.status == BehaviorStatus.OBSERVING


# 9. Missing telemetry handling
def test_09_missing_telemetry_handling(baseline_engine: BehavioralBaselineEngine, extractor: FeatureExtractor):
    """Verify baseline update does not fail on missing optional telemetry fields."""
    bare_evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="PROCESS_START",
        process_name="bare.exe",
        process_id=50,
    )
    fv = extractor.extract(bare_evt)

    rec = baseline_engine.update_baseline(fv)
    assert rec.process_name == "bare.exe"
    assert rec.observation_count == 1


# 10. Unknown protocol handling
def test_10_unknown_protocol_handling(baseline_engine: BehavioralBaselineEngine, extractor: FeatureExtractor):
    """Verify unknown protocol is isolated and does not contaminate TCP baseline."""
    evt_unk = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="p.exe",
        process_id=10,
        protocol="UNKNOWN",
    )
    fv_unk = extractor.extract(evt_unk)
    assert fv_unk.values["proto_other"] == 1.0
    assert fv_unk.values["proto_tcp"] == 0.0

    rec = baseline_engine.update_baseline(fv_unk)
    assert "UNKNOWN" in rec.behavior_key


# 11. Unknown direction handling
def test_11_unknown_direction_handling(baseline_engine: BehavioralBaselineEngine, extractor: FeatureExtractor):
    """Verify unknown direction is cleanly identified in behavior key."""
    evt_dir = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="p.exe",
        process_id=10,
        direction="UNKNOWN",
    )
    fv_dir = extractor.extract(evt_dir)
    assert fv_dir.values["direction_unknown"] == 1.0
    rec = baseline_engine.update_baseline(fv_dir)
    assert "UNKNOWN" in rec.behavior_key


# 12. Suspicious event statistic freeze
def test_12_suspicious_event_statistic_freeze(baseline_engine: BehavioralBaselineEngine):
    """Verify event with high anomaly score (>=0.7) freezes Welford statistics."""
    fv = _make_feature_vector(conn_freq=5.0)

    # Establish baseline
    for _ in range(6):
        baseline_engine.update_baseline(fv, anomaly_score=0.1)

    rec = baseline_engine.get_record(fv.behavior_key)
    assert rec.status == BehaviorStatus.KNOWN_BENIGN
    prev_mean = rec.metrics["connection_frequency"].mean
    prev_count = rec.metrics["connection_frequency"].count

    # Inject extreme anomalous spike with high anomaly score
    fv_spike = _make_feature_vector(conn_freq=5000.0)
    baseline_engine.update_baseline(fv_spike, anomaly_score=0.85)

    assert rec.status == BehaviorStatus.SUSPICIOUS
    # Statistics MUST remain frozen
    assert rec.metrics["connection_frequency"].mean == prev_mean
    assert rec.metrics["connection_frequency"].count == prev_count


# 13. Quarantined event freeze
def test_13_quarantined_event_freeze(baseline_engine: BehavioralBaselineEngine):
    """Verify quarantined identity never updates statistics."""
    fv = _make_feature_vector()
    baseline_engine.update_baseline(fv)
    baseline_engine.quarantine_behavior(fv.behavior_key)

    rec = baseline_engine.get_record(fv.behavior_key)
    assert rec.status == BehaviorStatus.QUARANTINED
    assert rec.confidence == 0.05

    # Any subsequent updates must be rejected
    baseline_engine.update_baseline(fv, anomaly_score=0.0)
    assert rec.metrics["connection_frequency"].count == 0


# 14. Baseline poisoning attempt
def test_14_baseline_poisoning_attempt(baseline_engine: BehavioralBaselineEngine):
    """Verify 50 consecutive anomalous attacks fail to shift trusted baseline mean."""
    fv_normal = _make_feature_vector(conn_freq=2.0)
    for _ in range(10):
        baseline_engine.update_baseline(fv_normal, anomaly_score=0.0)

    rec = baseline_engine.get_record(fv_normal.behavior_key)
    trusted_mean = rec.metrics["connection_frequency"].mean
    assert pytest.approx(trusted_mean, rel=1e-3) == 2.0

    # Adversarial poisoning burst
    fv_attack = _make_feature_vector(conn_freq=9999.0)
    for _ in range(50):
        baseline_engine.update_baseline(fv_attack, anomaly_score=0.90)

    # Trusted mean MUST NOT have changed
    assert rec.metrics["connection_frequency"].mean == trusted_mean


# 15. Persistence and summary
def test_15_persistence_and_summary(baseline_engine: BehavioralBaselineEngine, tmp_path: Path):
    """Verify save() writes versioned JSON and get_summary() returns accurate counts."""
    fv1 = _make_feature_vector(proc_name="app1.exe")
    fv2 = _make_feature_vector(proc_name="app2.exe")

    baseline_engine.update_baseline(fv1)
    baseline_engine.update_baseline(fv2)
    baseline_engine.save()

    assert baseline_engine.storage_path.exists()
    summary = baseline_engine.get_summary()

    assert summary["baseline_version"] == BASELINE_VERSION
    assert summary["total_behavior_keys"] == 2
    assert summary["status_counts"]["NEW"] == 2


# 16. Reload state integrity
def test_16_reload_state_integrity(tmp_path: Path):
    """Verify load() cleanly reconstructs records, metrics, counts, and confidence."""
    storage_file = tmp_path / "baseline_reload.json"
    engine1 = BehavioralBaselineEngine(storage_path=storage_file)

    fv = _make_feature_vector(conn_freq=10.0)
    for _ in range(6):
        engine1.update_baseline(fv, anomaly_score=0.0)
    engine1.save()

    # New engine loading from same storage
    engine2 = BehavioralBaselineEngine(storage_path=storage_file)
    rec = engine2.get_record(fv.behavior_key)

    assert rec is not None
    assert rec.status == BehaviorStatus.KNOWN_BENIGN
    assert rec.observation_count == 6
    assert pytest.approx(rec.metrics["connection_frequency"].mean, rel=1e-3) == 10.0


# 17. Version compatibility
def test_17_version_compatibility():
    """Verify BASELINE_VERSION is '1.0' and from_dict handles unversioned dictionaries."""
    assert BASELINE_VERSION == "1.0"
    raw_dict = {
        "behavior_key": "test_key",
        "process_name": "proc.exe",
        "observation_count": 3,
        "status": "OBSERVING",
        "confidence": 0.4,
        "metrics": {"connection_frequency": {"count": 2, "mean": 5.0, "variance": 1.0, "stddev": 1.0}},
    }
    rec = BehavioralRecord.from_dict(raw_dict)
    assert rec.behavior_key == "test_key"
    assert rec.status == BehaviorStatus.OBSERVING
    assert rec.metrics["connection_frequency"].mean == 5.0


# 18. Numerical stability with extreme values
def test_18_numerical_stability_extremes():
    """Verify Welford accumulator handles tiny numbers, large numbers, and identical values."""
    # Tiny numbers
    m_tiny = BaselineMetric()
    for _ in range(100):
        m_tiny.update(1e-7)
    assert pytest.approx(m_tiny.mean, rel=1e-5) == 1e-7
    assert m_tiny.variance == 0.0

    # Large numbers
    m_large = BaselineMetric()
    for _ in range(100):
        m_large.update(1e9)
    assert pytest.approx(m_large.mean, rel=1e-5) == 1e9
    assert m_large.variance == 0.0

    # Repeated identical values
    m_ident = BaselineMetric()
    for _ in range(50):
        m_ident.update(42.0)
    assert m_ident.mean == 42.0
    assert m_ident.stddev == 0.0
    assert m_ident.z_score(42.0) == 0.0


# 19. Large observation count stability
def test_19_large_observation_count_stability():
    """Verify Welford stability over 100,000 observations without float drift or overflow."""
    metric = BaselineMetric()
    for i in range(100_000):
        metric.update(10.0 + (i % 5))

    expected_mean = statistics.mean([10.0, 11.0, 12.0, 13.0, 14.0])
    assert metric.count == 100_000
    assert pytest.approx(metric.mean, rel=1e-4) == expected_mean
    assert math.isfinite(metric.variance)
    assert math.isfinite(metric.stddev)


# 20. Empty baseline handling & deviation calculation
def test_20_empty_baseline_handling(baseline_engine: BehavioralBaselineEngine):
    """Verify compute_deviation() on an empty/unknown baseline returns safe is_novel=True."""
    fv = _make_feature_vector(proc_name="unknown_proc.exe")
    dev = baseline_engine.compute_deviation(fv)

    assert dev.is_novel is True
    assert dev.novelty_score == 1.0
    assert dev.status == BehaviorStatus.NEW
    assert dev.confidence == 0.10
    assert dev.observation_count == 0
    assert dev.max_z_score == 0.0
    assert len(dev.deviating_features) == 0
    assert "connection_frequency" in dev.feature_deviations
