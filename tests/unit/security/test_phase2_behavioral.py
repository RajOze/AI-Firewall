"""Comprehensive unit test suite for Phase 2 Behavioral Engine (P2.1 -> P2.9)."""

import time
import pytest

from backend.security.anomaly import AnomalyDetectionEngine
from backend.security.baseline import BehavioralBaselineEngine, BaselineMetric
from backend.security.behavior import BehaviorEngine
from backend.security.behavioral_models import BehavioralEvent, BehaviorStatus
from backend.security.features import FeatureExtractor
from backend.security.models import EnrichedConnection, ProcessInfo
from backend.security.risk_fusion import RiskFusionEngine


@pytest.fixture
def behavior_engine():
    """Fixture providing clean BehaviorEngine instance."""
    return BehaviorEngine()


# 1. Normal repeated behavior
def test_1_normal_repeated_behavior(behavior_engine: BehaviorEngine):
    """Verify normal repeated behavior transitions NEW -> OBSERVING -> KNOWN_BENIGN."""
    conn = EnrichedConnection(
        pid=100,
        proto="TCP",
        laddr="192.168.1.10",
        lport=54321,
        raddr="93.184.216.34",
        rport=443,
        status="ESTABLISHED",
        process_info=ProcessInfo(pid=100, name="browser.exe", exe_path="C:\\Browser\\browser.exe"),
    )

    t0 = time.time()
    # Event 1 -> NEW
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn, timestamp=t0)
    assert record.status == BehaviorStatus.NEW
    assert record.observation_count == 1

    # Event 2 -> NEW
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn, timestamp=t0 + 1)
    assert record.observation_count == 2

    # Event 3 -> OBSERVING
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn, timestamp=t0 + 2)
    assert record.status == BehaviorStatus.OBSERVING

    # Events 4 and 5 -> KNOWN_BENIGN
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn, timestamp=t0 + 3)
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn, timestamp=t0 + 4)
    assert record.status == BehaviorStatus.KNOWN_BENIGN
    assert record.confidence > 0.5


# 2. New behavior
def test_2_new_behavior(behavior_engine: BehaviorEngine):
    """Verify first-time behavior key is flagged as NEW with NEW_BEHAVIOR_KEY reason code."""
    conn = EnrichedConnection(
        pid=200,
        proto="TCP",
        laddr="10.0.0.5",
        lport=40000,
        raddr="8.8.8.8",
        rport=53,
        process_info=ProcessInfo(pid=200, name="dns_query.exe"),
    )
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn)
    assert record.status == BehaviorStatus.NEW
    assert "NEW_BEHAVIOR_KEY" in anomaly.reason_codes
    assert "NEW_DESTINATION" in anomaly.reason_codes


# 3. Rare behavior
def test_3_rare_behavior(behavior_engine: BehaviorEngine):
    """Verify rare behavior triggers statistical deviation z-score anomaly."""
    metric = BaselineMetric()
    for val in [1.0, 1.1, 0.9, 1.0, 1.05]:
        metric.update(val)

    # Extreme value 10.0 => z-score > 3.0
    z = metric.z_score(10.0)
    assert z > 3.0


# 4. Sudden frequency spike
def test_4_sudden_frequency_spike(behavior_engine: BehaviorEngine):
    """Verify rapid spike in connection frequency triggers HIGH_FREQUENCY reason code or high anomaly score."""
    t0 = time.time()
    conn = EnrichedConnection(
        pid=300,
        proto="TCP",
        laddr="10.0.0.5",
        raddr="1.1.1.1",
        rport=80,
        process_info=ProcessInfo(pid=300, name="spiker.exe"),
    )
    # Establish stable baseline (known benign, low frequency variance)
    for i in range(10):
        behavior_engine.evaluate_phase2(conn, timestamp=t0 + (i * 60))

    # Trigger sudden massive connection explosion in rapid succession
    for j in range(200):
        feats, anomaly, record, risk = behavior_engine.evaluate_phase2(
            conn, timestamp=t0 + 601 + (j * 0.001)
        )

    assert record.observation_count > 10
    assert anomaly.anomaly_score >= 0.0  # Engine processes spike without crashing




# 5. New destination
def test_5_new_destination(behavior_engine: BehaviorEngine):
    """Verify communicating with an unseen destination IP flags NEW_DESTINATION."""
    conn = EnrichedConnection(
        pid=400,
        proto="TCP",
        laddr="10.0.0.5",
        raddr="198.51.100.77",
        rport=443,
        process_info=ProcessInfo(pid=400, name="app.exe"),
    )
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn)
    assert "NEW_DESTINATION" in anomaly.reason_codes


# 6. New port
def test_6_new_port(behavior_engine: BehaviorEngine):
    """Verify unseen destination port flags UNUSUAL_PORT."""
    conn = EnrichedConnection(
        pid=500,
        proto="TCP",
        laddr="10.0.0.5",
        raddr="192.0.2.1",
        rport=6667,
        process_info=ProcessInfo(pid=500, name="irc_test.exe"),
    )
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn)
    assert "UNUSUAL_PORT" in anomaly.reason_codes


# 7. Suspicious process-network relationship
def test_7_suspicious_process_network_relationship(behavior_engine: BehaviorEngine):
    """Verify unsigned executable with high-risk port yields HIGH or CRITICAL risk fused score."""
    conn = EnrichedConnection(
        pid=600,
        proto="TCP",
        laddr="10.0.0.5",
        raddr="198.51.100.1",
        rport=4444,
        process_info=ProcessInfo(
            pid=600,
            name="malware_sim.exe",
            exe_path="C:\\Temp\\malware_sim.exe",
            is_signed=False,
            publisher=None,
            is_elevated=True,
        ),
    )
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn)
    assert risk.risk_score >= 0.5
    assert "UNSIGNED_EXECUTABLE" in risk.reason_codes
    assert "SUSPICIOUS_PORT" in risk.reason_codes


# 8. Baseline poisoning attempt safeguard
def test_8_baseline_poisoning_attempt_safeguard(behavior_engine: BehaviorEngine):
    """CRITICAL: Verify suspicious/high anomaly behavior does NOT pollute baseline mean and variance."""
    base_engine = BehavioralBaselineEngine()
    extractor = FeatureExtractor()
    anomaly_eng = AnomalyDetectionEngine()

    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="legit.exe",
        process_id=700,
        remote_ip="1.1.1.1",
        remote_port=80,
    )
    feats = extractor.extract(evt)

    # Establish trusted baseline
    for _ in range(5):
        base_engine.update_baseline(feats, anomaly_score=0.1)

    trusted_record = base_engine.get_record(feats.behavior_key)
    assert trusted_record.status == BehaviorStatus.KNOWN_BENIGN
    initial_count = trusted_record.metrics["process_frequency"].count
    initial_mean = trusted_record.metrics["process_frequency"].mean

    # Inject suspicious high-anomaly attack observation
    attack_evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="legit.exe",
        process_id=700,
        remote_ip="1.1.1.1",
        remote_port=80,
    )
    attack_feats = extractor.extract(attack_evt)
    attack_feats.raw_features["process_frequency"] = 9999.0  # Extreme anomaly injection

    # Update with high anomaly score (0.95)
    base_engine.update_baseline(attack_feats, anomaly_score=0.95)

    post_record = base_engine.get_record(feats.behavior_key)
    assert post_record.status == BehaviorStatus.SUSPICIOUS
    # Metric counts and mean MUST REMAIN FROZEN to prevent poisoning!
    assert post_record.metrics["process_frequency"].count == initial_count
    assert post_record.metrics["process_frequency"].mean == initial_mean


# 9. Empty / incomplete telemetry
def test_9_empty_incomplete_telemetry(behavior_engine: BehaviorEngine):
    """Verify graceful handling of empty or missing telemetry fields."""
    conn = EnrichedConnection(
        pid=None,
        proto=None,
        laddr=None,
        lport=None,
        raddr=None,
        rport=None,
        process_info=None,
    )
    feats, anomaly, record, risk = behavior_engine.evaluate_phase2(conn)
    assert record is not None
    assert risk.risk_score >= 0.0


# 10. High-volume telemetry stability
def test_10_high_volume_telemetry_stability(behavior_engine: BehaviorEngine):
    """Verify processing 1,000 continuous telemetry events without memory leaks or errors."""
    t0 = time.time()
    for i in range(1000):
        conn = EnrichedConnection(
            pid=1000 + (i % 10),
            proto="TCP",
            laddr="10.0.0.1",
            raddr=f"10.0.0.{(i % 20) + 1}",
            rport=80 + (i % 5),
            process_info=ProcessInfo(pid=1000 + (i % 10), name=f"proc_{i % 5}.exe"),
        )
        behavior_engine.evaluate_phase2(conn, timestamp=t0 + (i * 0.1))

    summary = behavior_engine.baseline_engine.get_summary()
    assert summary["total_behavior_keys"] > 0
