"""Unit tests for Phase 2 P2.1 BehavioralEvent contract and validation."""

import pytest
import time
from app.schemas.events import ConnectionDirection, NetworkConnectionEvent, ProcessStartEvent
from backend.security.baseline import BehavioralBaselineEngine
from backend.security.behavioral_models import BehavioralEvent, BehaviorStatus
from backend.security.features import FeatureExtractor


def test_1_valid_network_event() -> None:
    """Verify constructing valid network event with all required fields."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="chrome.exe",
        process_id=1234,
        executable_path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
        local_ip="192.168.1.50",
        local_port=54321,
        remote_ip="142.250.190.46",
        remote_port=443,
        protocol="TCP",
        direction="OUTBOUND",
        connection_state="ESTABLISHED",
    )
    assert event.event_type == "NETWORK_CONNECTION"
    assert event.process_name == "chrome.exe"
    assert event.local_port == 54321
    assert event.remote_port == 443
    assert event.protocol == "TCP"
    assert event.direction == "OUTBOUND"
    assert event.event_id.startswith("evt_")


def test_2_valid_process_event() -> None:
    """Verify constructing valid process event with process metadata."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="PROCESS_START",
        process_name="cmd.exe",
        process_id=5678,
        parent_process_id=1000,
        executable_path="C:\\Windows\\System32\\cmd.exe",
        signed_status=True,
    )
    assert event.event_type == "PROCESS_START"
    assert event.process_name == "cmd.exe"
    assert event.parent_process_id == 1000
    assert event.signed_status is True


def test_3_missing_optional_fields() -> None:
    """Verify event construction with missing optional fields defaults gracefully."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="PROCESS_STOP",
        process_name="worker.exe",
        process_id=9999,
    )
    assert event.executable_path is None
    assert event.remote_ip is None
    assert event.remote_port is None
    assert event.direction == "UNKNOWN"
    assert event.protocol == "TCP"


def test_4_invalid_port_validation() -> None:
    """Verify out-of-range port numbers raise ValueError."""
    with pytest.raises(ValueError, match="Invalid local_port out of range"):
        BehavioralEvent(
            timestamp=1700000000.0,
            event_type="NETWORK_CONNECTION",
            process_name="test.exe",
            process_id=100,
            local_port=70000,
        )

    with pytest.raises(ValueError, match="Invalid remote_port out of range"):
        BehavioralEvent(
            timestamp=1700000000.0,
            event_type="NETWORK_CONNECTION",
            process_name="test.exe",
            process_id=100,
            remote_port=-5,
        )


def test_5_invalid_protocol_validation() -> None:
    """Verify unrecognized protocols normalize to UNKNOWN."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="test.exe",
        process_id=100,
        protocol="INVALID_PROTO",
    )
    assert event.protocol == "UNKNOWN"


def test_6_invalid_direction_validation() -> None:
    """Verify unrecognized direction string normalizes to UNKNOWN."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="test.exe",
        process_id=100,
        direction="MAGIC_DIRECTION",
    )
    assert event.direction == "UNKNOWN"


def test_7_malformed_ip_sanitization() -> None:
    """Verify malformed IP strings are sanitized to invalid_ip."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="test.exe",
        process_id=100,
        remote_ip="not_an_ip_address!!!",
    )
    assert event.remote_ip == "invalid_ip"


def test_8_serialization_deserialization() -> None:
    """Verify to_dict and from_dict produce identical event models."""
    event1 = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="curl.exe",
        process_id=4321,
        executable_path="C:\\Tools\\curl.exe",
        executable_hash="a1b2c3d4e5f6",
        remote_ip="93.184.216.34",
        remote_port=80,
        protocol="TCP",
        direction="OUTBOUND",
    )
    d = event1.to_dict()
    event2 = BehavioralEvent.from_dict(d)

    assert event2.event_id == event1.event_id
    assert event2.process_name == event1.process_name
    assert event2.executable_hash == event1.executable_hash
    assert event2.remote_ip == event1.remote_ip
    assert event2.behavior_identity_key == event1.behavior_identity_key


def test_9_event_behavior_identity_key() -> None:
    """Verify behavior_identity_key format and uniqueness."""
    event = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="python.exe",
        process_id=8888,
        executable_path="C:\\Python\\python.exe",
        executable_hash="hash123",
        remote_ip="1.1.1.1",
        remote_port=53,
        protocol="UDP",
        direction="OUTBOUND",
    )
    expected_key = "python.exe|hash123|1.1.1.1:53|UDP|OUTBOUND"
    assert event.behavior_identity_key == expected_key


def test_10_learning_state_transitions() -> None:
    """Verify baseline learning transitions (NEW -> OBSERVING -> KNOWN_BENIGN)."""
    base_engine = BehavioralBaselineEngine(min_observe_count=3, min_trust_count=5)
    extractor = FeatureExtractor()

    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="svchost.exe",
        process_id=1000,
        remote_ip="8.8.8.8",
        remote_port=53,
        protocol="UDP",
    )
    feats = extractor.extract(evt)

    # 1. First record -> NEW
    rec1 = base_engine.update_baseline(feats, anomaly_score=0.1)
    assert rec1.status == BehaviorStatus.NEW

    # 2. Reached min_observe_count (3) -> OBSERVING
    base_engine.update_baseline(feats, anomaly_score=0.1)
    rec3 = base_engine.update_baseline(feats, anomaly_score=0.1)
    assert rec3.status == BehaviorStatus.OBSERVING

    # 3. Reached min_trust_count (5) -> KNOWN_BENIGN
    base_engine.update_baseline(feats, anomaly_score=0.1)
    rec5 = base_engine.update_baseline(feats, anomaly_score=0.1)
    assert rec5.status == BehaviorStatus.KNOWN_BENIGN


def test_11_suspicious_event_does_not_poison_baseline() -> None:
    """Verify high anomaly suspicious events DO NOT pollute baseline statistics."""
    base_engine = BehavioralBaselineEngine()
    extractor = FeatureExtractor()

    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="trusted_app.exe",
        process_id=2000,
        remote_ip="10.0.0.1",
        remote_port=80,
    )
    feats = extractor.extract(evt)

    # Establish baseline
    for _ in range(5):
        base_engine.update_baseline(feats, anomaly_score=0.1)

    rec_before = base_engine.get_record(feats.behavior_key)
    before_count = rec_before.metrics["process_frequency"].count

    # Inject high anomaly observation
    base_engine.update_baseline(feats, anomaly_score=0.95)
    rec_after = base_engine.get_record(feats.behavior_key)

    assert rec_after.status == BehaviorStatus.SUSPICIOUS
    assert rec_after.metrics["process_frequency"].count == before_count


def test_12_from_security_event_conversion() -> None:
    """Verify converting Phase 1 SecurityEvent schema objects into Phase 2 BehavioralEvents."""
    p_start = ProcessStartEvent(
        process_id=500,
        parent_process_id=10,
        process_name="notepad.exe",
        executable_path="C:\\Windows\\notepad.exe",
        publisher="Microsoft Corporation",
        is_signed=True,
    )
    b_event = BehavioralEvent.from_security_event(p_start)
    assert b_event.event_type == "PROCESS_START"
    assert b_event.process_name == "notepad.exe"
    assert b_event.signed_status is True
    assert b_event.metadata["publisher"] == "Microsoft Corporation"

    n_conn = NetworkConnectionEvent(
        process_id=500,
        process_name="notepad.exe",
        local_address="127.0.0.1",
        local_port=12345,
        remote_address="93.184.216.34",
        remote_port=80,
        protocol="TCP",
        direction=ConnectionDirection.OUTBOUND,
        connection_state="ESTABLISHED",
    )
    b_net = BehavioralEvent.from_security_event(n_conn)
    assert b_net.event_type == "NETWORK_CONNECTION"
    assert b_net.remote_ip == "93.184.216.34"
    assert b_net.remote_port == 80
    assert b_net.direction == "OUTBOUND"
