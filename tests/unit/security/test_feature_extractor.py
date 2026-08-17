"""Comprehensive unit test suite for P2.2 Feature Extraction Engine."""

import time
import math
import numpy as np
import pytest

from backend.security.behavioral_models import BehavioralEvent
from backend.security.features import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    BehavioralFeatures,
    FeatureExtractor,
    FeatureVector,
)


@pytest.fixture
def extractor() -> FeatureExtractor:
    """Fixture providing clean FeatureExtractor instance."""
    return FeatureExtractor(history_window_sec=300.0)


# 1. Normal network event
def test_01_normal_network_event(extractor: FeatureExtractor):
    """Verify feature extraction for a standard network connection event."""
    ts = time.time()
    evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="chrome.exe",
        process_id=1234,
        parent_process_id=1000,
        executable_path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
        executable_hash="sha256_hash_abc",
        signed_status=True,
        local_ip="192.168.1.10",
        local_port=54321,
        remote_ip="142.250.190.46",
        remote_port=443,
        protocol="TCP",
        direction="OUTBOUND",
        connection_state="ESTABLISHED",
        bytes_sent=1500,
        bytes_received=5000,
    )

    fv = extractor.extract(evt)

    assert isinstance(fv, FeatureVector)
    assert fv.feature_version == FEATURE_VERSION
    assert fv.process_name == "chrome.exe"
    assert fv.remote_ip == "142.250.190.46"
    assert fv.remote_port == 443
    assert fv.values["signed_status_val"] == 1.0
    assert fv.values["has_parent_process"] == 1.0
    assert fv.values["proto_tcp"] == 1.0
    assert fv.values["direction_outbound"] == 1.0
    assert fv.values["bytes_sent_log"] == round(math.log1p(1500), 4)
    assert fv.values["bytes_received_log"] == round(math.log1p(5000), 4)


# 2. Process event (PROCESS_START / PROCESS_STOP)
def test_02_process_event(extractor: FeatureExtractor):
    """Verify feature extraction for process lifecycle events (no remote IP/port)."""
    ts = time.time()
    start_evt = BehavioralEvent(
        timestamp=ts,
        event_type="PROCESS_START",
        process_name="notepad.exe",
        process_id=4321,
        parent_process_id=1234,
        signed_status=True,
    )

    fv = extractor.extract(start_evt)

    assert fv.process_name == "notepad.exe"
    assert fv.remote_ip is None
    assert fv.remote_port is None
    assert fv.values["unique_destinations_count"] == 1.0
    assert fv.values["unique_ports_count"] == 1.0
    assert fv.values["is_new_destination"] == 0.0
    assert fv.values["is_new_port"] == 0.0


# 3. Missing optional fields
def test_03_missing_optional_fields(extractor: FeatureExtractor):
    """Verify graceful extraction handling when optional telemetry fields are missing."""
    ts = time.time()
    minimal_evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="bare_proc.exe",
        process_id=999,
        # Missing: parent_process_id, executable_path, signed_status, local_ip/port,
        # remote_ip/port, protocol, direction, bytes, state
    )

    fv = extractor.extract(minimal_evt)

    assert fv.values["has_parent_process"] == 0.0
    assert fv.values["signed_status_val"] == 0.5  # Neutral default for unverified status
    assert fv.values["bytes_sent_log"] == 0.0
    assert fv.values["bytes_received_log"] == 0.0
    assert fv.values["inbound_outbound_ratio"] == 0.5  # Neutral default
    assert fv.values["proto_tcp"] == 1.0  # Default protocol TCP
    assert fv.values["direction_unknown"] == 1.0
    assert len(fv.vector) == len(FEATURE_NAMES)


# 4. New destination
def test_04_new_destination(extractor: FeatureExtractor):
    """Verify flag is_new_destination is 1.0 for first contact with remote IP."""
    ts = time.time()
    evt1 = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="app.exe",
        process_id=500,
        remote_ip="1.1.1.1",
        remote_port=80,
    )
    evt2 = BehavioralEvent(
        timestamp=ts + 1,
        event_type="NETWORK_CONNECTION",
        process_name="app.exe",
        process_id=500,
        remote_ip="2.2.2.2",
        remote_port=80,
    )

    fv1 = extractor.extract(evt1, recent_events=[])
    assert fv1.values["is_new_destination"] == 1.0

    fv2 = extractor.extract(evt2, recent_events=[evt1])
    assert fv2.values["is_new_destination"] == 1.0
    assert fv2.values["unique_destinations_count"] == 2.0


# 5. New port
def test_05_new_port(extractor: FeatureExtractor):
    """Verify flag is_new_port is 1.0 when contacting a new port."""
    ts = time.time()
    evt1 = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="app.exe",
        process_id=500,
        remote_ip="1.1.1.1",
        remote_port=80,
    )
    evt2 = BehavioralEvent(
        timestamp=ts + 1,
        event_type="NETWORK_CONNECTION",
        process_name="app.exe",
        process_id=500,
        remote_ip="1.1.1.1",
        remote_port=8443,
    )

    fv2 = extractor.extract(evt2, recent_events=[evt1])
    assert fv2.values["is_new_port"] == 1.0
    assert fv2.values["is_new_destination"] == 0.0
    assert fv2.values["unique_ports_count"] == 2.0


# 6. High connection frequency
def test_06_high_connection_frequency(extractor: FeatureExtractor):
    """Verify per-minute connection frequency calculation under high rate."""
    ts = time.time()
    history = [
        BehavioralEvent(
            timestamp=ts - (i * 0.5),
            event_type="NETWORK_CONNECTION",
            process_name="spiker.exe",
            process_id=700,
            remote_ip="10.0.0.1",
            remote_port=443,
        )
        for i in range(50)
    ]

    current_evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="spiker.exe",
        process_id=700,
        remote_ip="10.0.0.1",
        remote_port=443,
    )

    fv = extractor.extract(current_evt, recent_events=history)
    assert fv.values["connection_frequency"] > 5.0
    assert fv.values["process_frequency"] > 5.0


# 7. High traffic volume
def test_07_high_traffic_volume(extractor: FeatureExtractor):
    """Verify logarithmic byte scaling for high traffic volume."""
    ts = time.time()
    large_traffic_evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="downloader.exe",
        process_id=800,
        bytes_sent=10_000_000,
        bytes_received=500_000_000,
    )

    fv = extractor.extract(large_traffic_evt)

    assert fv.values["bytes_sent_log"] == round(math.log1p(10_000_000), 4)
    assert fv.values["bytes_received_log"] == round(math.log1p(500_000_000), 4)
    assert 0.98 < fv.values["inbound_outbound_ratio"] <= 1.0


# 8. Inbound traffic
def test_08_inbound_traffic(extractor: FeatureExtractor):
    """Verify feature encoding for inbound connections."""
    ts = time.time()
    inbound_evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="server.exe",
        process_id=900,
        direction="INBOUND",
        connection_state="LISTEN",
    )

    fv = extractor.extract(inbound_evt)

    assert fv.values["direction_inbound"] == 1.0
    assert fv.values["direction_outbound"] == 0.0
    assert fv.values["state_listen"] == 1.0


# 9. Outbound traffic
def test_09_outbound_traffic(extractor: FeatureExtractor):
    """Verify feature encoding for outbound connections."""
    ts = time.time()
    outbound_evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="client.exe",
        process_id=950,
        direction="OUTBOUND",
        connection_state="ESTABLISHED",
    )

    fv = extractor.extract(outbound_evt)

    assert fv.values["direction_outbound"] == 1.0
    assert fv.values["direction_inbound"] == 0.0
    assert fv.values["state_established"] == 1.0


# 10. Different protocols
def test_10_different_protocols(extractor: FeatureExtractor):
    """Verify protocol distribution encoding across TCP, UDP, ICMP, and RAW."""
    ts = time.time()
    tcp_evt = BehavioralEvent(timestamp=ts, event_type="NETWORK_CONNECTION", process_name="p.exe", process_id=1, protocol="TCP")
    udp_evt = BehavioralEvent(timestamp=ts, event_type="NETWORK_CONNECTION", process_name="p.exe", process_id=1, protocol="UDP")
    icmp_evt = BehavioralEvent(timestamp=ts, event_type="NETWORK_CONNECTION", process_name="p.exe", process_id=1, protocol="ICMP")
    raw_evt = BehavioralEvent(timestamp=ts, event_type="NETWORK_CONNECTION", process_name="p.exe", process_id=1, protocol="RAW")

    fv_tcp = extractor.extract(tcp_evt)
    assert fv_tcp.values["proto_tcp"] == 1.0 and fv_tcp.values["proto_udp"] == 0.0

    fv_udp = extractor.extract(udp_evt)
    assert fv_udp.values["proto_udp"] == 1.0 and fv_udp.values["proto_tcp"] == 0.0

    fv_icmp = extractor.extract(icmp_evt)
    assert fv_icmp.values["proto_icmp"] == 1.0

    fv_raw = extractor.extract(raw_evt)
    assert fv_raw.values["proto_other"] == 1.0


# 11. Malformed / incomplete event
def test_11_malformed_incomplete_event(extractor: FeatureExtractor):
    """Verify malformed or empty data fields do not cause runtime crashes."""
    evt = BehavioralEvent(
        timestamp=0.0,
        event_type="UNKNOWN",
        process_name="",
        process_id=0,
        remote_ip="invalid_ip",
        remote_port=0,
        protocol="INVALID_PROTO",
        bytes_sent=-100,
        bytes_received=-500,
    )

    fv = extractor.extract(evt)

    assert isinstance(fv, FeatureVector)
    assert len(fv.vector) == len(FEATURE_NAMES)
    assert fv.values["bytes_sent_log"] == 0.0
    assert fv.values["bytes_received_log"] == 0.0


# 12. Deterministic output
def test_12_deterministic_output(extractor: FeatureExtractor):
    """Verify exact same input BehavioralEvent yields identical FeatureVector."""
    ts = 1700000000.0
    evt = BehavioralEvent(
        timestamp=ts,
        event_type="NETWORK_CONNECTION",
        process_name="det_test.exe",
        process_id=123,
        remote_ip="1.1.1.1",
        remote_port=80,
        protocol="TCP",
        bytes_sent=200,
    )

    fv1 = extractor.extract(evt)
    fv2 = extractor.extract(evt)

    assert fv1.vector == fv2.vector
    assert fv1.values == fv2.values
    assert fv1.behavior_identity_key == fv2.behavior_identity_key


# 13. Feature version
def test_13_feature_version(extractor: FeatureExtractor):
    """Verify FeatureVector contains feature_version '1.0'."""
    evt = BehavioralEvent(timestamp=time.time(), event_type="PROCESS_START", process_name="v.exe", process_id=1)
    fv = extractor.extract(evt)

    assert fv.feature_version == "1.0"
    assert FEATURE_VERSION == "1.0"


# 14. Numerical output compatibility (NumPy / scikit-learn)
def test_14_numerical_output_compatibility(extractor: FeatureExtractor):
    """Verify FeatureVector produces valid NumPy 1D float array for scikit-learn estimators."""
    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="ml_test.exe",
        process_id=55,
        remote_ip="8.8.8.8",
        remote_port=53,
    )

    fv = extractor.extract(evt)
    arr = fv.to_numpy()

    assert isinstance(arr, np.ndarray)
    assert arr.dtype == np.float64
    assert arr.ndim == 1
    assert len(arr) == len(FEATURE_NAMES)

    # Verify reshaping for scikit-learn predict(X)
    X = arr.reshape(1, -1)
    assert X.shape == (1, len(FEATURE_NAMES))


# 15. No raw IP used as numerical feature
def test_15_no_raw_ip_in_numerical_vector(extractor: FeatureExtractor):
    """Verify raw IP address strings are excluded from numerical ML feature vector."""
    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="ip_test.exe",
        process_id=77,
        remote_ip="192.168.1.100",
        remote_port=8080,
    )

    fv = extractor.extract(evt)

    # Every item in vector must be a float
    for val in fv.vector:
        assert isinstance(val, (int, float))

    # IP string exists in metadata only
    assert fv.metadata["remote_ip"] == "192.168.1.100"
    assert "192.168.1.100" not in fv.values.values()


# 16. No PID used as numerical behavioral feature
def test_16_no_pid_in_numerical_vector(extractor: FeatureExtractor):
    """Verify raw Process Identifiers (PIDs) are excluded from numerical ML vector."""
    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="pid_test.exe",
        process_id=98765,
        parent_process_id=12345,
    )

    fv = extractor.extract(evt)

    # Raw PID numbers 98765, 12345 must NOT be present in vector values
    assert 98765.0 not in fv.vector
    assert 12345.0 not in fv.vector
    assert fv.metadata["process_id"] == 98765


# 17. Serialization / Deserialization
def test_17_serialization_deserialization(extractor: FeatureExtractor):
    """Verify to_dict() and from_dict() roundtrip serialization integrity."""
    evt = BehavioralEvent(
        timestamp=1700000000.0,
        event_type="NETWORK_CONNECTION",
        process_name="ser_test.exe",
        process_id=300,
        remote_ip="10.0.0.1",
        remote_port=443,
        bytes_sent=1024,
    )

    fv_orig = extractor.extract(evt)
    d = fv_orig.to_dict()

    fv_restored = FeatureVector.from_dict(d)

    assert fv_restored.feature_version == fv_orig.feature_version
    assert fv_restored.behavior_identity_key == fv_orig.behavior_identity_key
    assert fv_restored.timestamp == fv_orig.timestamp
    assert fv_restored.vector == fv_orig.vector
    assert fv_restored.values == fv_orig.values
    assert fv_restored.metadata == fv_orig.metadata


# 18. Backward compatibility
def test_18_backward_compatibility(extractor: FeatureExtractor):
    """Verify BehavioralFeatures alias and property accessors for legacy Phase 2 engines."""
    evt = BehavioralEvent(
        timestamp=time.time(),
        event_type="NETWORK_CONNECTION",
        process_name="legacy.exe",
        process_id=400,
        remote_ip="1.1.1.1",
        remote_port=80,
    )

    feats: BehavioralFeatures = extractor.extract(evt)

    assert feats.behavior_key == evt.behavior_identity_key
    assert feats.process_name == "legacy.exe"
    assert feats.unique_destinations_count == 1
    assert feats.unique_ports_count == 1
    assert "process_frequency" in feats.raw_features
    assert "unique_destinations" in feats.raw_features
    assert "unique_ports" in feats.raw_features
    assert "remote_port" in feats.raw_features
