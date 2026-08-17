"""Compact Feature Extraction Engine for Phase 2 Behavioral Telemetry (P2.2).

Converts standardized BehavioralEvent objects into compact, normalized behavioral
FeatureVector objects suitable for statistical baselines, anomaly detection, risk fusion,
and ML models.
"""

import math
from dataclasses import dataclass, field
from typing import Any

from backend.security.behavioral_models import BehavioralEvent

FEATURE_VERSION = "1.0"

# Canonical ordered feature names for statistical ML models
FEATURE_NAMES: list[str] = [
    "process_frequency",
    "process_lifetime_sec",
    "has_parent_process",
    "signed_status_val",
    "connection_frequency",
    "unique_destinations_count",
    "unique_ports_count",
    "bytes_sent_log",
    "bytes_received_log",
    "inbound_outbound_ratio",
    "failed_connection_rate",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
    "direction_inbound",
    "direction_outbound",
    "direction_unknown",
    "state_established",
    "state_listen",
    "state_other",
    "is_new_destination",
    "is_new_port",
    "is_new_protocol",
    "is_new_process_net_rel",
    "is_first_seen_behavior",
]


@dataclass
class FeatureVector:
    """Standardized Feature Vector contract for Phase 2 ML models and baseline engines.

    Attributes:
        feature_version: Version identifier string for schema compatibility (e.g., "1.0").
        behavior_identity_key: Canonical identifier key for process-network relationship.
        timestamp: Event timestamp in epoch seconds.
        feature_names: List of feature names matching vector ordering.
        vector: Pure numerical feature values list for ML estimators.
        values: Dictionary mapping feature name to normalized numerical float value.
        categorical_encoded: Encoded categorical variables mapping.
        metadata: Explainability metadata containing raw identities and non-numerical attributes.
    """

    behavior_identity_key: str
    timestamp: float
    feature_version: str = FEATURE_VERSION
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    vector: list[float] = field(default_factory=list)
    values: dict[str, float] = field(default_factory=dict)
    categorical_encoded: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_numpy(self) -> Any:
        """Convert numerical feature vector to a 1D NumPy array for scikit-learn models."""
        try:
            import numpy as np
            return np.array(self.vector, dtype=np.float64)
        except ImportError:
            return self.vector

    def explainable_payload(self) -> dict[str, Any]:
        """Return structured, non-sensitive payload for explainability and alert reporting."""
        return {
            "feature_version": self.feature_version,
            "behavior_identity_key": self.behavior_identity_key,
            "timestamp": self.timestamp,
            "process_name": self.process_name,
            "remote_target": f"{self.remote_ip or '*'}:{self.remote_port or 0}",
            "protocol": self.protocol,
            "values": {k: round(v, 4) for k, v in self.values.items()},
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert FeatureVector to a JSON-serializable dictionary representation."""
        return {
            "feature_version": self.feature_version,
            "behavior_identity_key": self.behavior_identity_key,
            "timestamp": self.timestamp,
            "feature_names": self.feature_names,
            "vector": [round(x, 4) for x in self.vector],
            "values": {k: round(v, 4) for k, v in self.values.items()},
            "categorical_encoded": self.categorical_encoded,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FeatureVector":
        """Reconstruct FeatureVector from a dictionary."""
        vector = [float(x) for x in data.get("vector", [])]
        values = {k: float(v) for k, v in data.get("values", {}).items()}
        feature_names = data.get("feature_names", list(FEATURE_NAMES))
        return cls(
            feature_version=data.get("feature_version", FEATURE_VERSION),
            behavior_identity_key=data["behavior_identity_key"],
            timestamp=data["timestamp"],
            feature_names=feature_names,
            vector=vector,
            values=values,
            categorical_encoded=data.get("categorical_encoded", {}),
            metadata=data.get("metadata", {}),
        )

    # -------------------------------------------------------------------------
    # Backward Compatibility Properties for Phase 2 Baseline/Anomaly Engines
    # -------------------------------------------------------------------------
    @property
    def behavior_key(self) -> str:
        """Alias for behavior_identity_key."""
        return self.behavior_identity_key

    @property
    def process_name(self) -> str:
        """Raw process executable name."""
        return self.metadata.get("process_name", "unknown")

    @property
    def process_frequency(self) -> float:
        """Recent process event frequency per minute."""
        return self.values.get("process_frequency", 0.0)

    @property
    def connection_frequency(self) -> float:
        """Recent network connection frequency per minute."""
        return self.values.get("connection_frequency", 0.0)

    @property
    def unique_destinations_count(self) -> int:
        """Count of unique destination IPs seen."""
        return int(self.values.get("unique_destinations_count", self.values.get("unique_destinations", 1)))

    @property
    def unique_ports_count(self) -> int:
        """Count of unique destination ports seen."""
        return int(self.values.get("unique_ports_count", self.values.get("unique_ports", 1)))

    @property
    def protocol(self) -> str:
        """Transport layer protocol."""
        return self.metadata.get("protocol", "TCP")

    @property
    def remote_ip(self) -> str | None:
        """Destination IP string."""
        return self.metadata.get("remote_ip")

    @property
    def remote_port(self) -> int | None:
        """Destination port integer."""
        return self.metadata.get("remote_port")

    @property
    def proc_dest_key(self) -> str:
        """Process -> Destination relationship key."""
        return self.metadata.get("proc_dest_key", "")

    @property
    def proc_port_key(self) -> str:
        """Process -> Port relationship key."""
        return self.metadata.get("proc_port_key", "")

    @property
    def proc_proto_key(self) -> str:
        """Process -> Protocol relationship key."""
        return self.metadata.get("proc_proto_key", "")

    @property
    def proc_dir_key(self) -> str:
        """Process -> Direction relationship key."""
        return self.metadata.get("proc_dir_key", "")

    @property
    def raw_features(self) -> dict[str, float]:
        """Dictionary of numerical features (for baseline accumulator update)."""
        raw = dict(self.values)
        raw["unique_destinations"] = float(self.unique_destinations_count)
        raw["unique_ports"] = float(self.unique_ports_count)
        raw["remote_port"] = float(self.remote_port or 0)
        return raw


# Alias BehavioralFeatures to FeatureVector for backward compatibility
BehavioralFeatures = FeatureVector


class FeatureExtractor:
    """Extracts normalized, compact statistical and relational feature vectors from BehavioralEvents.

    The extractor is a pure deterministic transformation layer:
    - Does NOT make network calls or execute processes
    - Does NOT alter baseline memory or firewall rules
    - Safely handles missing optional telemetry fields
    """

    def __init__(self, history_window_sec: float = 300.0) -> None:
        self.history_window_sec = history_window_sec

    def extract(
        self,
        event: BehavioralEvent,
        recent_events: list[BehavioralEvent] | None = None,
        baseline_memory: dict[str, Any] | None = None,
    ) -> FeatureVector:
        """Extract standardized FeatureVector from BehavioralEvent and history context.

        Args:
            event: The incoming BehavioralEvent to extract features from.
            recent_events: Optional list of recent historical BehavioralEvents within the sliding window.
            baseline_memory: Optional dictionary of known behavioral baseline records/keys.

        Returns:
            A versioned, normalized FeatureVector ready for baseline and ML models.
        """
        recent = recent_events or []
        proc_name = event.process_name or "unknown"
        r_ip = event.remote_ip if (event.remote_ip and event.remote_ip not in ("*", "0.0.0.0")) else None
        r_port = event.remote_port if (event.remote_port and event.remote_port > 0) else None
        proto = (
            str(event.protocol).upper()
            if event.protocol and str(event.protocol).upper() not in ("UNKNOWN", "NONE", "")
            else "UNKNOWN"
        )
        direction = (
            str(event.direction).upper()
            if event.direction and str(event.direction).upper() not in ("UNKNOWN", "NONE", "")
            else "UNKNOWN"
        )

        # Canonical behavior & relationship keys
        r_ip_str = r_ip or "0.0.0.0"
        r_port_num = r_port or 0
        behavior_key = event.behavior_identity_key
        proc_dest_key = f"{proc_name}->{r_ip_str}"
        proc_port_key = f"{proc_name}->{r_port_num}"
        proc_proto_key = f"{proc_name}->{proto}"
        proc_dir_key = f"{proc_name}->{direction}"

        # ---------------------------------------------------------------------
        # 1. PROCESS FEATURES
        # ---------------------------------------------------------------------
        window_events = [
            e for e in recent if (event.timestamp - e.timestamp) <= self.history_window_sec
        ]
        proc_events = [e for e in window_events if e.process_name == proc_name]

        window_minutes = max(self.history_window_sec / 60.0, 0.1)
        proc_count = len(proc_events) + 1
        process_freq = round(proc_count / window_minutes, 3)

        if proc_events:
            earliest_ts = min(e.timestamp for e in proc_events)
            process_lifetime_sec = max(0.0, event.timestamp - earliest_ts)
        else:
            process_lifetime_sec = 0.0

        has_parent_process = 1.0 if event.parent_process_id is not None and event.parent_process_id > 0 else 0.0

        if event.signed_status is True:
            signed_status_val = 1.0
        elif event.signed_status is False:
            signed_status_val = 0.0
        else:
            signed_status_val = 0.5

        # ---------------------------------------------------------------------
        # 2. NETWORK FEATURES
        # ---------------------------------------------------------------------
        conn_freq = round((len(window_events) + 1) / window_minutes, 3)

        unique_dests = {
            e.remote_ip for e in proc_events if e.remote_ip and e.remote_ip not in ("*", "0.0.0.0")
        }
        if r_ip:
            unique_dests.add(r_ip)
        unique_destinations_count = float(len(unique_dests)) if unique_dests else 1.0

        unique_ports = {
            e.remote_port for e in proc_events if e.remote_port and e.remote_port > 0
        }
        if r_port:
            unique_ports.add(r_port)
        unique_ports_count = float(len(unique_ports)) if unique_ports else 1.0

        bytes_sent_val = max(0, event.bytes_sent) if event.bytes_sent is not None else 0
        bytes_rec_val = max(0, event.bytes_received) if event.bytes_received is not None else 0

        bytes_sent_log = round(math.log1p(bytes_sent_val), 4)
        bytes_received_log = round(math.log1p(bytes_rec_val), 4)

        total_bytes = bytes_sent_val + bytes_rec_val
        if total_bytes > 0:
            inbound_outbound_ratio = round(bytes_rec_val / float(total_bytes), 4)
        else:
            inbound_outbound_ratio = 0.5

        failed_connection_rate = float(event.metadata.get("failed_connection_rate", 0.0))

        proto_tcp = 1.0 if proto == "TCP" else 0.0
        proto_udp = 1.0 if proto == "UDP" else 0.0
        proto_icmp = 1.0 if proto == "ICMP" else 0.0
        proto_other = 1.0 if proto not in ("TCP", "UDP", "ICMP") else 0.0

        dir_inbound = 1.0 if direction == "INBOUND" else 0.0
        dir_outbound = 1.0 if direction == "OUTBOUND" else 0.0
        dir_unknown = 1.0 if direction not in ("INBOUND", "OUTBOUND") else 0.0

        conn_state = (event.connection_state or "UNKNOWN").upper()
        state_established = 1.0 if conn_state in ("ESTABLISHED", "CONNECTED") else 0.0
        state_listen = 1.0 if conn_state in ("LISTEN", "LISTENING") else 0.0
        state_other = 1.0 if conn_state not in ("ESTABLISHED", "CONNECTED", "LISTEN", "LISTENING") else 0.0

        # ---------------------------------------------------------------------
        # 3. NOVELTY FEATURES
        # ---------------------------------------------------------------------
        prior_dests = {
            e.remote_ip for e in proc_events if e.remote_ip and e.remote_ip not in ("*", "0.0.0.0")
        }
        is_new_destination = 1.0 if (r_ip and r_ip not in prior_dests) else 0.0

        prior_ports = {
            e.remote_port for e in proc_events if e.remote_port and e.remote_port > 0
        }
        is_new_port = 1.0 if (r_port and r_port not in prior_ports) else 0.0

        prior_protos = {e.protocol for e in proc_events if e.protocol}
        is_new_protocol = 1.0 if (proto and proto not in prior_protos and len(proc_events) > 0) else 0.0

        prior_keys = {e.behavior_identity_key for e in proc_events}
        is_new_process_net_rel = 1.0 if (behavior_key not in prior_keys) else 0.0

        if baseline_memory and behavior_key in baseline_memory:
            is_first_seen_behavior = 0.0
        elif prior_keys and behavior_key in prior_keys:
            is_first_seen_behavior = 0.0
        else:
            is_first_seen_behavior = 1.0

        values: dict[str, float] = {
            "process_frequency": process_freq,
            "process_lifetime_sec": round(process_lifetime_sec, 2),
            "has_parent_process": has_parent_process,
            "signed_status_val": signed_status_val,
            "connection_frequency": conn_freq,
            "unique_destinations_count": unique_destinations_count,
            "unique_ports_count": unique_ports_count,
            "bytes_sent_log": bytes_sent_log,
            "bytes_received_log": bytes_received_log,
            "inbound_outbound_ratio": inbound_outbound_ratio,
            "failed_connection_rate": failed_connection_rate,
            "proto_tcp": proto_tcp,
            "proto_udp": proto_udp,
            "proto_icmp": proto_icmp,
            "proto_other": proto_other,
            "direction_inbound": dir_inbound,
            "direction_outbound": dir_outbound,
            "direction_unknown": dir_unknown,
            "state_established": state_established,
            "state_listen": state_listen,
            "state_other": state_other,
            "is_new_destination": is_new_destination,
            "is_new_port": is_new_port,
            "is_new_protocol": is_new_protocol,
            "is_new_process_net_rel": is_new_process_net_rel,
            "is_first_seen_behavior": is_first_seen_behavior,
        }

        vector = [values[fname] for fname in FEATURE_NAMES]

        categorical_encoded = {
            "protocol": proto,
            "direction": direction,
            "connection_state": conn_state,
        }

        metadata = {
            "process_name": proc_name,
            "process_id": event.process_id,
            "parent_process_id": event.parent_process_id,
            "executable_path": event.executable_path,
            "executable_hash": event.executable_hash,
            "signed_status": event.signed_status,
            "local_ip": event.local_ip,
            "local_port": event.local_port,
            "remote_ip": r_ip,
            "remote_port": r_port,
            "protocol": proto,
            "direction": direction,
            "connection_state": conn_state,
            "proc_dest_key": proc_dest_key,
            "proc_port_key": proc_port_key,
            "proc_proto_key": proc_proto_key,
            "proc_dir_key": proc_dir_key,
            "event_type": event.event_type,
            "event_id": event.event_id,
        }

        return FeatureVector(
            feature_version=FEATURE_VERSION,
            behavior_identity_key=behavior_key,
            timestamp=event.timestamp,
            feature_names=list(FEATURE_NAMES),
            vector=vector,
            values=values,
            categorical_encoded=categorical_encoded,
            metadata=metadata,
        )
