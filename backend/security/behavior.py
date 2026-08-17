"""Behavior Detection Engine for AI Firewall (Phase 1 & Phase 2 Integration).

Analyzes sliding history windows and statistical baselines of EnrichedConnections/BehavioralEvents
to detect suspicious behavioral patterns and compute explainable threat scores.
"""

import logging
import statistics
import time
from dataclasses import dataclass

from backend.security.anomaly import AnomalyDetectionEngine, AnomalyResult
from backend.security.baseline import BehavioralBaselineEngine, BehavioralRecord
from backend.security.behavioral_models import BehavioralEvent
from backend.security.features import BehavioralFeatures, FeatureExtractor
from backend.security.models import BehaviorFinding, EnrichedConnection
from backend.security.risk_fusion import RiskFusionEngine, RiskFusionResult

logger = logging.getLogger(__name__)


@dataclass
class BehaviorEngineConfig:
    """Configurable thresholds for the Behavior Detection Engine rules."""

    history_window_sec: float = 300.0  # Max history retention (5 minutes)

    # 1. Beacon Detection
    beacon_min_count: int = 4
    beacon_max_stddev_sec: float = 2.0
    beacon_window_sec: float = 120.0

    # 2. Connection Explosion
    explosion_threshold: int = 20
    explosion_window_sec: float = 5.0

    # 3. Port Scan
    port_scan_unique_ports: int = 10
    port_scan_window_sec: float = 10.0

    # 4. DNS Flood
    dns_flood_count: int = 15
    dns_flood_window_sec: float = 10.0

    # 5. Many Unique IPs
    unique_ips_count: int = 15
    unique_ips_window_sec: float = 10.0


class BehaviorEngine:
    """Unified Behavior Engine integrating Phase 1 sliding rules and Phase 2 self-learning baselines."""

    def __init__(
        self,
        config: BehaviorEngineConfig | None = None,
        baseline_engine: BehavioralBaselineEngine | None = None,
    ) -> None:
        self.config = config or BehaviorEngineConfig()
        # History store: list of tuples (timestamp: float, event: EnrichedConnection)
        self._history: list[tuple[float, EnrichedConnection]] = []

        # Phase 2 Components
        self.feature_extractor = FeatureExtractor(history_window_sec=self.config.history_window_sec)
        self.baseline_engine = baseline_engine or BehavioralBaselineEngine()
        self.anomaly_engine = AnomalyDetectionEngine()
        self.risk_fusion_engine = RiskFusionEngine()

    def record_connection(
        self, enriched: EnrichedConnection, timestamp: float | None = None
    ) -> float:
        """Record an enriched connection into the sliding history buffer."""
        ts = timestamp if timestamp is not None else time.time()
        self._history.append((ts, enriched))
        self._prune_history(ts)
        return ts

    def _prune_history(self, current_ts: float) -> None:
        """Prune historical observations older than history_window_sec."""
        cutoff = current_ts - self.config.history_window_sec
        self._history = [(t, conn) for t, conn in self._history if t >= cutoff]

    def clear_history(self) -> None:
        """Clear all historical observations."""
        self._history.clear()

    def evaluate_phase2(
        self,
        enriched: EnrichedConnection,
        timestamp: float | None = None,
        record_history: bool = True,
    ) -> tuple[BehavioralFeatures, AnomalyResult, BehavioralRecord, RiskFusionResult]:
        """Perform full Phase 2 Behavioral Baseline, Anomaly Detection, and Risk Fusion evaluation."""
        if record_history:
            ts = self.record_connection(enriched, timestamp)
        else:
            ts = timestamp if timestamp is not None else time.time()

        b_event = BehavioralEvent.from_enriched_connection(enriched, timestamp=ts)

        # 1. Feature Extraction
        history_events = [
            BehavioralEvent.from_enriched_connection(conn, timestamp=t)
            for t, conn in self._history
        ]
        features = self.feature_extractor.extract(b_event, recent_events=history_events)

        # 2. Novelty & Baseline Memory Query
        is_novel, novelty_score = self.baseline_engine.evaluate_novelty(features.behavior_key)
        record = self.baseline_engine.get_record(features.behavior_key)

        # 3. Anomaly Detection Engine
        anomaly_res = self.anomaly_engine.detect(
            features, record=record, is_novel=is_novel, novelty_score=novelty_score
        )

        # 4. Safe Adaptive Baseline Learning Update
        updated_record = self.baseline_engine.update_baseline(
            features, anomaly_score=anomaly_res.anomaly_score, timestamp=ts
        )

        # 5. Risk Fusion Engine
        proc_info = enriched.process_info
        risk_res = self.risk_fusion_engine.fuse(anomaly_res, b_event, process_info=proc_info)

        return features, anomaly_res, updated_record, risk_res

    def analyze(
        self, enriched_connection: EnrichedConnection, timestamp: float | None = None
    ) -> list[BehaviorFinding]:
        """Analyze an enriched connection against historical observations and self-learning baseline.

        Args:
            enriched_connection: Connection event to evaluate.
            timestamp: Optional explicit timestamp for testing.

        Returns:
            List of BehaviorFinding objects representing triggered behavioral rules.
        """
        try:
            ts = self.record_connection(enriched_connection, timestamp)
            findings: list[BehaviorFinding] = []

            # 1. Phase 1 Sliding History Rules
            r1 = self._rule_beacon_detection(enriched_connection, ts)
            if r1:
                findings.append(r1)

            r2 = self._rule_connection_explosion(enriched_connection, ts)
            if r2:
                findings.append(r2)

            r3 = self._rule_port_scan(enriched_connection, ts)
            if r3:
                findings.append(r3)

            r4 = self._rule_dns_flood(enriched_connection, ts)
            if r4:
                findings.append(r4)

            r5 = self._rule_many_unique_ips(enriched_connection, ts)
            if r5:
                findings.append(r5)

            # 2. Phase 2 Statistical Baseline & Anomaly Engine Integration
            features, anomaly_res, record, risk_res = self.evaluate_phase2(
                enriched_connection, timestamp=ts, record_history=False
            )

            if anomaly_res.anomaly_score >= 0.5:
                findings.append(
                    BehaviorFinding(
                        name="Behavioral Anomaly",
                        severity=risk_res.risk_level,
                        confidence=anomaly_res.confidence,
                        score=int(anomaly_res.anomaly_score * 100),
                        description=(
                            f"Statistical Behavioral Anomaly detected for {features.process_name} "
                            f"(score: {anomaly_res.anomaly_score:.2f}, reasons: {', '.join(anomaly_res.reason_codes)})"
                        ),
                        evidence={
                            "behavior_key": features.behavior_key,
                            "anomaly_score": anomaly_res.anomaly_score,
                            "risk_score": risk_res.risk_score,
                            "reason_codes": anomaly_res.reason_codes,
                            "details": anomaly_res.details,
                        },
                    )
                )

            return findings
        except Exception:
            logger.exception("Unexpected error during behavior analysis")
            return []

    def _rule_beacon_detection(
        self, current: EnrichedConnection, current_ts: float
    ) -> BehaviorFinding | None:
        """Rule 1: Detect fixed-interval regular connections to the same destination."""
        if not current.raddr or current.raddr in ("*", "0.0.0.0"):
            return None

        cutoff = current_ts - self.config.beacon_window_sec
        matching_timestamps = [
            t
            for t, conn in self._history
            if t >= cutoff and conn.raddr == current.raddr and conn.rport == current.rport
        ]

        if len(matching_timestamps) < self.config.beacon_min_count:
            return None

        matching_timestamps.sort()
        deltas = [
            matching_timestamps[i] - matching_timestamps[i - 1]
            for i in range(1, len(matching_timestamps))
        ]

        if len(deltas) < 2:
            return None

        avg_interval = sum(deltas) / len(deltas)
        stddev = statistics.stdev(deltas)

        if stddev <= self.config.beacon_max_stddev_sec:
            return BehaviorFinding(
                name="Beacon Detection",
                severity="HIGH",
                confidence=0.85,
                score=80,
                description=(
                    f"Possible C2 Beacon: Repeated outbound connections to "
                    f"{current.raddr}:{current.rport} at fixed interval (~{avg_interval:.1f}s)"
                ),
                evidence={
                    "raddr": current.raddr,
                    "rport": current.rport,
                    "count": len(matching_timestamps),
                    "avg_interval_sec": round(avg_interval, 2),
                    "stddev_sec": round(stddev, 2),
                },
            )
        return None

    def _rule_connection_explosion(
        self, current: EnrichedConnection, current_ts: float
    ) -> BehaviorFinding | None:
        """Rule 2: Detect rapid spikes in total network connection rate."""
        cutoff = current_ts - self.config.explosion_window_sec
        recent_count = sum(1 for t, _ in self._history if t >= cutoff)

        if recent_count > self.config.explosion_threshold:
            return BehaviorFinding(
                name="Connection Explosion",
                severity="MEDIUM",
                confidence=0.90,
                score=60,
                description=(
                    f"Connection Explosion: High frequency of network connections "
                    f"({recent_count} connections in {self.config.explosion_window_sec}s)"
                ),
                evidence={
                    "count": recent_count,
                    "window_sec": self.config.explosion_window_sec,
                    "pid": current.pid,
                },
            )
        return None

    def _rule_port_scan(
        self, current: EnrichedConnection, current_ts: float
    ) -> BehaviorFinding | None:
        """Rule 3: Detect single process probing multiple destination ports."""
        if current.pid is None or current.pid <= 0:
            return None

        cutoff = current_ts - self.config.port_scan_window_sec
        ports = {
            conn.rport
            for t, conn in self._history
            if t >= cutoff and conn.pid == current.pid and conn.rport and conn.rport > 0
        }

        if len(ports) >= self.config.port_scan_unique_ports:
            return BehaviorFinding(
                name="Port Scan",
                severity="HIGH",
                confidence=0.95,
                score=75,
                description=(
                    f"Port Scanner: Process (PID {current.pid}) probed "
                    f"{len(ports)} distinct destination ports"
                ),
                evidence={
                    "pid": current.pid,
                    "unique_ports_count": len(ports),
                    "sample_ports": sorted(ports)[:10],
                },
            )
        return None

    def _rule_dns_flood(
        self, current: EnrichedConnection, current_ts: float
    ) -> BehaviorFinding | None:
        """Rule 4: Detect large volume of DNS requests (port 53)."""
        cutoff = current_ts - self.config.dns_flood_window_sec
        dns_count = sum(
            1 for t, conn in self._history if t >= cutoff and (conn.rport == 53 or conn.lport == 53)
        )

        if dns_count >= self.config.dns_flood_count:
            return BehaviorFinding(
                name="DNS Flood",
                severity="HIGH",
                confidence=0.80,
                score=70,
                description=(
                    f"Possible DGA: High volume of DNS requests "
                    f"({dns_count} queries in {self.config.dns_flood_window_sec}s)"
                ),
                evidence={
                    "dns_request_count": dns_count,
                    "window_sec": self.config.dns_flood_window_sec,
                    "pid": current.pid,
                },
            )
        return None

    def _rule_many_unique_ips(
        self, current: EnrichedConnection, current_ts: float
    ) -> BehaviorFinding | None:
        """Rule 5: Detect rapid communication with many distinct destination IPs."""
        cutoff = current_ts - self.config.unique_ips_window_sec
        unique_ips = {
            conn.raddr
            for t, conn in self._history
            if t >= cutoff and conn.raddr and conn.raddr not in ("*", "0.0.0.0")
        }

        if len(unique_ips) >= self.config.unique_ips_count:
            return BehaviorFinding(
                name="Many Unique IPs",
                severity="MEDIUM",
                confidence=0.85,
                score=65,
                description=(
                    f"Suspicious rapid communication with {len(unique_ips)} "
                    f"distinct destination IP addresses"
                ),
                evidence={
                    "unique_ips_count": len(unique_ips),
                    "window_sec": self.config.unique_ips_window_sec,
                    "pid": current.pid,
                },
            )
        return None
