"""Statistical Behavioral Baseline and Safe Adaptive Learning Engine for Phase 2 (P2.3).

Maintains online Welford statistics per canonical behavior_identity_key, manages
learning-state lifecycles, tracks deterministic confidence, exposes a clean deviation
interface for anomaly detection, and enforces strict baseline poisoning safeguards.
"""

import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.security.behavioral_models import BehaviorStatus
from backend.security.features import BehavioralFeatures, FeatureVector

BASELINE_VERSION = "1.0"


@dataclass
class BaselineMetric:
    """Welford online statistical accumulator for a single numerical feature.

    Maintains running count, mean, sum of squared differences (M2), min, and max
    in $O(1)$ time and $O(1)$ memory without storing raw event histories.

    Attributes:
        count: Total number of trusted observations.
        mean: Running arithmetic mean.
        m2: Running sum of squared differences from mean.
        min_val: Minimum observed numerical value.
        max_val: Maximum observed numerical value.
    """

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min_val: float = float("inf")
    max_val: float = float("-inf")

    def update(self, val: float) -> None:
        """Update running statistics with a new value using Welford's algorithm."""
        if not math.isfinite(val):
            return

        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        self.m2 += delta * delta2

        if val < self.min_val:
            self.min_val = val
        if val > self.max_val:
            self.max_val = val

    @property
    def variance(self) -> float:
        """Return sample variance (M2 / (N - 1)), guarded against negative epsilon."""
        if self.count < 2:
            return 0.0
        return max(0.0, self.m2 / (self.count - 1))

    @property
    def stddev(self) -> float:
        """Return sample standard deviation."""
        return math.sqrt(self.variance)

    def z_score(self, val: float) -> float:
        """Calculate z-score for value relative to baseline.

        Returns 0.0 if insufficient observations or value equals mean.
        If variance is near zero but value differs from mean, computes relative deviation.
        """
        if self.count < 2:
            return 0.0
        diff = abs(val - self.mean)
        if diff <= 1e-9:
            return 0.0
        if self.stddev > 1e-9:
            return diff / self.stddev
        # Zero variance baseline with different value -> scale relative to mean
        scale = max(1e-3, 0.1 * abs(self.mean))
        return diff / scale

    def deviation(self, val: float) -> float:
        """Calculate absolute difference between observed value and baseline mean."""
        if self.count < 1:
            return 0.0
        return abs(val - self.mean)

    def to_dict(self) -> dict[str, Any]:
        """Convert metric to dictionary representation for compact JSON persistence."""
        return {
            "count": self.count,
            "mean": round(self.mean, 4),
            "variance": round(self.variance, 4),
            "stddev": round(self.stddev, 4),
            "min_val": round(self.min_val, 4) if self.min_val != float("inf") else None,
            "max_val": round(self.max_val, 4) if self.max_val != float("-inf") else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaselineMetric":
        """Reconstruct BaselineMetric from dictionary."""
        var = float(data.get("variance", 0.0))
        cnt = int(data.get("count", 0))
        m2 = var * (cnt - 1) if cnt > 1 else 0.0
        min_v = float(data["min_val"]) if data.get("min_val") is not None else float("inf")
        max_v = float(data["max_val"]) if data.get("max_val") is not None else float("-inf")
        return cls(
            count=cnt,
            mean=float(data.get("mean", 0.0)),
            m2=m2,
            min_val=min_v,
            max_val=max_v,
        )


@dataclass
class FeatureDeviation:
    """Individual feature measurement deviation compared to baseline memory."""

    feature_name: str
    observed_value: float
    baseline_mean: float
    baseline_variance: float
    baseline_stddev: float
    min_val: float | None
    max_val: float | None
    z_score: float
    deviation: float

    def to_dict(self) -> dict[str, Any]:
        """Convert feature deviation to dictionary representation."""
        return {
            "feature_name": self.feature_name,
            "observed_value": round(self.observed_value, 4),
            "baseline_mean": round(self.baseline_mean, 4),
            "baseline_variance": round(self.baseline_variance, 4),
            "baseline_stddev": round(self.baseline_stddev, 4),
            "min_val": round(self.min_val, 4) if self.min_val is not None else None,
            "max_val": round(self.max_val, 4) if self.max_val is not None else None,
            "z_score": round(self.z_score, 2),
            "deviation": round(self.deviation, 4),
        }


@dataclass
class BaselineDeviation:
    """Comprehensive behavioral deviation output for P2.4 Anomaly Detection Engine.

    Attributes:
        behavior_identity_key: Canonical unique behavior key.
        is_novel: True if behavior key is novel or untrusted.
        novelty_score: Novelty magnitude (0.0 to 1.0).
        status: Lifecycle state of the behavior record.
        confidence: Learned baseline confidence level (0.0 to 1.0).
        observation_count: Total number of observations recorded.
        feature_deviations: Dictionary of individual feature deviations.
        max_z_score: Highest z-score among observed features.
        avg_z_score: Average z-score across observed features.
        deviating_features: List of feature names exceeding the deviation threshold.
    """

    behavior_identity_key: str
    is_novel: bool
    novelty_score: float
    status: BehaviorStatus
    confidence: float
    observation_count: int
    feature_deviations: dict[str, FeatureDeviation] = field(default_factory=dict)
    max_z_score: float = 0.0
    avg_z_score: float = 0.0
    deviating_features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert baseline deviation result to JSON dictionary."""
        return {
            "behavior_identity_key": self.behavior_identity_key,
            "is_novel": self.is_novel,
            "novelty_score": round(self.novelty_score, 2),
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
            "observation_count": self.observation_count,
            "max_z_score": round(self.max_z_score, 2),
            "avg_z_score": round(self.avg_z_score, 2),
            "deviating_features": self.deviating_features,
            "feature_deviations": {k: v.to_dict() for k, v in self.feature_deviations.items()},
        }


@dataclass
class BehavioralRecord:
    """Compact behavioral summary record for a specific behavior identity key.

    Attributes:
        behavior_key: Canonical identifier key.
        process_name: Executable name.
        observation_count: Total observations recorded.
        status: Learning lifecycle status (NEW, OBSERVING, KNOWN_BENIGN, SUSPICIOUS, QUARANTINED).
        confidence: Baseline confidence score (0.0 to 1.0).
        first_seen: Timestamp when behavior was first observed.
        last_seen: Timestamp when behavior was last observed.
        metrics: Dictionary of statistical BaselineMetric objects for numerical features.
    """

    behavior_key: str
    process_name: str
    observation_count: int = 1
    status: BehaviorStatus = BehaviorStatus.NEW
    confidence: float = 0.1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    metrics: dict[str, BaselineMetric] = field(default_factory=dict)

    def compute_confidence(self, anomaly_score: float = 0.0) -> float:
        """Compute deterministic confidence score based on observation history and state.

        Formula:
            S(N) = N / (N + 5) [Saturation function]
            NEW: 0.10
            OBSERVING: 0.35 + (0.20 * S(N))
            KNOWN_BENIGN: 0.50 + (0.50 * S(N)) - min(0.3, anomaly_score * 0.3)
            SUSPICIOUS: 0.20
            QUARANTINED: 0.05
        """
        n = self.observation_count
        sat = n / (n + 5.0)

        if self.status == BehaviorStatus.NEW:
            conf = 0.10
        elif self.status == BehaviorStatus.OBSERVING:
            conf = 0.35 + (0.20 * sat)
        elif self.status == BehaviorStatus.KNOWN_BENIGN:
            penalty = min(0.30, anomaly_score * 0.30)
            conf = 0.50 + (0.50 * sat) - penalty
        elif self.status == BehaviorStatus.SUSPICIOUS:
            conf = 0.20
        elif self.status == BehaviorStatus.QUARANTINED:
            conf = 0.05
        else:
            conf = 0.10

        return max(0.05, min(1.0, round(conf, 2)))

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary for compact JSON persistence."""
        return {
            "behavior_key": self.behavior_key,
            "process_name": self.process_name,
            "observation_count": self.observation_count,
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metrics": {k: v.to_dict() for k, v in self.metrics.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BehavioralRecord":
        """Reconstruct BehavioralRecord from dictionary."""
        raw_status = data.get("status", BehaviorStatus.NEW.value)
        try:
            status = BehaviorStatus(raw_status)
        except ValueError:
            status = BehaviorStatus.NEW

        metrics = {
            k: BaselineMetric.from_dict(v)
            for k, v in data.get("metrics", {}).items()
        }

        return cls(
            behavior_key=data["behavior_key"],
            process_name=data.get("process_name", "unknown"),
            observation_count=data.get("observation_count", 1),
            status=status,
            confidence=data.get("confidence", 0.1),
            first_seen=data.get("first_seen", time.time()),
            last_seen=data.get("last_seen", time.time()),
            metrics=metrics,
        )


class BehavioralBaselineEngine:
    """Manages online statistical baseline memory and safe adaptive learning policies (P2.3)."""

    def __init__(
        self,
        min_observe_count: int = 3,
        min_trust_count: int = 5,
        z_threshold: float = 3.0,
        storage_path: str | Path | None = None,
    ) -> None:
        self.min_observe_count = min_observe_count
        self.min_trust_count = min_trust_count
        self.z_threshold = z_threshold
        self.storage_path = Path(storage_path) if storage_path else None
        self._memory: dict[str, BehavioralRecord] = {}
        self._last_saved: float = 0.0
        self._save_throttle_sec: float = 30.0

        if self.storage_path and self.storage_path.exists():
            self.load()

    def get_record(self, behavior_key: str) -> BehavioralRecord | None:
        """Retrieve stored behavioral record for key if present."""
        return self._memory.get(behavior_key)

    def evaluate_novelty(self, behavior_key: str) -> tuple[bool, float]:
        """Check if behavior key is novel and return (is_novel, novelty_score)."""
        record = self._memory.get(behavior_key)
        if record is None:
            return True, 1.0  # Completely brand new key

        if record.status == BehaviorStatus.NEW:
            return True, 0.7  # Under initial observation

        if record.status == BehaviorStatus.KNOWN_BENIGN:
            return False, 0.0  # Established trusted baseline

        if record.status == BehaviorStatus.SUSPICIOUS:
            return True, 0.9  # Flagged suspicious

        if record.status == BehaviorStatus.QUARANTINED:
            return True, 1.0  # Quarantined identity

        return False, 0.2

    def compute_deviation(
        self, features: FeatureVector | BehavioralFeatures, z_threshold: float | None = None
    ) -> BaselineDeviation:
        """Compute comprehensive statistical deviations across all features against baseline memory.

        Exposes a standardized interface for P2.4 Anomaly Detection Engine.
        """
        thresh = z_threshold if z_threshold is not None else self.z_threshold
        key = features.behavior_key
        record = self._memory.get(key)
        is_novel, novelty_score = self.evaluate_novelty(key)

        feature_deviations: dict[str, FeatureDeviation] = {}
        deviating_features: list[str] = []
        total_z = 0.0
        max_z = 0.0
        count_z = 0

        raw_feats = features.raw_features if hasattr(features, "raw_features") else features.values

        if record is not None:
            status = record.status
            confidence = record.confidence
            obs_count = record.observation_count

            for feat_name, feat_val in raw_feats.items():
                if feat_name in record.metrics:
                    metric = record.metrics[feat_name]
                    z = metric.z_score(feat_val)
                    dev = metric.deviation(feat_val)

                    f_dev = FeatureDeviation(
                        feature_name=feat_name,
                        observed_value=feat_val,
                        baseline_mean=metric.mean,
                        baseline_variance=metric.variance,
                        baseline_stddev=metric.stddev,
                        min_val=metric.min_val if metric.min_val != float("inf") else None,
                        max_val=metric.max_val if metric.max_val != float("-inf") else None,
                        z_score=z,
                        deviation=dev,
                    )
                    feature_deviations[feat_name] = f_dev

                    if metric.count >= 2:
                        total_z += z
                        count_z += 1
                        if z > max_z:
                            max_z = z
                        if z >= thresh:
                            deviating_features.append(feat_name)
        else:
            status = BehaviorStatus.NEW
            confidence = 0.10
            obs_count = 0

            for feat_name, feat_val in raw_feats.items():
                feature_deviations[feat_name] = FeatureDeviation(
                    feature_name=feat_name,
                    observed_value=feat_val,
                    baseline_mean=0.0,
                    baseline_variance=0.0,
                    baseline_stddev=0.0,
                    min_val=None,
                    max_val=None,
                    z_score=0.0,
                    deviation=0.0,
                )

        avg_z = (total_z / count_z) if count_z > 0 else 0.0

        return BaselineDeviation(
            behavior_identity_key=key,
            is_novel=is_novel,
            novelty_score=novelty_score,
            status=status,
            confidence=confidence,
            observation_count=obs_count,
            feature_deviations=feature_deviations,
            max_z_score=round(max_z, 2),
            avg_z_score=round(avg_z, 2),
            deviating_features=deviating_features,
        )

    def update_baseline(
        self,
        features: FeatureVector | BehavioralFeatures,
        anomaly_score: float = 0.0,
        timestamp: float | None = None,
    ) -> BehavioralRecord:
        """Apply safe adaptive learning policy to update or create behavioral baseline."""
        ts = timestamp if timestamp is not None else time.time()
        key = features.behavior_key
        record = self._memory.get(key)
        raw_feats = features.raw_features if hasattr(features, "raw_features") else features.values

        if record is None:
            # 1. New Behavior Registration -> Status: NEW
            record = BehavioralRecord(
                behavior_key=key,
                process_name=features.process_name,
                observation_count=1,
                status=BehaviorStatus.NEW,
                confidence=0.10,
                first_seen=ts,
                last_seen=ts,
            )
            # Initialize metrics accumulators without polluting baseline statistics on first view
            for feat_name in raw_feats.keys():
                record.metrics[feat_name] = BaselineMetric()
            self._memory[key] = record
            return record

        # Update last seen timestamp and increment observation count
        record.last_seen = ts
        record.observation_count += 1

        # 2. SAFE ADAPTIVE LEARNING POLICY ENFORCEMENT
        # Quarantined records must never be updated
        if record.status == BehaviorStatus.QUARANTINED:
            record.confidence = record.compute_confidence(anomaly_score)
            return record

        # High anomaly score or suspicious status MUST NOT contaminate trusted baseline statistics!
        if anomaly_score >= 0.7 or record.status == BehaviorStatus.SUSPICIOUS:
            record.status = BehaviorStatus.SUSPICIOUS
            record.confidence = record.compute_confidence(anomaly_score)
            # Freeze statistics — DO NOT call metric.update() for suspicious observations!
            return record

        # Lifecycle Transitions for validated normal traffic
        if record.status == BehaviorStatus.NEW:
            if record.observation_count >= self.min_observe_count:
                record.status = BehaviorStatus.OBSERVING
        elif record.status == BehaviorStatus.OBSERVING:
            if record.observation_count >= self.min_trust_count and anomaly_score < 0.5:
                record.status = BehaviorStatus.KNOWN_BENIGN

        # Compute updated confidence
        record.confidence = record.compute_confidence(anomaly_score)

        # 3. Update online Welford statistical accumulators ONLY if not suspicious/quarantined
        if record.status in (BehaviorStatus.OBSERVING, BehaviorStatus.KNOWN_BENIGN):
            for feat_name, feat_val in raw_feats.items():
                if feat_name not in record.metrics:
                    record.metrics[feat_name] = BaselineMetric()
                record.metrics[feat_name].update(feat_val)

        return record

    def quarantine_behavior(self, behavior_key: str) -> bool:
        """Explicitly set a behavior identity key to QUARANTINED state."""
        record = self._memory.get(behavior_key)
        if record:
            record.status = BehaviorStatus.QUARANTINED
            record.confidence = 0.05
            return True
        return False

    def save(self) -> None:
        """Persist behavioral memory records to host-local compact JSON storage."""
        if not self.storage_path:
            return

        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "baseline_version": BASELINE_VERSION,
                "timestamp": time.time(),
                "records": {k: v.to_dict() for k, v in self._memory.items()},
            }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self._last_saved = time.time()
        except Exception:
            pass

    def load(self) -> None:
        """Load behavioral memory records from host-local JSON storage."""
        if not self.storage_path or not self.storage_path.exists():
            return

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support both direct record dict and versioned dictionary
            records_data = data.get("records", data) if isinstance(data, dict) else {}
            self._memory = {
                k: BehavioralRecord.from_dict(v)
                for k, v in records_data.items()
                if isinstance(v, dict) and "behavior_key" in v
            }
        except Exception:
            pass

    def get_summary(self) -> dict[str, Any]:
        """Return operational baseline memory summary statistics."""
        status_counts: dict[str, int] = {st.value: 0 for st in BehaviorStatus}
        for rec in self._memory.values():
            status_counts[rec.status.value] = status_counts.get(rec.status.value, 0) + 1

        return {
            "baseline_version": BASELINE_VERSION,
            "total_behavior_keys": len(self._memory),
            "status_counts": status_counts,
        }
