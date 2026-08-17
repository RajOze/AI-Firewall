"""Anomaly Detection Engine and Isolation Forest Model for Phase 2 (P2.4).

Combines statistical baseline deviations (z-scores, novelty, multiplicity) and
lightweight scikit-learn Isolation Forest ML inference into explainable, bounded
anomaly assessment scores.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.security.base_model import BaseSecurityModel, ModelOutput
from backend.security.baseline import (
    BaselineDeviation,
    BehavioralBaselineEngine,
    BehavioralRecord,
)
from backend.security.behavioral_models import BehaviorStatus
from backend.security.features import FEATURE_VERSION, BehavioralFeatures, FeatureVector

ANOMALY_MODEL_VERSION = "0.1.0"


@dataclass
class AnomalyResult:
    """Standardized output assessment from AnomalyDetectionEngine (P2.4).

    Attributes:
        anomaly_score: Fused overall anomaly score clamped between 0.0 (safe) and 1.0 (highly anomalous).
        confidence: Confidence level of detection (0.0 to 1.0), decoupled from anomaly score.
        statistical_score: Component statistical deviation score (0.0 to 1.0).
        ml_score: Component machine learning anomaly score (0.0 to 1.0) or None if ML model unavailable.
        max_feature_deviation: Highest individual feature z-score or absolute deviation.
        average_feature_deviation: Mean feature z-score across evaluated numerical metrics.
        deviating_features: List of feature names exceeding the deviation threshold.
        reason_codes: Standardized explainable reason codes with supporting empirical evidence.
        behavior_identity_key: Canonical unique behavior key of evaluated event.
        model_version: Version identifier of the anomaly model.
        feature_version: Version identifier of the feature schema used.
        timestamp: Epoch timestamp of evaluation.
        details: Empirical feature measurements, z-scores, and decision breakdown.
    """

    anomaly_score: float
    confidence: float
    statistical_score: float = 0.0
    ml_score: float | None = None
    max_feature_deviation: float = 0.0
    average_feature_deviation: float = 0.0
    deviating_features: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    behavior_identity_key: str = ""
    model_version: str = ANOMALY_MODEL_VERSION
    feature_version: str = FEATURE_VERSION
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert anomaly result to standardized dictionary representation."""
        return {
            "anomaly_score": round(self.anomaly_score, 2),
            "confidence": round(self.confidence, 2),
            "statistical_score": round(self.statistical_score, 2),
            "ml_score": round(self.ml_score, 2) if self.ml_score is not None else None,
            "max_feature_deviation": round(self.max_feature_deviation, 2),
            "average_feature_deviation": round(self.average_feature_deviation, 2),
            "deviating_features": self.deviating_features,
            "reason_codes": self.reason_codes,
            "behavior_identity_key": self.behavior_identity_key,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class IsolationForestAnomalyModel(BaseSecurityModel):
    """Lightweight scikit-learn Isolation Forest ML anomaly detector for Phase 2.

    Adheres to BaseSecurityModel interface with offline training isolation, joblib
    persistence, and feature schema version validation.
    """

    def __init__(
        self,
        model_version: str = ANOMALY_MODEL_VERSION,
        feature_version: str = FEATURE_VERSION,
        n_estimators: int = 50,
        contamination: float | str = 0.05,
        random_state: int = 42,
    ) -> None:
        super().__init__(
            model_name="isolation_forest_anomaly",
            model_version=model_version,
            feature_version=feature_version,
        )
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.clf: IsolationForest | None = None
        self.training_sample_count: int = 0
        self.trained_timestamp: float | None = None

    def fit(self, X: Any, y: Any = None) -> Self:
        """Train IsolationForest model on validated benign feature data X.

        Args:
            X: 2D array-like (N, num_features) or list of FeatureVector instances.
            y: Ignored (unsupervised).

        Raises:
            ValueError: If sample count is less than 10 or data is malformed.
        """
        arr = self._to_numpy_matrix(X)
        if arr.shape[0] < 10:
            raise ValueError(
                f"Insufficient training samples for IsolationForest: {arr.shape[0]} provided (minimum 10 required)"
            )

        self.clf = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        )
        self.clf.fit(arr)
        self.training_sample_count = int(arr.shape[0])
        self.trained_timestamp = time.time()
        return self

    def predict(self, X: Any) -> list[int]:
        """Generate binary predictions: 1 for inlier/normal, -1 for outlier/anomaly."""
        if self.clf is None:
            raise RuntimeError("IsolationForestAnomalyModel has not been fitted or loaded")
        arr = self._to_numpy_matrix(X)
        preds = self.clf.predict(arr)
        return [int(p) for p in preds]

    def score(self, X: Any) -> list[ModelOutput] | ModelOutput:
        """Generate standardized ModelOutput scores normalized between 0.0 and 1.0."""
        if self.clf is None:
            raise RuntimeError("IsolationForestAnomalyModel has not been fitted or loaded")

        is_single = isinstance(X, (FeatureVector, BehavioralFeatures)) or (
            isinstance(X, np.ndarray) and X.ndim == 1
        )
        arr = self._to_numpy_matrix(X)
        decision_scores = self.clf.decision_function(arr)

        outputs: list[ModelOutput] = []
        for i, raw_score in enumerate(decision_scores):
            raw_f = float(raw_score)
            # IsolationForest decision_function: lower/negative = outlier
            # Inliers cluster around [-0.04, +0.25], while distinct outliers fall below -0.05
            norm_score = min(1.0, max(0.0, 0.45 - (raw_f * 1.5)))
            is_outlier = raw_f < -0.05 or norm_score >= 0.60

            reason_codes: list[str] = []
            if is_outlier:
                reason_codes.append("ML_ANOMALY")

            # Model confidence increases with training dataset volume
            confidence = min(0.95, 0.50 + (self.training_sample_count / 200.0))

            output = ModelOutput(
                model_name=self.model_name,
                model_version=self.model_version,
                score=round(norm_score, 4),
                confidence=round(confidence, 2),
                reason_codes=reason_codes,
                feature_version=self.feature_version,
                details={
                    "raw_decision_score": round(float(raw_score), 4),
                    "training_sample_count": self.training_sample_count,
                },
            )
            outputs.append(output)

        return outputs[0] if is_single else outputs

    def save(self, path: str | Path) -> None:
        """Persist model artifact and metadata using joblib."""
        if self.clf is None:
            raise RuntimeError("Cannot save unfitted IsolationForestAnomalyModel")

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "training_sample_count": self.training_sample_count,
            "trained_timestamp": self.trained_timestamp,
            "clf": self.clf,
        }
        joblib.dump(payload, p)

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForestAnomalyModel":
        """Load model artifact from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model artifact not found at: {path}")

        payload = joblib.load(p)
        model = cls(
            model_version=payload.get("model_version", ANOMALY_MODEL_VERSION),
            feature_version=payload.get("feature_version", FEATURE_VERSION),
            n_estimators=payload.get("n_estimators", 50),
            contamination=payload.get("contamination", 0.05),
            random_state=payload.get("random_state", 42),
        )
        model.clf = payload["clf"]
        model.training_sample_count = payload.get("training_sample_count", 0)
        model.trained_timestamp = payload.get("trained_timestamp")
        return model

    def _to_numpy_matrix(self, X: Any) -> np.ndarray:
        """Convert input feature representations to clean 2D NumPy array."""
        if isinstance(X, (FeatureVector, BehavioralFeatures)):
            if hasattr(X, "feature_version") and X.feature_version != self.feature_version:
                raise ValueError(
                    f"Feature version mismatch: model expects {self.feature_version}, received {X.feature_version}"
                )
            return np.array([X.vector], dtype=np.float64)

        if isinstance(X, list):
            if not X:
                raise ValueError("Empty feature dataset provided")
            if isinstance(X[0], (FeatureVector, BehavioralFeatures)):
                rows = []
                for fv in X:
                    if hasattr(fv, "feature_version") and fv.feature_version != self.feature_version:
                        raise ValueError(
                            f"Feature version mismatch in batch: model expects {self.feature_version}, received {fv.feature_version}"
                        )
                    rows.append(fv.vector)
                return np.array(rows, dtype=np.float64)
            return np.array(X, dtype=np.float64)

        if isinstance(X, np.ndarray):
            if X.ndim == 1:
                return X.reshape(1, -1).astype(np.float64)
            return X.astype(np.float64)

        raise TypeError(f"Unsupported feature input type: {type(X)}")


class AnomalyDetectionEngine:
    """Computes statistical and ML behavioral deviations and outputs explainable AnomalyResults."""

    def __init__(
        self,
        z_threshold: float = 3.0,
        ml_model: IsolationForestAnomalyModel | None = None,
        weight_stat: float = 0.60,
        weight_ml: float = 0.40,
    ) -> None:
        self.z_threshold = z_threshold
        self.ml_model = ml_model
        self.weight_stat = weight_stat
        self.weight_ml = weight_ml

    def detect(
        self,
        features: FeatureVector | BehavioralFeatures,
        record: BehavioralRecord | None = None,
        is_novel: bool | None = None,
        novelty_score: float | None = None,
        baseline_engine: BehavioralBaselineEngine | None = None,
    ) -> AnomalyResult:
        """Evaluate behavioral features against baseline memory and ML model to return AnomalyResult.

        Supports both direct baseline deviation evaluation and backward-compatible parameters.
        """
        reason_codes: list[str] = []
        details: dict[str, Any] = {}
        z_scores: dict[str, float] = {}

        key = features.behavior_key

        # ---------------------------------------------------------------------
        # 1. BASELINE DEVIATION EVALUATION
        # ---------------------------------------------------------------------
        if baseline_engine is not None:
            dev: BaselineDeviation = baseline_engine.compute_deviation(
                features, z_threshold=self.z_threshold
            )
            is_nov = dev.is_novel
            nov_score = dev.novelty_score
            rec_status = dev.status
            rec_conf = dev.confidence
            obs_count = dev.observation_count
            max_z = dev.max_z_score
            avg_z = dev.avg_z_score
            deviating_feats = list(dev.deviating_features)

            for f_name, f_dev in dev.feature_deviations.items():
                z_scores[f_name] = round(f_dev.z_score, 2)
        else:
            # Backward-compatibility path
            is_nov = is_novel if is_novel is not None else (record is None)
            nov_score = novelty_score if novelty_score is not None else (1.0 if is_nov else 0.0)
            rec_status = record.status if record else BehaviorStatus.NEW
            rec_conf = record.confidence if record else 0.10
            obs_count = record.observation_count if record else 0

            deviating_feats = []
            total_z = 0.0
            max_z = 0.0
            count_z = 0

            raw_feats = features.raw_features if hasattr(features, "raw_features") else features.values
            if record is not None:
                for feat_name, feat_val in raw_feats.items():
                    if feat_name in record.metrics:
                        metric = record.metrics[feat_name]
                        if metric.count >= 2:
                            z = metric.z_score(feat_val)
                            z_scores[feat_name] = round(z, 2)
                            total_z += z
                            count_z += 1
                            if z > max_z:
                                max_z = z
                            if z >= self.z_threshold:
                                deviating_feats.append(feat_name)
            avg_z = (total_z / count_z) if count_z > 0 else 0.0

        # ---------------------------------------------------------------------
        # 2. STATISTICAL ANOMALY SCORING & REASON CODE GENERATION
        # ---------------------------------------------------------------------
        if is_nov or rec_status == BehaviorStatus.NEW:
            reason_codes.append("NEW_BEHAVIOR_KEY")
            if features.remote_ip:
                reason_codes.append("NEW_DESTINATION")
            if features.remote_port:
                reason_codes.append("UNUSUAL_PORT")

            statistical_score = min(0.80, 0.40 + (nov_score * 0.40))
        else:
            # Z-score component: composite of average and maximum z-score
            avg_z_norm = min(1.0, avg_z / 4.0)
            max_z_norm = min(1.0, max_z / 5.0)
            z_comp = min(1.0, max(avg_z_norm, max_z_norm))

            # Multiplicity checks
            dest_count = getattr(features, "unique_destinations_count", 1)
            port_count = getattr(features, "unique_ports_count", 1)

            multiplicity_bonus = 0.0
            if dest_count >= 10:
                reason_codes.append("HIGH_DESTINATION_DIVERSITY")
                multiplicity_bonus += 0.15
            if port_count >= 10:
                reason_codes.append("HIGH_PORT_DIVERSITY")
                multiplicity_bonus += 0.15

            # Specific feature deviation reason codes
            for f_name in deviating_feats:
                if "frequency" in f_name:
                    reason_codes.append("HIGH_FREQUENCY")
                if "bytes" in f_name or "traffic" in f_name:
                    reason_codes.append("TRAFFIC_VOLUME_ANOMALY")
                if "port" in f_name and "UNUSUAL_PORT" not in reason_codes:
                    reason_codes.append("UNUSUAL_PORT")
                if "dest" in f_name and "NEW_DESTINATION" not in reason_codes:
                    reason_codes.append("NEW_DESTINATION")

            if deviating_feats and not any(r in reason_codes for r in ("HIGH_FREQUENCY", "TRAFFIC_VOLUME_ANOMALY")):
                reason_codes.append("STATISTICAL_DEVIATION")

            statistical_score = min(1.0, max(0.0, z_comp + multiplicity_bonus))

        if rec_conf < 0.30 and "LOW_BASELINE_CONFIDENCE" not in reason_codes:
            reason_codes.append("LOW_BASELINE_CONFIDENCE")

        # ---------------------------------------------------------------------
        # 3. MACHINE LEARNING ANOMALY SCORING (ISOLATION FOREST)
        # ---------------------------------------------------------------------
        ml_score: float | None = None
        if self.ml_model is not None and self.ml_model.clf is not None:
            # Check feature version compatibility
            fv_ver = getattr(features, "feature_version", FEATURE_VERSION)
            if fv_ver == self.ml_model.feature_version:
                try:
                    ml_out: ModelOutput = self.ml_model.score(features)
                    ml_score = ml_out.score
                    if "ML_ANOMALY" in ml_out.reason_codes:
                        reason_codes.append("ML_ANOMALY")
                    details["ml_raw_decision"] = ml_out.details.get("raw_decision_score")
                except Exception as e:
                    details["ml_error"] = str(e)
            else:
                reason_codes.append("FEATURE_VERSION_MISMATCH")
                details["feature_version_mismatch"] = {
                    "model_feature_version": self.ml_model.feature_version,
                    "event_feature_version": fv_ver,
                }

        # ---------------------------------------------------------------------
        # 4. DETERMINISTIC ANOMALY FUSION
        # ---------------------------------------------------------------------
        if ml_score is not None:
            fused_score = (self.weight_stat * statistical_score) + (self.weight_ml * ml_score)
        else:
            fused_score = statistical_score

        anomaly_score = min(1.0, max(0.0, round(fused_score, 4)))

        # Confidence: baseline confidence weighted with observation volume
        if rec_status == BehaviorStatus.QUARANTINED:
            confidence = 0.05
        elif is_nov:
            confidence = 0.50
        else:
            confidence = min(1.0, max(0.10, rec_conf))

        # Format unique reason codes
        unique_reasons = list(dict.fromkeys(reason_codes))

        details["z_scores"] = z_scores
        details["avg_z_score"] = round(avg_z, 2)
        details["max_z_score"] = round(max_z, 2)
        details["observation_count"] = obs_count
        details["statistical_score"] = round(statistical_score, 4)
        if ml_score is not None:
            details["ml_score"] = round(ml_score, 4)

        return AnomalyResult(
            anomaly_score=round(anomaly_score, 2),
            confidence=round(confidence, 2),
            statistical_score=round(statistical_score, 2),
            ml_score=round(ml_score, 2) if ml_score is not None else None,
            max_feature_deviation=round(max_z, 2),
            average_feature_deviation=round(avg_z, 2),
            deviating_features=deviating_feats,
            reason_codes=unique_reasons,
            behavior_identity_key=key,
            model_version=ANOMALY_MODEL_VERSION,
            feature_version=getattr(features, "feature_version", FEATURE_VERSION),
            details=details,
        )
