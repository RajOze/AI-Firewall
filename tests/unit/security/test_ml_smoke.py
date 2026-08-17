"""Phase 2 ML Stack Smoke Test verifying NumPy, scikit-learn, joblib, and model serialization."""

import os
import tempfile
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from backend.security.base_model import BaseSecurityModel, ModelOutput


class IsolationForestAnomalyModel(BaseSecurityModel):
    """Wrapper model implementing BaseSecurityModel interface using scikit-learn IsolationForest."""

    def __init__(self, contamination: float = 0.05) -> None:
        super().__init__(model_name="isolation_forest_anomaly", model_version="0.1.0")
        self.contamination = contamination
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: None = None) -> "IsolationForestAnomalyModel":
        """Fit IsolationForest model on feature dataset X."""
        self.model.fit(X)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict binary anomaly labels (-1 = anomaly, 1 = normal)."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict()")
        return self.model.predict(X)

    def score(self, X: np.ndarray) -> list[ModelOutput]:
        """Generate standardized ModelOutput scores."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before score()")

        # raw decision_function: lower score = more anomalous
        scores_raw = self.model.decision_function(X)
        preds = self.model.predict(X)

        outputs: list[ModelOutput] = []
        for i in range(len(X)):
            # Convert decision_function raw score into [0.0, 1.0] anomaly score
            raw_score = float(scores_raw[i])
            anomaly_score = max(0.0, min(1.0, 0.5 - (raw_score * 2.0)))
            is_anomaly = int(preds[i]) == -1

            reasons = ["ISOLATION_FOREST_ANOMALY"] if is_anomaly else ["NORMAL_BEHAVIOR"]

            outputs.append(
                ModelOutput(
                    model_name=self.model_name,
                    model_version=self.model_version,
                    score=round(anomaly_score, 2),
                    confidence=0.85 if is_anomaly else 0.95,
                    reason_codes=reasons,
                    details={"raw_decision_score": round(raw_score, 4)},
                )
            )
        return outputs

    def save(self, path: str) -> None:
        """Persist model state using joblib."""
        data = {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "contamination": self.contamination,
            "is_fitted": self.is_fitted,
            "sklearn_model": self.model,
        }
        joblib.dump(data, path)

    @classmethod
    def load(cls, path: str) -> "IsolationForestAnomalyModel":
        """Load model state using joblib."""
        data = joblib.load(path)
        instance = cls(contamination=data.get("contamination", 0.05))
        instance.model_name = data["model_name"]
        instance.model_version = data["model_version"]
        instance.feature_version = data["feature_version"]
        instance.is_fitted = data["is_fitted"]
        instance.model = data["sklearn_model"]
        return instance


def test_ml_stack_smoke() -> None:
    """Smoke test verifying NumPy, scikit-learn, joblib, training, evaluation, save, and load."""
    # 1. NumPy verification & feature vector creation
    np.random.seed(42)
    # Synthetic normal behavior: 100 samples with 3 features (process_freq, conn_freq, port_diversity)
    X_normal = np.random.normal(loc=[10.0, 5.0, 2.0], scale=[1.0, 0.5, 0.2], size=(100, 3))

    # Synthetic anomalous behavior: 1 sample with extreme values
    X_anomaly = np.array([[500.0, 200.0, 50.0]])

    X_train = X_normal
    X_test = np.vstack([X_normal[:2], X_anomaly])

    # 2. Train lightweight scikit-learn model
    model = IsolationForestAnomalyModel(contamination=0.05)
    model.fit(X_train)

    # 3. Generate predictions & standardized ModelOutput scores
    scores_before = model.score(X_test)
    assert len(scores_before) == 3
    # Anomaly sample (index 2) must have high anomaly score
    assert scores_before[2].score > 0.6
    assert "ISOLATION_FOREST_ANOMALY" in scores_before[2].reason_codes

    # 4. Joblib serialization: save and load model
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        model.save(tmp_path)
        assert os.path.exists(tmp_path)

        loaded_model = IsolationForestAnomalyModel.load(tmp_path)
        scores_after = loaded_model.score(X_test)

        # 5. Verify loaded model produces identical predictions
        assert len(scores_after) == len(scores_before)
        for sb, sa in zip(scores_before, scores_after):
            assert sb.score == sa.score
            assert sb.reason_codes == sa.reason_codes
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
