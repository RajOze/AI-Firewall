"""Common Model Base Interface for Phase 2 Sentinel AI Firewall ML Models."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ModelOutput:
    """Standardized output structure for all Sentinel ML models.

    Attributes:
        model_name: Name of the model.
        model_version: Semantic version of the model.
        score: Threat / anomaly score (0.0 to 1.0).
        confidence: Model prediction confidence (0.0 to 1.0).
        reason_codes: List of standardized explainable reason codes.
        timestamp: ISO timestamp of prediction.
        feature_version: Version of feature schema used.
        details: Model-specific empirical evidence or decision rationale.
    """

    model_name: str
    model_version: str
    score: float
    confidence: float
    reason_codes: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    feature_version: str = "1.0.0"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert model output to a standardized dictionary representation."""
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "score": round(self.score, 2),
            "confidence": round(self.confidence, 2),
            "reason_codes": self.reason_codes,
            "timestamp": self.timestamp,
            "feature_version": self.feature_version,
            "details": self.details,
        }


class BaseSecurityModel(ABC):
    """Abstract Base Class for Sentinel AI Firewall Machine Learning Models."""

    def __init__(
        self,
        model_name: str,
        model_version: str = "0.1.0",
        feature_version: str = "1.0.0",
    ) -> None:
        self.model_name = model_name
        self.model_version = model_version
        self.feature_version = feature_version

    @abstractmethod
    def fit(self, X: Any, y: Any = None) -> "BaseSecurityModel":
        """Train model on feature dataset X."""
        pass

    @abstractmethod
    def predict(self, X: Any) -> list[int] | Any:
        """Generate binary or categorical predictions."""
        pass

    @abstractmethod
    def score(self, X: Any) -> list[ModelOutput] | ModelOutput:
        """Generate standardized ModelOutput scores with explainable reason codes."""
        pass

    @abstractmethod
    def save(self, path: str | Path) -> None:
        """Persist model artifacts to path."""
        pass

    @classmethod
    @abstractmethod
    def load(cls, path: str | Path) -> "BaseSecurityModel":
        """Load model artifacts from path."""
        pass
