"""Data models for the AI Firewall detection engine."""

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels assigned to detected threats."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatMatch(BaseModel):
    """Represents a single threat detected in the input."""

    name: str = Field(..., description="Threat identifier")
    severity: Severity = Field(..., description="Threat severity")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Detection confidence"
    )
    evidence: str = Field(..., description="Matched text or explanation")


class DetectionResult(BaseModel):
    """Structured output produced by the detection engine."""

    allowed: bool = Field(..., description="Whether the request is allowed")
    risk_score: int = Field(..., ge=0, le=100)
    severity: Severity
    threats: list[ThreatMatch] = Field(default_factory=list)