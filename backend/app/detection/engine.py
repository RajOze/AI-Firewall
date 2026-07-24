"""Detection engine for AI Firewall."""

from app.detection.models import DetectionResult, Severity, ThreatMatch
from app.services.detector import analyze_text


def analyze(text: str) -> DetectionResult:
    """
    Run the existing detector service and convert its output into
    the new DetectionResult model.
    """

    result = analyze_text(text)

    if result["safe"]:
        return DetectionResult(
            allowed=True,
            risk_score=0,
            severity=Severity.LOW,
            threats=[],
        )

    threat = ThreatMatch(
        name=result["category"],
        severity=Severity.HIGH,
        confidence=result["score"] / 100,
        evidence=result["reason"],
    )

    return DetectionResult(
        allowed=False,
        risk_score=result["score"],
        severity=Severity.HIGH,
        threats=[threat],
    )