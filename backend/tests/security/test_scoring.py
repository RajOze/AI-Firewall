"""Exhaustive pytest suite for Threat Scoring Engine."""

from unittest.mock import MagicMock

from backend.security.models import BehaviorFinding, EnrichedConnection, ProcessInfo, ReputationResult, ThreatScore
from backend.security.scoring import calculate_threat_score


class TestThreatScoreModel:
    """Test ThreatScore dataclass and serialization."""

    def test_threat_score_to_dict(self):
        score = ThreatScore(
            score=88,
            risk_level="CRITICAL",
            confidence=0.92,
            reasons=["Unsigned executable", "Beacon Detection"],
            recommendation="Block",
            behavior_score=80,
            reputation_score=100,
            overall_score=88,
        )
        data = score.to_dict()

        assert data["score"] == 88
        assert data["risk_level"] == "CRITICAL"
        assert data["confidence"] == 0.92
        assert data["recommendation"] == "Block"
        assert data["behavior_score"] == 80
        assert data["reputation_score"] == 100
        assert data["overall_score"] == 88
        assert len(data["reasons"]) == 2


class TestCalculateThreatScore:
    """Test calculate_threat_score function logic and risk level mappings."""

    def test_low_risk_allow_recommendation(self):
        conn = EnrichedConnection(pid=100)
        rep = ReputationResult(
            score=95,
            trust_level="LOW",
            confidence=1.0,
            reasons=["Trusted vendor: Microsoft", "Executable is digitally signed"],
            vendor="Microsoft Corporation",
            signed=True,
        )
        behaviors: list[BehaviorFinding] = []

        result = calculate_threat_score(conn, rep, behaviors)

        assert result.overall_score < 25
        assert result.risk_level == "LOW"
        assert result.recommendation == "Allow"
        assert "Trusted vendor: Microsoft" in result.reasons

    def test_medium_risk_monitor_recommendation(self):
        conn = EnrichedConnection(pid=200)
        rep = ReputationResult(
            score=80,
            trust_level="LOW",
            confidence=0.9,
            reasons=["Trusted vendor: Google"],
            vendor="Google LLC",
            signed=True,
        )
        behaviors = [
            BehaviorFinding(
                name="Connection Explosion",
                severity="MEDIUM",
                confidence=0.9,
                score=60,
                description="High frequency of network connections",
                evidence={"count": 25},
            )
        ]

        result = calculate_threat_score(conn, rep, behaviors)

        # rep_threat = 20, beh_threat = 60 -> weighted = 0.4*20 + 0.6*60 = 44
        assert result.overall_score == 44
        assert result.risk_level == "MEDIUM"
        assert result.recommendation == "Monitor"
        assert "Trusted vendor: Google" in result.reasons
        assert "High frequency of network connections" in result.reasons

    def test_high_risk_warn_recommendation(self):
        conn = EnrichedConnection(pid=300)
        rep = ReputationResult(
            score=30,
            trust_level="HIGH",
            confidence=0.8,
            reasons=["Unknown vendor", "Unsigned executable"],
            vendor="Unknown",
            signed=False,
        )
        behaviors = [
            BehaviorFinding(
                name="Connection Explosion",
                severity="MEDIUM",
                confidence=0.9,
                score=60,
                description="Connection Explosion detected",
                evidence={"count": 30},
            )
        ]

        result = calculate_threat_score(conn, rep, behaviors)

        # rep_threat = 70, beh_threat = 60 -> weighted = 0.4*70 + 0.6*60 = 28 + 36 = 64
        assert result.overall_score == 64
        assert result.risk_level == "HIGH"
        assert result.recommendation == "Warn"
        assert "Unsigned executable" in result.reasons
        assert "Connection Explosion detected" in result.reasons

    def test_critical_risk_block_recommendation(self):
        conn = EnrichedConnection(pid=400)
        rep = ReputationResult(
            score=0,
            trust_level="CRITICAL",
            confidence=1.0,
            reasons=["Unsigned executable", "Executable located in high-risk directory"],
            vendor=None,
            signed=False,
        )
        behaviors = [
            BehaviorFinding(
                name="Beacon Detection",
                severity="HIGH",
                confidence=0.85,
                score=80,
                description="Possible C2 Beacon detected",
                evidence={"raddr": "1.2.3.4"},
            ),
            BehaviorFinding(
                name="Port Scan",
                severity="HIGH",
                confidence=0.95,
                score=75,
                description="Port Scanner detected",
                evidence={"pid": 400},
            ),
        ]

        result = calculate_threat_score(conn, rep, behaviors)

        # rep_threat = 100, beh_threat = min(100, 80 + 10) = 90
        # weighted = 0.4*100 + 0.6*90 = 40 + 54 = 94
        assert result.overall_score >= 75
        assert result.risk_level == "CRITICAL"
        assert result.recommendation == "Block"
        assert "Unsigned executable" in result.reasons
        assert "Possible C2 Beacon detected" in result.reasons
        assert "Port Scanner detected" in result.reasons

    def test_reasons_aggregation_example(self):
        conn = EnrichedConnection(pid=500)
        rep = ReputationResult(
            score=20,
            trust_level="HIGH",
            confidence=0.9,
            reasons=["Unsigned executable", "Unknown publisher"],
            vendor=None,
            signed=False,
        )
        behaviors = [
            BehaviorFinding(
                name="Beacon Detection",
                severity="HIGH",
                confidence=0.85,
                score=80,
                description="Beacon behavior detected",
                evidence={},
            ),
            BehaviorFinding(
                name="Connection Explosion",
                severity="MEDIUM",
                confidence=0.9,
                score=60,
                description="Connection explosion detected",
                evidence={},
            ),
        ]

        result = calculate_threat_score(conn, rep, behaviors)

        assert "Unsigned executable" in result.reasons
        assert "Unknown publisher" in result.reasons
        assert "Beacon behavior detected" in result.reasons
        assert "Connection explosion detected" in result.reasons

    def test_exception_safety(self):
        faulty_conn = EnrichedConnection(pid=600)
        faulty_rep = MagicMock(spec=ReputationResult)
        type(faulty_rep).score = property(
            lambda self: (_ for _ in ()).throw(RuntimeError("Unexpected error"))
        )

        result = calculate_threat_score(faulty_conn, faulty_rep, [])

        assert isinstance(result, ThreatScore)
        assert result.score == 100
        assert result.risk_level == "CRITICAL"
        assert result.recommendation == "Block"
        assert result.confidence == 0.0
        assert any("error" in reason.lower() for reason in result.reasons)
