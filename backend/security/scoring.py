"""Threat Scoring Engine module for AI Firewall.

Combines process reputation assessments and behavioral findings into a unified ThreatScore object.
"""

import logging

from backend.security.models import BehaviorFinding, EnrichedConnection, ReputationResult, ThreatScore

logger = logging.getLogger(__name__)


def calculate_threat_score(
    enriched: EnrichedConnection,
    reputation: ReputationResult,
    behaviors: list[BehaviorFinding],
) -> ThreatScore:
    """Calculate the aggregated ThreatScore for a network connection event.

    Applies a weighted scoring model (40% Reputation Threat, 60% Behavior Threat),
    assigns risk level categories (LOW, MEDIUM, HIGH, CRITICAL), aggregates reasons,
    and determines enforcement recommendations (Allow, Monitor, Warn, Block).

    Args:
        enriched: EnrichedConnection metadata.
        reputation: ReputationResult trust assessment.
        behaviors: List of detected BehaviorFinding anomalies.

    Returns:
        ThreatScore object containing composite score, risk level, confidence, and recommendation.
    """
    try:
        # 1. Component Scores
        # Reputation trust score (0 to 100) converted to threat score
        rep_trust = reputation.score if isinstance(reputation, ReputationResult) else 50
        reputation_threat_score = max(0, min(100, 100 - rep_trust))

        # Behavior threat score aggregated from findings
        behavior_threat_score = 0
        if behaviors:
            max_b_score = max(b.score for b in behaviors if isinstance(b, BehaviorFinding))
            count_bonus = (len(behaviors) - 1) * 10
            behavior_threat_score = max(0, min(100, max_b_score + count_bonus))

        # 2. Weighted Overall Score (40% Reputation, 60% Behavior)
        raw_weighted = (0.40 * reputation_threat_score) + (0.60 * behavior_threat_score)
        overall_score = round(max(0, min(100, raw_weighted)))
        score = overall_score

        # 3. Risk Level Classification
        if overall_score >= 75:
            risk_level = "CRITICAL"
            recommendation = "Block"
        elif overall_score >= 50:
            risk_level = "HIGH"
            recommendation = "Warn"
        elif overall_score >= 25:
            risk_level = "MEDIUM"
            recommendation = "Monitor"
        else:
            risk_level = "LOW"
            recommendation = "Allow"

        # 4. Reason Aggregation
        reasons: list[str] = []
        if isinstance(reputation, ReputationResult) and reputation.reasons:
            reasons.extend(reputation.reasons)

        for b in behaviors:
            if isinstance(b, BehaviorFinding) and b.description not in reasons:
                reasons.append(b.description)

        # 5. Confidence Calculation
        rep_conf = reputation.confidence if isinstance(reputation, ReputationResult) else 0.5
        if behaviors:
            beh_conf = sum(b.confidence for b in behaviors if isinstance(b, BehaviorFinding)) / len(
                behaviors
            )
        else:
            beh_conf = 1.0

        confidence = round(max(0.0, min(1.0, (0.40 * rep_conf) + (0.60 * beh_conf))), 2)

        return ThreatScore(
            score=score,
            risk_level=risk_level,
            confidence=confidence,
            reasons=reasons,
            recommendation=recommendation,
            behavior_score=behavior_threat_score,
            reputation_score=reputation_threat_score,
            overall_score=overall_score,
        )

    except Exception as exc:
        logger.exception("Unexpected error during threat score calculation")
        return ThreatScore(
            score=100,
            risk_level="CRITICAL",
            confidence=0.0,
            reasons=[f"Threat scoring error: {exc}"],
            recommendation="Block",
            behavior_score=100,
            reputation_score=100,
            overall_score=100,
        )
