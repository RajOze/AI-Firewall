"""Reputation Engine module for AI Firewall security intelligence."""

import logging

from backend.security.models import EnrichedConnection, ReputationResult

logger = logging.getLogger(__name__)

# List of explicitly trusted software vendors
TRUSTED_VENDORS = (
    "microsoft",
    "google",
    "mozilla",
    "intel",
    "amd",
    "advanced micro devices",
    "nvidia",
    "vmware",
    "docker",
    "github",
    "python software foundation",
    "python",
)

# High-risk directory path tokens
HIGH_RISK_PATH_TOKENS = (
    "\\temp\\",
    "/temp/",
    "\\tmp\\",
    "/tmp/",
    "appdata\\local\\temp",
    "appdata/local/temp",
    "\\downloads\\",
    "/downloads/",
)

# Trusted system directory path tokens
SYSTEM_PATH_TOKENS = (
    "\\system32\\",
    "/system32/",
    "\\program files\\",
    "/program files/",
    "\\program files (x86)\\",
    "/program files (x86)/",
    "\\windows\\",
    "/windows/",
)


def _is_trusted_vendor(vendor_name: str | None) -> bool:
    """Return True if vendor_name matches any known trusted vendor."""
    if not vendor_name:
        return False
    name_lower = vendor_name.strip().lower()
    return any(trusted in name_lower for trusted in TRUSTED_VENDORS)


def evaluate_reputation(enriched: EnrichedConnection) -> ReputationResult:
    """Evaluate reputation of an enriched network connection.

    Calculates a trust score (0 to 100), maps risk level (LOW, MEDIUM, HIGH, CRITICAL),
    and logs evaluation reasons for decision auditing.

    Args:
        enriched: EnrichedConnection object combining network event and process metadata.

    Returns:
        ReputationResult dataclass with score, risk level, confidence, and reasons. Never raises unhandled exceptions.
    """
    try:
        score = 50  # Neutral base score
        reasons: list[str] = []
        confidence_factors: list[float] = []

        process_info = enriched.process_info if isinstance(enriched, EnrichedConnection) else None

        vendor: str | None = None
        signed: bool | None = None
        exe_path: str | None = None

        if process_info:
            vendor = process_info.publisher
            signed = process_info.is_signed
            exe_path = process_info.exe_path

        # 1. Vendor Trust Evaluation
        if vendor:
            if _is_trusted_vendor(vendor):
                score += 30
                reasons.append(f"Trusted vendor: {vendor}")
                confidence_factors.append(1.0)
            else:
                score -= 10
                reasons.append(f"Unknown vendor: {vendor}")
                confidence_factors.append(0.7)
        else:
            score -= 15
            reasons.append("Vendor information missing or unverified")
            confidence_factors.append(0.4)

        # 2. Digital Signature Evaluation
        if signed is True:
            score += 20
            reasons.append("Executable is digitally signed")
            confidence_factors.append(1.0)
        elif signed is False:
            score -= 25
            reasons.append("Unsigned executable binary")
            confidence_factors.append(0.9)
        else:
            score -= 10
            reasons.append("Digital signature status unverified")
            confidence_factors.append(0.5)

        # 3. Path Location Risk Evaluation
        if exe_path:
            norm_path = exe_path.lower()

            # Check high-risk volatile directories
            if any(token in norm_path for token in HIGH_RISK_PATH_TOKENS) or norm_path.endswith(
                ("temp", "downloads")
            ):
                score -= 30
                reasons.append(f"Executable located in high-risk directory: {exe_path}")
                confidence_factors.append(1.0)
            elif any(token in norm_path for token in SYSTEM_PATH_TOKENS):
                score += 20
                reasons.append(f"Executable located in secure system directory: {exe_path}")
                confidence_factors.append(1.0)
            else:
                reasons.append(f"Executable located in user directory: {exe_path}")
                confidence_factors.append(0.8)
        else:
            score -= 15
            reasons.append("Executable file path unavailable")
            confidence_factors.append(0.2)

        # Clamp final score between 0 and 100
        clamped_score = max(0, min(100, score))

        # Risk level mapping
        if clamped_score >= 75:
            trust_level = "LOW"
        elif clamped_score >= 50:
            trust_level = "MEDIUM"
        elif clamped_score >= 25:
            trust_level = "HIGH"
        else:
            trust_level = "CRITICAL"

        confidence = (
            sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.5
        )
        confidence = round(max(0.0, min(1.0, confidence)), 2)

        return ReputationResult(
            score=clamped_score,
            trust_level=trust_level,
            confidence=confidence,
            reasons=reasons,
            vendor=vendor,
            signed=signed,
        )

    except Exception as exc:
        logger.exception("Unexpected error during reputation evaluation")
        return ReputationResult(
            score=0,
            trust_level="CRITICAL",
            confidence=0.0,
            reasons=[f"Reputation evaluation exception: {exc}"],
            vendor=None,
            signed=False,
        )
