"""Pydantic schemas for Policy Engine configuration and deterministic decisions."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from pydantic import BaseModel, Field

from backend.ai.schemas import ThreatSeverity


class EnforcementMode(str, Enum):
    """Operational enforcement level for firewall mutations."""
    MANUAL = "MANUAL"                   # Strictly audit; all actions require manual admin trigger
    SEMI_AUTOMATIC = "SEMI_AUTOMATIC"   # Auto-alerts created; mutations queued for approval
    FULL_AUTONOMOUS = "FULL_AUTONOMOUS" # Critical/High threats meeting threshold are blocked immediately


class PolicyAction(str, Enum):
    """Deterministic policy actions."""
    ENFORCE_BLOCK = "ENFORCE_BLOCK"
    QUEUE_FOR_APPROVAL = "QUEUE_FOR_APPROVAL"
    MONITOR_ONLY = "MONITOR_ONLY"
    IGNORE_WHITELISTED = "IGNORE_WHITELISTED"
    RATE_LIMITED = "RATE_LIMITED"


class PolicyConfig(BaseModel):
    """Configuration settings for deterministic policy evaluation."""
    enforcement_mode: EnforcementMode = Field(
        default=EnforcementMode.FULL_AUTONOMOUS,
        description="Global enforcement policy mode",
    )
    auto_block_min_severity: ThreatSeverity = Field(
        default=ThreatSeverity.HIGH,
        description="Minimum threat severity required for autonomous blocking",
    )
    auto_block_min_confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required for autonomous blocking",
    )
    max_blocks_per_minute: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Rate limit bounding maximum autonomous rule mutations per minute",
    )
    cooldown_period_sec: float = Field(
        default=60.0,
        ge=0.0,
        description="Cooldown window in seconds to prevent repetitive rule mutations on same target",
    )
    enable_system_whitelist: bool = Field(
        default=True,
        description="Safety invariant: always True to protect OS critical binaries",
    )


class PolicyDecision(BaseModel):
    """Deterministic evaluation outcome produced by the Policy Engine."""
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Target Context
    process_name: str = Field(description="Evaluated process name")
    process_id: int | None = Field(default=None, description="Operating system PID")
    destination_ip: str | None = Field(default=None, description="Destination IP")
    destination_port: int | None = Field(default=None, description="Destination Port")

    # Input Advisory Reference
    advisory_id: str | None = Field(default=None, description="ID of ThreatAdvisory that triggered evaluation")
    advisory_severity: ThreatSeverity = Field(description="Severity assessed by AI")
    advisory_confidence: float = Field(description="Confidence score assessed by AI")

    # Policy Result
    action: PolicyAction = Field(description="Deterministic policy action")
    reason: str = Field(description="Explanation of policy rule matching or safety guardrail trigger")
    is_blocked: bool = Field(default=False, description="True if firewall block mutation was enacted")
    mutation_rule_name: str | None = Field(default=None, description="Firewall rule name if created")
