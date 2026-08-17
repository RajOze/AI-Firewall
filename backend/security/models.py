"""Data models for security process intelligence, enriched connections, reputation results, behavior findings, and threat scores."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProcessInfo:
    """Represents intelligence metadata for a system process.

    Attributes:
        pid: Process Identifier.
        name: Name of the process executable.
        exe_path: Absolute path to the process executable file.
        cmdline: Command line arguments passed to launch the process.
        username: Name of the user account running the process.
        create_time: Process creation timestamp (Epoch seconds).
        parent_pid: PID of the parent process.
        sha256: SHA-256 hash of the executable binary.
        status: Current process execution status (e.g., 'running', 'sleeping', 'zombie').
        cpu_percent: Recent CPU utilization percentage.
        memory_rss: Resident set size memory in bytes.
        memory_vms: Virtual memory size in bytes.
        is_elevated: True if process is running with administrative privileges.
        publisher: Name of software publisher / company vendor if available.
        is_signed: True if executable is digitally signed, False if unsigned.
        access_denied: True if access to some process details was restricted.
        error_message: Error description if process lookup partially or completely failed.
    """

    pid: int
    name: str | None = None
    exe_path: str | None = None
    cmdline: list[str] | None = None
    username: str | None = None
    create_time: float | None = None
    parent_pid: int | None = None
    sha256: str | None = None
    status: str | None = None
    cpu_percent: float | None = None
    memory_rss: int | None = None
    memory_vms: int | None = None
    is_elevated: bool | None = None
    publisher: str | None = None
    is_signed: bool | None = None
    access_denied: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert process info to a dictionary representation."""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "username": self.username,
            "create_time": self.create_time,
            "parent_pid": self.parent_pid,
            "sha256": self.sha256,
            "status": self.status,
            "cpu_percent": self.cpu_percent,
            "memory_rss": self.memory_rss,
            "memory_vms": self.memory_vms,
            "is_elevated": self.is_elevated,
            "publisher": self.publisher,
            "is_signed": self.is_signed,
            "access_denied": self.access_denied,
            "error_message": self.error_message,
        }

    @property
    def is_complete(self) -> bool:
        """Returns True if essential metadata (name, exe_path, sha256) were retrieved successfully."""
        return bool(self.name and self.exe_path and self.sha256 and not self.error_message)


@dataclass
class EnrichedConnection:
    """Combines raw network connection metadata with process intelligence details.

    Attributes:
        pid: Process Identifier associated with the connection.
        proto: Transport layer protocol (e.g. 'TCP', 'UDP').
        laddr: Local IP address string.
        lport: Local port number.
        raddr: Remote IP address string.
        rport: Remote port number.
        status: Connection status string (e.g. 'ESTABLISHED', 'LISTEN').
        family: Address family (e.g. AF_INET).
        process_info: Process intelligence details retrieved from ProcessInfo.
        raw_connection: Dictionary containing all original raw connection key-values.
    """

    pid: int | None = None
    proto: str | None = None
    laddr: str | None = None
    lport: int | None = None
    raddr: str | None = None
    rport: int | None = None
    status: str | None = None
    family: Any | None = None
    process_info: ProcessInfo | None = None
    raw_connection: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert enriched connection to a combined dictionary representation."""
        result = dict(self.raw_connection)
        result.update(
            {
                "pid": self.pid,
                "proto": self.proto,
                "laddr": self.laddr,
                "lport": self.lport,
                "raddr": self.raddr,
                "rport": self.rport,
                "status": self.status,
                "family": self.family,
                "process_info": self.process_info.to_dict() if self.process_info else None,
            }
        )
        return result


@dataclass
class ReputationResult:
    """Represents security reputation analysis for an enriched network connection.

    Attributes:
        score: Security reputation score ranging from 0 (highest risk) to 100 (highest trust).
        trust_level: Categorical risk level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        confidence: Confidence score of the reputation assessment (0.0 to 1.0).
        reasons: List of reasoning strings detailing bonuses and penalties applied during evaluation.
        vendor: Software publisher or vendor name if identified.
        signed: True if binary is digitally signed, False if unsigned, None if unverified.
    """

    score: int
    trust_level: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    vendor: str | None = None
    signed: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert reputation result to a dictionary representation."""
        return {
            "score": self.score,
            "trust_level": self.trust_level,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "vendor": self.vendor,
            "signed": self.signed,
        }


@dataclass
class BehaviorFinding:
    """Represents a suspicious behavioral pattern detected by the Behavior Engine.

    Attributes:
        name: Short descriptive name of the behavioral rule / finding.
        severity: Risk severity rating ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        confidence: Confidence score of the detection (0.0 to 1.0).
        score: Score contribution / penalty score for reputation impact.
        description: Detailed explanation of the detected anomaly.
        evidence: Key-value dictionary containing empirical telemetry evidence.
    """

    name: str
    severity: str
    confidence: float
    score: int
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert behavior finding to a dictionary representation."""
        return {
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class ThreatScore:
    """Combined threat assessment for a network connection event.

    Attributes:
        score: Final overall threat score clamped between 0 (safe) and 100 (critical threat).
        risk_level: Risk level rating ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        confidence: Overall confidence rating of the assessment (0.0 to 1.0).
        reasons: Aggregated list of decision reasons from reputation and behavioral findings.
        recommendation: Recommended action ('Allow', 'Monitor', 'Warn', 'Block').
        behavior_score: Component threat score derived from behavioral anomalies.
        reputation_score: Component threat score derived from process/executable reputation.
        overall_score: Combined weighted score (40% reputation threat + 60% behavior threat).
    """

    score: int
    risk_level: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    recommendation: str = "Allow"
    behavior_score: int = 0
    reputation_score: int = 0
    overall_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert threat score assessment to a dictionary representation."""
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "recommendation": self.recommendation,
            "behavior_score": self.behavior_score,
            "reputation_score": self.reputation_score,
            "overall_score": self.overall_score,
        }
