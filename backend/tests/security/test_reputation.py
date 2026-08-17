"""Exhaustive pytest suite for Reputation Engine."""

from unittest.mock import MagicMock

import pytest

from backend.security.models import EnrichedConnection, ProcessInfo, ReputationResult
from backend.security.reputation import evaluate_reputation


class TestReputationResultModel:
    """Test ReputationResult dataclass and serialization."""

    def test_reputation_result_to_dict(self):
        result = ReputationResult(
            score=85,
            trust_level="LOW",
            confidence=0.95,
            reasons=["Trusted vendor: Microsoft", "Executable is digitally signed"],
            vendor="Microsoft Corporation",
            signed=True,
        )
        data = result.to_dict()
        assert data["score"] == 85
        assert data["trust_level"] == "LOW"
        assert data["confidence"] == 0.95
        assert data["vendor"] == "Microsoft Corporation"
        assert data["signed"] is True
        assert len(data["reasons"]) == 2


class TestTrustedVendors:
    """Test recognition and bonuses for all 10 trusted vendors."""

    @pytest.mark.parametrize(
        "vendor_name",
        [
            "Microsoft Corporation",
            "Google LLC",
            "Mozilla Corporation",
            "Intel Corporation",
            "Advanced Micro Devices, Inc.",
            "AMD Technologies",
            "NVIDIA Corporation",
            "VMware, Inc.",
            "Docker Inc.",
            "GitHub, Inc.",
            "Python Software Foundation",
        ],
    )
    def test_trusted_vendors_bonus(self, vendor_name: str):
        proc_info = ProcessInfo(
            pid=1000,
            name="app.exe",
            exe_path="C:\\Program Files\\App\\app.exe",
            publisher=vendor_name,
            is_signed=True,
        )
        enriched = EnrichedConnection(pid=1000, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.vendor == vendor_name
        assert any("Trusted vendor" in reason for reason in result.reasons)
        assert result.score >= 75
        assert result.trust_level == "LOW"


class TestUnknownAndMissingVendors:
    """Test penalties for unknown or missing vendors."""

    def test_unknown_vendor_penalty(self):
        proc_info = ProcessInfo(
            pid=2000,
            name="unknown.exe",
            exe_path="C:\\Tools\\unknown.exe",
            publisher="Untrusted Hacker Group",
            is_signed=False,
        )
        enriched = EnrichedConnection(pid=2000, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.vendor == "Untrusted Hacker Group"
        assert any("Unknown vendor" in reason for reason in result.reasons)
        assert result.score < 50

    def test_missing_vendor_penalty(self):
        proc_info = ProcessInfo(
            pid=2001,
            name="nopub.exe",
            exe_path="C:\\Tools\\nopub.exe",
            publisher=None,
            is_signed=False,
        )
        enriched = EnrichedConnection(pid=2001, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.vendor is None
        assert any("Vendor information missing" in reason for reason in result.reasons)


class TestDigitalSignatures:
    """Test digital signature evaluation."""

    def test_signed_executable_bonus(self):
        proc_info = ProcessInfo(
            pid=3000,
            exe_path="C:\\Program Files\\SignedApp\\signed.exe",
            publisher="Microsoft Corporation",
            is_signed=True,
        )
        enriched = EnrichedConnection(pid=3000, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.signed is True
        assert any("digitally signed" in reason.lower() for reason in result.reasons)

    def test_unsigned_executable_penalty(self):
        proc_info = ProcessInfo(
            pid=3001,
            exe_path="C:\\Tools\\unsigned.exe",
            publisher=None,
            is_signed=False,
        )
        enriched = EnrichedConnection(pid=3001, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.signed is False
        assert any("unsigned" in reason.lower() for reason in result.reasons)

    def test_unverified_signature_penalty(self):
        proc_info = ProcessInfo(
            pid=3002,
            exe_path="C:\\Tools\\unverified.exe",
            publisher=None,
            is_signed=None,
        )
        enriched = EnrichedConnection(pid=3002, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.signed is None
        assert any("unverified" in reason.lower() for reason in result.reasons)


class TestPathRiskLocation:
    """Test high-risk directory penalties and system path bonuses."""

    @pytest.mark.parametrize(
        "high_risk_path",
        [
            "C:\\Users\\admin\\AppData\\Local\\Temp\\malware.exe",
            "C:\\Windows\\Temp\\payload.exe",
            "C:\\Users\\admin\\Downloads\\untrusted_installer.exe",
            "/tmp/suspicious_script.exe",
        ],
    )
    def test_high_risk_path_penalty(self, high_risk_path: str):
        proc_info = ProcessInfo(
            pid=4000,
            exe_path=high_risk_path,
            publisher=None,
            is_signed=False,
        )
        enriched = EnrichedConnection(pid=4000, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert any("high-risk directory" in reason.lower() for reason in result.reasons)
        assert result.score <= 25
        assert result.trust_level in ("HIGH", "CRITICAL")

    @pytest.mark.parametrize(
        "system_path",
        [
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\edge.exe",
            "C:\\Windows\\explorer.exe",
        ],
    )
    def test_system_path_bonus(self, system_path: str):
        proc_info = ProcessInfo(
            pid=4001,
            exe_path=system_path,
            publisher="Microsoft Corporation",
            is_signed=True,
        )
        enriched = EnrichedConnection(pid=4001, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert any("secure system directory" in reason.lower() for reason in result.reasons)
        assert result.score >= 75
        assert result.trust_level == "LOW"


class TestRiskLevelsAndClamping:
    """Test score bounds and risk level category mappings."""

    def test_critical_risk_level(self):
        # Unsigned, unknown vendor in Temp directory -> Lowest score
        proc_info = ProcessInfo(
            pid=5000,
            exe_path="C:\\Users\\user\\AppData\\Local\\Temp\\evil.exe",
            publisher="Evil Corp",
            is_signed=False,
        )
        enriched = EnrichedConnection(pid=5000, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.score == 0
        assert result.trust_level == "CRITICAL"

    def test_low_risk_level(self):
        # Signed Microsoft binary in System32 -> Highest score
        proc_info = ProcessInfo(
            pid=5001,
            exe_path="C:\\Windows\\System32\\cmd.exe",
            publisher="Microsoft Corporation",
            is_signed=True,
        )
        enriched = EnrichedConnection(pid=5001, process_info=proc_info)

        result = evaluate_reputation(enriched)

        assert result.score == 100
        assert result.trust_level == "LOW"


class TestEdgeCasesAndExceptionSafety:
    """Test robustness against missing process info, unexpected types, and errors."""

    def test_missing_process_info(self):
        enriched = EnrichedConnection(pid=6000, process_info=None)

        result = evaluate_reputation(enriched)

        assert isinstance(result, ReputationResult)
        assert result.score < 50
        assert any("path unavailable" in reason.lower() for reason in result.reasons)

    def test_unhandled_exception_fallback(self):
        faulty_enriched = EnrichedConnection(pid=9999)
        mock_proc = MagicMock(spec=ProcessInfo)
        type(mock_proc).publisher = property(
            lambda self: (_ for _ in ()).throw(RuntimeError("Unexpected memory error"))
        )
        faulty_enriched.process_info = mock_proc

        result = evaluate_reputation(faulty_enriched)

        assert isinstance(result, ReputationResult)
        assert result.score == 0
        assert result.trust_level == "CRITICAL"
        assert result.confidence == 0.0
        assert any("exception" in reason.lower() for reason in result.reasons)
