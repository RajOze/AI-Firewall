"""Unit tests for Event Enrichment Layer."""

import os
from unittest.mock import MagicMock

from backend.security.enrichment import enrich_connection
from backend.security.intelligence import ProcessIntelligenceEngine
from backend.security.models import EnrichedConnection, ProcessInfo


class TestEnrichedConnectionModel:
    """Test EnrichedConnection dataclass methods."""

    def test_enriched_connection_to_dict(self):
        proc_info = ProcessInfo(
            pid=1234,
            name="test_app.exe",
            exe_path="C:\\test_app.exe",
            sha256="c" * 64,
        )
        conn = EnrichedConnection(
            pid=1234,
            proto="TCP",
            laddr="127.0.0.1",
            lport=8080,
            raddr="1.1.1.1",
            rport=443,
            status="ESTABLISHED",
            family=2,
            process_info=proc_info,
            raw_connection={
                "pid": 1234,
                "proto": "TCP",
                "laddr": "127.0.0.1",
                "lport": 8080,
                "raddr": "1.1.1.1",
                "rport": 443,
                "status": "ESTABLISHED",
                "custom_metric": "test_val",
            },
        )

        data = conn.to_dict()
        assert data["pid"] == 1234
        assert data["proto"] == "TCP"
        assert data["laddr"] == "127.0.0.1"
        assert data["raddr"] == "1.1.1.1"
        assert data["custom_metric"] == "test_val"
        assert isinstance(data["process_info"], dict)
        assert data["process_info"]["name"] == "test_app.exe"
        assert data["process_info"]["sha256"] == "c" * 64


class TestEnrichConnection:
    """Test enrich_connection function."""

    def test_enrich_valid_connection_active_pid(self):
        current_pid = os.getpid()
        raw_conn = {
            "proto": "TCP",
            "laddr": "192.168.1.50",
            "lport": 54321,
            "raddr": "8.8.8.8",
            "rport": 53,
            "status": "ESTABLISHED",
            "pid": current_pid,
            "family": 2,
        }

        enriched = enrich_connection(raw_conn)

        assert isinstance(enriched, EnrichedConnection)
        assert enriched.pid == current_pid
        assert enriched.proto == "TCP"
        assert enriched.laddr == "192.168.1.50"
        assert enriched.raddr == "8.8.8.8"
        assert enriched.process_info is not None
        assert enriched.process_info.pid == current_pid
        assert enriched.process_info.name is not None
        assert enriched.raw_connection == raw_conn

    def test_enrich_non_existent_pid(self):
        raw_conn = {
            "proto": "UDP",
            "laddr": "0.0.0.0",
            "lport": 12345,
            "raddr": "*",
            "rport": 0,
            "status": "BOUND",
            "pid": 9999999,
        }

        enriched = enrich_connection(raw_conn)

        assert isinstance(enriched, EnrichedConnection)
        assert enriched.pid == 9999999
        assert enriched.process_info is not None
        assert enriched.process_info.error_message is not None
        assert "not found" in enriched.process_info.error_message.lower()

    def test_enrich_missing_or_invalid_pid(self):
        raw_conn_no_pid = {"proto": "TCP", "laddr": "127.0.0.1", "lport": 80}
        enriched1 = enrich_connection(raw_conn_no_pid)
        assert enriched1.pid is None
        assert enriched1.process_info is not None
        assert "missing or invalid pid" in enriched1.process_info.error_message.lower()

        raw_conn_invalid_pid = {"proto": "TCP", "pid": "not_an_int"}
        enriched2 = enrich_connection(raw_conn_invalid_pid)
        assert enriched2.pid is None
        assert enriched2.process_info is not None

    def test_enrich_string_pid_conversion(self):
        current_pid = os.getpid()
        raw_conn = {"proto": "TCP", "pid": str(current_pid)}

        enriched = enrich_connection(raw_conn)
        assert enriched.pid == current_pid
        assert enriched.process_info is not None
        assert enriched.process_info.pid == current_pid

    def test_enrich_exception_safety(self):
        mock_engine = MagicMock(spec=ProcessIntelligenceEngine)
        mock_engine.get_process_info.side_effect = RuntimeError("Unexpected provider crash")

        raw_conn = {"proto": "TCP", "pid": 1234, "laddr": "10.0.0.1"}

        enriched = enrich_connection(raw_conn, process_engine=mock_engine)

        assert isinstance(enriched, EnrichedConnection)
        assert enriched.pid == 1234
        assert enriched.proto == "TCP"
        assert enriched.process_info is not None
        assert enriched.process_info.error_message is not None
        assert "Enrichment lookup failed" in enriched.process_info.error_message

    def test_enrich_preserves_custom_fields(self):
        raw_conn = {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 443,
            "raddr": "104.16.1.1",
            "rport": 443,
            "status": "ESTABLISHED",
            "pid": os.getpid(),
            "timestamp": 1700000000.0,
            "interface": "eth0",
            "rx_bytes": 4096,
        }

        enriched = enrich_connection(raw_conn)
        data = enriched.to_dict()

        assert data["timestamp"] == 1700000000.0
        assert data["interface"] == "eth0"
        assert data["rx_bytes"] == 4096
        assert enriched.raw_connection["interface"] == "eth0"

    def test_enrich_invalid_connection_type(self):
        # Passing non-dict parameter
        enriched = enrich_connection(None)  # type: ignore
        assert isinstance(enriched, EnrichedConnection)
        assert enriched.pid is None
        assert enriched.process_info is not None
