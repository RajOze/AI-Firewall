"""Exhaustive pytest suite for Behavior Detection Engine."""

from unittest.mock import MagicMock

from backend.security.behavior import BehaviorEngine, BehaviorEngineConfig
from backend.security.models import BehaviorFinding, EnrichedConnection


class TestBehaviorFindingModel:
    """Test BehaviorFinding dataclass and serialization."""

    def test_behavior_finding_to_dict(self):
        finding = BehaviorFinding(
            name="Beacon Detection",
            severity="HIGH",
            confidence=0.85,
            score=80,
            description="Possible C2 Beacon detected",
            evidence={"raddr": "1.2.3.4", "count": 5},
        )
        data = finding.to_dict()

        assert data["name"] == "Beacon Detection"
        assert data["severity"] == "HIGH"
        assert data["confidence"] == 0.85
        assert data["score"] == 80
        assert data["evidence"]["raddr"] == "1.2.3.4"


class TestRule1BeaconDetection:
    """Test Rule 1: Beacon Detection."""

    def test_beacon_detection_success(self):
        engine = BehaviorEngine()
        base_ts = 1000.0

        # Simulate 5 regular connections at 10-second intervals to 198.51.100.5:443
        for i in range(4):
            conn = EnrichedConnection(
                pid=1234, proto="TCP", raddr="198.51.100.5", rport=443, lport=50000 + i
            )
            engine.analyze(conn, timestamp=base_ts + (i * 10.0))

        # 5th connection triggers Beacon Detection
        trigger_conn = EnrichedConnection(
            pid=1234, proto="TCP", raddr="198.51.100.5", rport=443, lport=50005
        )
        findings = engine.analyze(trigger_conn, timestamp=base_ts + 40.0)

        assert len(findings) >= 1
        beacon = next(f for f in findings if f.name == "Beacon Detection")
        assert beacon.severity == "HIGH"
        assert beacon.confidence == 0.85
        assert beacon.score == 80
        assert beacon.evidence["raddr"] == "198.51.100.5"
        assert beacon.evidence["rport"] == 443

    def test_beacon_detection_irregular_intervals(self):
        engine = BehaviorEngine()
        base_ts = 1000.0
        # Irregular deltas (e.g. +2s, +45s, +120s)
        offsets = [0.0, 2.0, 47.0, 167.0, 200.0]

        findings: list[BehaviorFinding] = []
        for i, offset in enumerate(offsets):
            conn = EnrichedConnection(
                pid=1234, proto="TCP", raddr="198.51.100.5", rport=443, lport=50000 + i
            )
            findings = engine.analyze(conn, timestamp=base_ts + offset)

        # High stddev should prevent beacon rule from firing
        beacon_findings = [f for f in findings if f.name == "Beacon Detection"]
        assert len(beacon_findings) == 0


class TestRule2ConnectionExplosion:
    """Test Rule 2: Connection Explosion."""

    def test_connection_explosion_triggered(self):
        config = BehaviorEngineConfig(explosion_threshold=10, explosion_window_sec=5.0)
        engine = BehaviorEngine(config=config)
        base_ts = 2000.0

        findings: list[BehaviorFinding] = []
        for i in range(12):
            conn = EnrichedConnection(
                pid=2000, proto="TCP", raddr=f"10.0.0.{i+1}", rport=80, lport=51000 + i
            )
            findings = engine.analyze(conn, timestamp=base_ts + (i * 0.1))

        explosion = next((f for f in findings if f.name == "Connection Explosion"), None)
        assert explosion is not None
        assert explosion.severity == "MEDIUM"
        assert explosion.confidence == 0.90
        assert explosion.score == 60
        assert explosion.evidence["count"] >= 11


class TestRule3PortScan:
    """Test Rule 3: Port Scan."""

    def test_port_scan_triggered(self):
        config = BehaviorEngineConfig(port_scan_unique_ports=5, port_scan_window_sec=10.0)
        engine = BehaviorEngine(config=config)
        base_ts = 3000.0

        findings: list[BehaviorFinding] = []
        # PID 3000 probes 6 distinct ports
        for i in range(6):
            conn = EnrichedConnection(
                pid=3000, proto="TCP", raddr="192.168.1.100", rport=80 + i, lport=52000 + i
            )
            findings = engine.analyze(conn, timestamp=base_ts + (i * 0.5))

        port_scan = next((f for f in findings if f.name == "Port Scan"), None)
        assert port_scan is not None
        assert port_scan.severity == "HIGH"
        assert port_scan.confidence == 0.95
        assert port_scan.score == 75
        assert port_scan.evidence["pid"] == 3000
        assert port_scan.evidence["unique_ports_count"] == 6


class TestRule4DNSFlood:
    """Test Rule 4: DNS Flood."""

    def test_dns_flood_triggered(self):
        config = BehaviorEngineConfig(dns_flood_count=5, dns_flood_window_sec=10.0)
        engine = BehaviorEngine(config=config)
        base_ts = 4000.0

        findings: list[BehaviorFinding] = []
        # PID 4000 sends 6 DNS requests to port 53
        for i in range(6):
            conn = EnrichedConnection(
                pid=4000, proto="UDP", raddr="8.8.8.8", rport=53, lport=53000 + i
            )
            findings = engine.analyze(conn, timestamp=base_ts + (i * 0.2))

        dns_flood = next((f for f in findings if f.name == "DNS Flood"), None)
        assert dns_flood is not None
        assert dns_flood.severity == "HIGH"
        assert dns_flood.confidence == 0.80
        assert dns_flood.score == 70
        assert dns_flood.evidence["dns_request_count"] == 6


class TestRule5ManyUniqueIPs:
    """Test Rule 5: Many Unique IPs."""

    def test_many_unique_ips_triggered(self):
        config = BehaviorEngineConfig(unique_ips_count=5, unique_ips_window_sec=10.0)
        engine = BehaviorEngine(config=config)
        base_ts = 5000.0

        findings: list[BehaviorFinding] = []
        # Connect to 6 unique IPs
        for i in range(6):
            conn = EnrichedConnection(
                pid=5000, proto="TCP", raddr=f"203.0.113.{i+1}", rport=443, lport=54000 + i
            )
            findings = engine.analyze(conn, timestamp=base_ts + (i * 0.3))

        unique_ips = next((f for f in findings if f.name == "Many Unique IPs"), None)
        assert unique_ips is not None
        assert unique_ips.severity == "MEDIUM"
        assert unique_ips.confidence == 0.85
        assert unique_ips.score == 65
        assert unique_ips.evidence["unique_ips_count"] == 6


class TestEngineHistoryPruningAndExceptions:
    """Test sliding history pruning and exception safety."""

    def test_history_window_pruning(self):
        config = BehaviorEngineConfig(
            history_window_sec=100.0, explosion_threshold=5, explosion_window_sec=50.0
        )
        engine = BehaviorEngine(config=config)

        # Record 6 connections at t=0
        for i in range(6):
            conn = EnrichedConnection(pid=6000, raddr=f"10.0.0.{i+1}", rport=80)
            engine.analyze(conn, timestamp=0.0)

        # Analyze new connection at t=200 (well beyond history_window_sec=100.0)
        new_conn = EnrichedConnection(pid=6000, raddr="10.0.0.100", rport=80)
        findings = engine.analyze(new_conn, timestamp=200.0)

        # History should have pruned all t=0 connections, so no explosion finding
        explosion_findings = [f for f in findings if f.name == "Connection Explosion"]
        assert len(explosion_findings) == 0

    def test_analyze_exception_safety(self):
        engine = BehaviorEngine()

        # Pass invalid connection that causes exception during rule processing
        faulty_conn = MagicMock(spec=EnrichedConnection)
        type(faulty_conn).raddr = property(
            lambda self: (_ for _ in ()).throw(RuntimeError("Unexpected error"))
        )

        findings = engine.analyze(faulty_conn, timestamp=1000.0)
        assert isinstance(findings, list)
        assert len(findings) == 0
