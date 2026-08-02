"""Unit tests for network.monitor.tracker module.

Validates connection collection, snapshot generation, diff comparison,
event generation, statistics calculation, and watch polling loop.
"""

import socket
import time
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from network.monitor.tracker import (
    _snapshot,
    _snapshot_statistics,
    collect_connections,
    compare_snapshots,
    watch,
)


def test_collect_connections_real():
    """Verify collect_connections returns valid list of connection dicts from live host."""
    connections = collect_connections()
    assert isinstance(connections, list)
    assert len(connections) > 0

    required_keys = {"proto", "laddr", "lport", "raddr", "rport", "status", "pid", "family"}
    for conn in connections:
        assert required_keys.issubset(conn.keys())
        assert conn["proto"] in ("TCP", "UDP")
        assert isinstance(conn["laddr"], str)
        assert isinstance(conn["lport"], int)
        assert isinstance(conn["raddr"], str)
        assert isinstance(conn["rport"], int)


def test_collect_connections_netstat_fallback(monkeypatch):
    """Verify netstat fallback parsing when psutil is unavailable or raises exception."""
    # Force psutil import error to test fallback netstat branch
    import sys
    monkeypatch.setitem(sys.modules, "psutil", None)

    connections = collect_connections()
    assert isinstance(connections, list)
    assert len(connections) > 0
    for conn in connections:
        assert conn["proto"] in ("TCP", "UDP")


def test_snapshot_generation():
    """Verify _snapshot generates 5-tuple indexed dictionary."""
    snapshot = _snapshot()
    assert isinstance(snapshot, dict)
    assert len(snapshot) > 0

    for key, conn in snapshot.items():
        assert len(key) == 5
        proto, laddr, lport, raddr, rport = key
        assert proto in ("TCP", "UDP")
        assert conn["proto"] == proto
        assert conn["laddr"] == laddr
        assert conn["lport"] == lport
        assert conn["raddr"] == raddr
        assert conn["rport"] == rport


def test_compare_snapshots_initial():
    """Verify compare_snapshots with previous=None (initial snapshot)."""
    current_snapshot = {
        ("TCP", "0.0.0.0", 80, "0.0.0.0", 0): {
            "proto": "TCP",
            "laddr": "0.0.0.0",
            "lport": 80,
            "raddr": "0.0.0.0",
            "rport": 0,
            "status": "LISTENING",
            "pid": 100,
            "family": socket.AF_INET,
        },
        ("TCP", "192.168.1.10", 50000, "1.1.1.1", 443): {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 50000,
            "raddr": "1.1.1.1",
            "rport": 443,
            "status": "ESTABLISHED",
            "pid": 200,
            "family": socket.AF_INET,
        },
    }

    events = compare_snapshots(None, current_snapshot)
    assert len(events) == 2
    event_types = {e["event_type"] for e in events}
    assert "LISTENER_OPENED" in event_types
    assert "CONNECTION_APPEARED" in event_types


def test_compare_snapshots_diff_events():
    """Verify compare_snapshots detects additions, removals, and state changes."""
    key_listener = ("TCP", "0.0.0.0", 80, "0.0.0.0", 0)
    key_conn1 = ("TCP", "192.168.1.10", 50000, "1.1.1.1", 443)
    key_conn2 = ("TCP", "192.168.1.10", 50001, "8.8.8.8", 53)
    key_conn3 = ("TCP", "192.168.1.10", 50002, "9.9.9.9", 443)

    previous_snapshot = {
        key_listener: {
            "proto": "TCP",
            "laddr": "0.0.0.0",
            "lport": 80,
            "raddr": "0.0.0.0",
            "rport": 0,
            "status": "LISTEN",
            "pid": 100,
            "family": socket.AF_INET,
        },
        key_conn1: {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 50000,
            "raddr": "1.1.1.1",
            "rport": 443,
            "status": "SYN_SENT",
            "pid": 200,
            "family": socket.AF_INET,
        },
        key_conn2: {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 50001,
            "raddr": "8.8.8.8",
            "rport": 53,
            "status": "ESTABLISHED",
            "pid": 300,
            "family": socket.AF_INET,
        },
    }

    current_snapshot = {
        # key_listener removed -> LISTENER_CLOSED
        # key_conn1 state changed to ESTABLISHED -> CONNECTION_STATE_CHANGED
        key_conn1: {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 50000,
            "raddr": "1.1.1.1",
            "rport": 443,
            "status": "ESTABLISHED",
            "pid": 200,
            "family": socket.AF_INET,
        },
        # key_conn2 unchanged -> no event
        key_conn2: {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 50001,
            "raddr": "8.8.8.8",
            "rport": 53,
            "status": "ESTABLISHED",
            "pid": 300,
            "family": socket.AF_INET,
        },
        # key_conn3 added -> CONNECTION_APPEARED
        key_conn3: {
            "proto": "TCP",
            "laddr": "192.168.1.10",
            "lport": 50002,
            "raddr": "9.9.9.9",
            "rport": 443,
            "status": "ESTABLISHED",
            "pid": 400,
            "family": socket.AF_INET,
        },
    }

    events = compare_snapshots(previous_snapshot, current_snapshot)
    assert len(events) == 3

    event_map = {e["event_type"]: e for e in events}
    assert "LISTENER_CLOSED" in event_map
    assert "CONNECTION_STATE_CHANGED" in event_map
    assert "CONNECTION_APPEARED" in event_map

    assert event_map["LISTENER_CLOSED"]["connection"]["lport"] == 80
    assert event_map["CONNECTION_STATE_CHANGED"]["connection"]["status"] == "ESTABLISHED"
    assert event_map["CONNECTION_STATE_CHANGED"]["previous_connection"]["status"] == "SYN_SENT"
    assert event_map["CONNECTION_APPEARED"]["connection"]["raddr"] == "9.9.9.9"


def test_snapshot_statistics_mutually_exclusive():
    """Verify _snapshot_statistics total connections equals sum of IPv4 and IPv6."""
    snapshot = {
        ("TCP", "127.0.0.1", 8080, "0.0.0.0", 0): {
            "proto": "TCP",
            "laddr": "127.0.0.1",
            "raddr": "0.0.0.0",
            "family": socket.AF_INET,
        },
        ("TCP", "::1", 9090, "::", 0): {
            "proto": "TCP",
            "laddr": "::1",
            "raddr": "::",
            "family": socket.AF_INET6,
        },
        ("UDP", "0.0.0.0", 53, "*", 0): {
            "proto": "UDP",
            "laddr": "0.0.0.0",
            "raddr": "*",
            "family": socket.AF_INET,
        },
    }

    stats = _snapshot_statistics(snapshot)
    assert stats["total_connections"] == 3
    assert stats["tcp_connections"] == 2
    assert stats["udp_connections"] == 1
    assert stats["ipv4_connections"] == 2
    assert stats["ipv6_connections"] == 1
    assert stats["ipv4_connections"] + stats["ipv6_connections"] == stats["total_connections"]


def test_watch_polling_iterations():
    """Verify watch polling runs for multiple iterations, invokes callback, and yields tuples."""
    callback_mock = MagicMock()
    iterations_run = 0
    max_iterations = 3

    for current, events, diagnostics in watch(interval=0.01, callback=callback_mock):
        iterations_run += 1
        assert isinstance(current, dict)
        assert isinstance(events, list)
        assert isinstance(diagnostics, dict)

        assert "poll_number" in diagnostics
        assert "poll_duration_ms" in diagnostics
        assert "events_generated" in diagnostics
        assert diagnostics["poll_number"] == iterations_run

        if iterations_run >= max_iterations:
            break

    assert iterations_run == max_iterations
    assert callback_mock.call_count == max_iterations
