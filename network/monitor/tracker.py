"""Snapshot Tracker module for network connection monitoring.

Provides functions for capturing connection snapshots, comparing snapshot diffs,
deriving lightweight diagnostics, and watching connection changes over time.
"""

import platform
import socket
import subprocess
import time
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple


def collect_connections() -> List[Dict[str, Any]]:
    """Collect active host network connections using psutil or netstat."""
    connections: List[Dict[str, Any]] = []
    try:
        import psutil  # type: ignore

        for conn in psutil.net_connections(kind="all"):
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            laddr = conn.laddr.ip if conn.laddr else "0.0.0.0"
            lport = conn.laddr.port if conn.laddr else 0
            raddr = conn.raddr.ip if conn.raddr else "*"
            rport = conn.raddr.port if conn.raddr else 0
            status = str(conn.status).upper() if conn.status else ("LISTEN" if lport and not rport else "BOUND")
            family = conn.family if hasattr(conn, "family") else socket.AF_INET
            connections.append(
                {
                    "proto": proto,
                    "laddr": laddr,
                    "lport": lport,
                    "raddr": raddr,
                    "rport": rport,
                    "status": status,
                    "pid": conn.pid,
                    "family": family,
                }
            )
        return connections
    except Exception:
        pass

    is_windows = platform.system() == "Windows"
    cmd = ["netstat", "-ano"] if is_windows else ["netstat", "-tun"]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except (subprocess.SubprocessError, FileNotFoundError):
        return connections

    for line in output.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("Active") or line_str.startswith("Proto"):
            continue
        parts = line_str.split()
        if len(parts) < 4:
            continue
        proto_raw = parts[0].upper()
        if "TCP" in proto_raw:
            proto = "TCP"
        elif "UDP" in proto_raw:
            proto = "UDP"
        else:
            continue

        def _parse(addr_port: str) -> Tuple[str, int]:
            addr_port = addr_port.strip()
            if not addr_port or addr_port in ("*:*", "*"):
                return "*", 0
            if addr_port.startswith("["):
                idx = addr_port.rfind("]:")
                if idx != -1:
                    try:
                        return addr_port[1:idx], int(addr_port[idx + 2 :])
                    except ValueError:
                        return addr_port[1:idx], 0
                return addr_port.strip("[]"), 0
            if ":" in addr_port:
                p = addr_port.rsplit(":", 1)
                try:
                    return p[0], int(p[1])
                except ValueError:
                    return p[0], 0
            return addr_port, 0

        if is_windows:
            laddr, lport = _parse(parts[1])
            raddr, rport = _parse(parts[2])
            pid = None
            status = "ESTABLISHED" if proto == "TCP" else "BOUND"
            if proto == "TCP" and len(parts) >= 5:
                status = parts[3].upper()
                try:
                    pid = int(parts[4])
                except ValueError:
                    pid = None
            elif proto == "UDP" and len(parts) >= 4:
                try:
                    pid = int(parts[3])
                except ValueError:
                    pid = None
        else:
            # Linux netstat -tun layout: Proto Recv-Q Send-Q Local-Address Foreign-Address [State]
            if len(parts) < 5:
                continue
            laddr, lport = _parse(parts[3])
            raddr, rport = _parse(parts[4])
            pid = None
            status = parts[5].upper() if len(parts) >= 6 else ("ESTABLISHED" if proto == "TCP" else "BOUND")

        family = socket.AF_INET6 if ":" in laddr else socket.AF_INET
        connections.append(
            {
                "proto": proto,
                "laddr": laddr,
                "lport": lport,
                "raddr": raddr,
                "rport": rport,
                "status": status,
                "pid": pid,
                "family": family,
            }
        )
    return connections


def _snapshot() -> Dict[Tuple[str, str, int, str, int], Dict[str, Any]]:
    """Capture active connection snapshot indexed by 5-tuple key."""
    connections = collect_connections()
    snapshot: Dict[Tuple[str, str, int, str, int], Dict[str, Any]] = {}
    for conn in connections:
        key = (
            conn["proto"],
            conn["laddr"],
            conn["lport"],
            conn["raddr"],
            conn["rport"],
        )
        snapshot[key] = conn
    return snapshot


def compare_snapshots(
    previous: Optional[Dict[Tuple[str, str, int, str, int], Dict[str, Any]]],
    current: Dict[Tuple[str, str, int, str, int], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compare two connection snapshots and generate event dictionaries."""
    events: List[Dict[str, Any]] = []

    def _is_listener(conn_dict: Dict[str, Any]) -> bool:
        st = str(conn_dict.get("status", "")).upper()
        return st in ("LISTEN", "LISTENING")

    if previous is None:
        for key, conn in current.items():
            event_name = (
                "LISTENER_OPENED"
                if _is_listener(conn)
                else "CONNECTION_APPEARED"
            )
            events.append(
                {
                    "event_type": event_name,
                    "connection": conn,
                    "previous_connection": None,
                }
            )
        return events

    prev_keys = set(previous.keys())
    curr_keys = set(current.keys())

    # 1. New entries
    for key in curr_keys - prev_keys:
        conn = current[key]
        event_name = (
            "LISTENER_OPENED"
            if _is_listener(conn)
            else "CONNECTION_APPEARED"
        )
        events.append(
            {
                "event_type": event_name,
                "connection": conn,
                "previous_connection": None,
            }
        )

    # 2. Removed entries
    for key in prev_keys - curr_keys:
        prev_conn = previous[key]
        event_name = (
            "LISTENER_CLOSED"
            if _is_listener(prev_conn)
            else "CONNECTION_DISAPPEARED"
        )
        events.append(
            {
                "event_type": event_name,
                "connection": prev_conn,
                "previous_connection": prev_conn,
            }
        )

    # 3. Modified entries
    for key in prev_keys & curr_keys:
        prev_conn = previous[key]
        curr_conn = current[key]
        if (
            prev_conn.get("status") != curr_conn.get("status")
            or prev_conn.get("pid") != curr_conn.get("pid")
        ):
            events.append(
                {
                    "event_type": "CONNECTION_STATE_CHANGED",
                    "connection": curr_conn,
                    "previous_connection": prev_conn,
                }
            )

    return events


def _snapshot_statistics(
    snapshot: Dict[Tuple[str, str, int, str, int], Dict[str, Any]]
) -> Dict[str, int]:
    """Derive connection count statistics from snapshot dictionary."""
    tcp_count = sum(
        1 for c in snapshot.values() if str(c.get("proto", "")).upper() == "TCP"
    )
    udp_count = sum(
        1 for c in snapshot.values() if str(c.get("proto", "")).upper() == "UDP"
    )

    def _is_v6(c: Dict[str, Any]) -> bool:
        fam = c.get("family")
        if fam in (socket.AF_INET6, getattr(socket, "AF_INET6", 23)):
            return True
        return ":" in str(c.get("laddr", "")) or ":" in str(c.get("raddr", ""))

    ipv6_count = sum(1 for c in snapshot.values() if _is_v6(c))
    ipv4_count = len(snapshot) - ipv6_count

    return {
        "total_connections": len(snapshot),
        "tcp_connections": tcp_count,
        "udp_connections": udp_count,
        "ipv4_connections": ipv4_count,
        "ipv6_connections": ipv6_count,
    }


def watch(
    interval: float = 1.0, callback: Optional[Callable] = None
) -> Generator[
    Tuple[
        Dict[Tuple[str, str, int, str, int], Dict[str, Any]],
        List[Dict[str, Any]],
        Dict[str, Any],
    ],
    None,
    None,
]:
    """Poll connections periodically, emitting (snapshot, events, diagnostics)."""
    previous = None
    poll_number = 0

    while True:
        start_time = time.perf_counter()
        poll_number += 1

        current = _snapshot()
        events = compare_snapshots(previous, current)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        stats = _snapshot_statistics(current)
        diagnostics = {
            "poll_number": poll_number,
            "poll_duration_ms": round(duration_ms, 3),
            "events_generated": len(events),
            **stats,
        }

        print(f"[Diagnostics] Poll #{poll_number}: {diagnostics}")

        if callback:
            callback(current, events, diagnostics)

        yield current, events, diagnostics
        previous = current
        time.sleep(interval)
