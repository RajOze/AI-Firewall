from __future__ import annotations

from datetime import datetime, timezone
import socket

import psutil


def _address(addr):
    if not addr:
        return None, None

    return addr.ip, addr.port


def _process_name(pid):
    if pid is None or pid == 0:
        return None

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def collect_connections():
    timestamp = datetime.now(timezone.utc).isoformat()

    results = []

    for connection in psutil.net_connections(kind="inet"):
        local_ip, local_port = _address(connection.laddr)
        remote_ip, remote_port = _address(connection.raddr)

        results.append(
            {
                "timestamp": timestamp,
                "pid": connection.pid,
                "process_name": _process_name(connection.pid),
                "family": (
                    "IPv4"
                    if connection.family == socket.AF_INET
                    else "IPv6"
                    if connection.family == socket.AF_INET6
                    else str(connection.family)
                ),
                "protocol": (
                    "TCP"
                    if connection.type == socket.SOCK_STREAM
                    else "UDP"
                    if connection.type == socket.SOCK_DGRAM
                    else str(connection.type)
                ),
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": connection.status,
            }
        )

    return results


if __name__ == "__main__":
    connections = collect_connections()

    print(f"Real connections detected: {len(connections)}")

    for connection in connections:
        print(connection)
