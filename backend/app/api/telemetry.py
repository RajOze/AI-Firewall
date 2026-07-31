from fastapi import APIRouter, Query

from network.monitor.connections import collect_connections


router = APIRouter(
    prefix="/api/v1/telemetry",
    tags=["telemetry"],
)


@router.get("/connections")
def get_connections(
    status: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
):
    connections = collect_connections()

    if status:
        expected_status = status.upper()
        connections = [
            connection
            for connection in connections
            if connection["status"].upper() == expected_status
        ]

    if protocol:
        expected_protocol = protocol.upper()
        connections = [
            connection
            for connection in connections
            if connection["protocol"].upper() == expected_protocol
        ]

    return {
        "count": len(connections),
        "connections": connections,
    }


@router.get("/summary")
def get_summary():
    connections = collect_connections()

    return {
        "total": len(connections),
        "established": sum(
            connection["status"] == "ESTABLISHED"
            for connection in connections
        ),
        "listening": sum(
            connection["status"] == "LISTEN"
            for connection in connections
        ),
        "time_wait": sum(
            connection["status"] == "TIME_WAIT"
            for connection in connections
        ),
        "tcp": sum(
            connection["protocol"] == "TCP"
            for connection in connections
        ),
        "udp": sum(
            connection["protocol"] == "UDP"
            for connection in connections
        ),
        "ipv4": sum(
            connection["family"] == "IPv4"
            for connection in connections
        ),
        "ipv6": sum(
            connection["family"] == "IPv6"
            for connection in connections
        ),
    }
