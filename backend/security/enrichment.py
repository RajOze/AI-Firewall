"""Event Enrichment Layer for AI Firewall.

Enriches raw network connection events with process intelligence metadata.
"""

import logging
from typing import Any

from backend.security.intelligence import ProcessIntelligenceEngine, get_process_info
from backend.security.models import EnrichedConnection, ProcessInfo

logger = logging.getLogger(__name__)


def enrich_connection(
    connection: dict[str, Any],
    process_engine: ProcessIntelligenceEngine | None = None,
) -> EnrichedConnection:
    """Enrich a raw network connection event dictionary with process intelligence metadata.

    Args:
        connection: Raw network connection dictionary (e.g. containing pid, proto, laddr, raddr).
        process_engine: Optional ProcessIntelligenceEngine instance (defaults to global engine).

    Returns:
        EnrichedConnection instance containing connection details and process metadata.
        Never raises unhandled exceptions; returns partial data on failure.
    """
    if not isinstance(connection, dict):
        logger.error("Invalid connection event type provided: %s", type(connection))
        raw_dict: dict[str, Any] = {}
    else:
        raw_dict = dict(connection)

    raw_pid = raw_dict.get("pid")
    pid: int | None = None

    if isinstance(raw_pid, int) and raw_pid > 0:
        pid = raw_pid
    elif isinstance(raw_pid, str) and raw_pid.isdigit() and int(raw_pid) > 0:
        pid = int(raw_pid)

    process_info: ProcessInfo | None = None

    try:
        if pid is not None:
            if process_engine is not None:
                process_info = process_engine.get_process_info(pid)
            else:
                process_info = get_process_info(pid)
        else:
            logger.debug("Connection event has missing or invalid PID: %s", raw_pid)
            process_info = ProcessInfo(
                pid=0,
                error_message=f"Missing or invalid PID in connection event: {raw_pid}",
            )
    except Exception as exc:
        logger.exception("Error enriching connection event for PID %s", pid)
        process_info = ProcessInfo(
            pid=pid if pid is not None else 0,
            error_message=f"Enrichment lookup failed: {exc}",
        )

    return EnrichedConnection(
        pid=pid,
        proto=raw_dict.get("proto"),
        laddr=raw_dict.get("laddr"),
        lport=raw_dict.get("lport"),
        raddr=raw_dict.get("raddr"),
        rport=raw_dict.get("rport"),
        status=raw_dict.get("status"),
        family=raw_dict.get("family"),
        process_info=process_info,
        raw_connection=raw_dict,
    )
