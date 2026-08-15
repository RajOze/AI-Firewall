"""Process Telemetry Monitor for tracking host process start and stop events."""

import logging
import sys
from typing import Any
import psutil

from app.schemas.events import ProcessStartEvent, ProcessStopEvent
from backend.security.providers.windows import WindowsProcessProvider

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitors host system for process creation (PROCESS_START) and termination (PROCESS_STOP)."""

    def __init__(self, windows_provider: WindowsProcessProvider | None = None) -> None:
        self.windows_provider = windows_provider or WindowsProcessProvider()
        self._active_processes: dict[int, dict[str, Any]] = {}
        self._initialized = False

    def poll(self) -> list[ProcessStartEvent | ProcessStopEvent]:
        """Poll host system PIDs and return normalized PROCESS_START / PROCESS_STOP events."""
        events: list[ProcessStartEvent | ProcessStopEvent] = []
        current_pids: set[int] = set()
        current_proc_map: dict[int, dict[str, Any]] = {}

        for proc in psutil.process_iter(attrs=["pid", "name", "ppid"]):
            try:
                pid = proc.info["pid"]
                if pid <= 0:
                    continue
                current_pids.add(pid)
                current_proc_map[pid] = {
                    "name": proc.info.get("name") or "unknown",
                    "ppid": proc.info.get("ppid"),
                }
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                continue

        if not self._initialized:
            # First poll initializes active baseline PIDs without generating massive backfill storm
            for pid in current_pids:
                info = current_proc_map[pid]
                proc_info = self.windows_provider.get_process_info(pid)
                self._active_processes[pid] = {
                    "name": proc_info.name or info["name"],
                    "ppid": proc_info.parent_pid or info["ppid"],
                    "exe_path": proc_info.exe_path,
                }
            self._initialized = True
            logger.info("ProcessMonitor initialized with %d active processes.", len(current_pids))
            return events

        previous_pids = set(self._active_processes.keys())

        # Detect new processes (PROCESS_START)
        new_pids = current_pids - previous_pids
        for pid in new_pids:
            try:
                info = current_proc_map.get(pid, {})
                proc_info = self.windows_provider.get_process_info(pid)

                name = proc_info.name or info.get("name") or "unknown"
                ppid = proc_info.parent_pid if proc_info.parent_pid is not None else info.get("ppid")
                exe_path = proc_info.exe_path
                cmdline = proc_info.cmdline
                publisher = proc_info.publisher
                is_signed = proc_info.is_signed

                event = ProcessStartEvent(
                    process_id=pid,
                    parent_process_id=ppid,
                    process_name=name,
                    executable_path=exe_path,
                    command_line=cmdline,
                    publisher=publisher,
                    is_signed=is_signed,
                )
                events.append(event)

                self._active_processes[pid] = {
                    "name": name,
                    "ppid": ppid,
                    "exe_path": exe_path,
                }
            except Exception as exc:
                logger.debug("Error processing PROCESS_START for PID %d: %s", pid, exc)

        # Detect terminated processes (PROCESS_STOP)
        stopped_pids = previous_pids - current_pids
        for pid in stopped_pids:
            cached_info = self._active_processes.pop(pid, {})
            event = ProcessStopEvent(
                process_id=pid,
                parent_process_id=cached_info.get("ppid"),
                process_name=cached_info.get("name", "unknown"),
                executable_path=cached_info.get("exe_path"),
            )
            events.append(event)

        return events
