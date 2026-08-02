"""Windows-specific process inspection provider using psutil and Windows APIs."""

import logging
import sys

import psutil

from backend.security.cache import ProcessIntelligenceCache
from backend.security.hashing import calculate_sha256
from backend.security.models import ProcessInfo

logger = logging.getLogger(__name__)


class WindowsProcessProvider:
    """Provides process metadata and binary intelligence for Windows system processes."""

    def __init__(self, cache: ProcessIntelligenceCache | None = None):
        self.cache = cache or ProcessIntelligenceCache()

    def _check_is_elevated(self, proc: psutil.Process) -> bool | None:
        """Check if the process is elevated (admin)."""
        if sys.platform != "win32":
            return None

        try:
            import ctypes.wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            TOKEN_QUERY = 0x0008
            TokenElevation = 20

            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, proc.pid
            )
            if not handle:
                return None

            try:
                token = ctypes.wintypes.HANDLE()
                if ctypes.windll.advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
                    try:
                        elevation = ctypes.c_ulong()
                        size = ctypes.c_ulong()
                        if ctypes.windll.advapi32.GetTokenInformation(
                            token,
                            TokenElevation,
                            ctypes.byref(elevation),
                            ctypes.sizeof(elevation),
                            ctypes.byref(size),
                        ):
                            return bool(elevation.value)
                    finally:
                        ctypes.windll.kernel32.CloseHandle(token)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not determine elevation for PID %d: %s", proc.pid, exc)

        return None

    def get_process_info(self, pid: int) -> ProcessInfo:
        """Fetch ProcessInfo for the given PID, handling access denial and process state gracefully.

        Args:
            pid: Process Identifier.

        Returns:
            ProcessInfo object containing metadata and partial error details if restricted.
        """
        try:
            proc = psutil.Process(pid)
        except psutil.ZombieProcess:
            logger.warning("Process PID %d is a zombie process", pid)
            return ProcessInfo(
                pid=pid,
                status="zombie",
                access_denied=False,
                error_message=f"Process PID {pid} is a zombie process",
            )
        except psutil.NoSuchProcess:
            logger.warning("Process PID %d does not exist", pid)
            return ProcessInfo(pid=pid, error_message=f"Process PID {pid} not found")
        except psutil.AccessDenied:
            logger.warning("Access denied when accessing PID %d", pid)
            return ProcessInfo(
                pid=pid, access_denied=True, error_message=f"Access denied for process PID {pid}"
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error creating Process object for PID %d: %s", pid, exc)
            return ProcessInfo(pid=pid, error_message=str(exc))

        access_denied = False
        name: str | None = None
        exe_path: str | None = None
        cmdline: list[str] | None = None
        username: str | None = None
        create_time: float | None = None
        parent_pid: int | None = None
        status: str | None = None
        cpu_percent: float | None = None
        memory_rss: int | None = None
        memory_vms: int | None = None
        sha256: str | None = None
        is_elevated: bool | None = None

        # Fetch attributes individually to handle partial AccessDenied gracefully
        try:
            name = proc.name()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            exe_path = proc.exe()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            cmdline = proc.cmdline()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            username = proc.username()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            create_time = proc.create_time()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            parent_pid = proc.ppid()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            status = proc.status()
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            cpu_percent = proc.cpu_percent(interval=None)
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        try:
            mem_info = proc.memory_info()
            if mem_info:
                memory_rss = getattr(mem_info, "rss", None)
                memory_vms = getattr(mem_info, "vms", None)
        except (psutil.AccessDenied, PermissionError):
            access_denied = True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        # Hash executable if path was accessible
        if exe_path:
            sha256 = self.cache.get_hash(exe_path)
            if not sha256:
                sha256 = calculate_sha256(exe_path)
                if sha256:
                    self.cache.set_hash(exe_path, sha256)

        # Elevation check
        is_elevated = self._check_is_elevated(proc)

        error_message = (
            "Partial process data retrieved due to access restrictions" if access_denied else None
        )

        return ProcessInfo(
            pid=pid,
            name=name,
            exe_path=exe_path,
            cmdline=cmdline,
            username=username,
            create_time=create_time,
            parent_pid=parent_pid,
            sha256=sha256,
            status=status,
            cpu_percent=cpu_percent,
            memory_rss=memory_rss,
            memory_vms=memory_vms,
            is_elevated=is_elevated,
            access_denied=access_denied,
            error_message=error_message,
        )
