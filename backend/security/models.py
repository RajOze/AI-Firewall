"""Data models for security process intelligence."""

from dataclasses import dataclass
from typing import Any


@dataclass
class ProcessInfo:
    """Represents intelligence metadata for a system process.

    Attributes:
        pid: Process Identifier.
        name: Name of the process executable.
        exe_path: Absolute path to the process executable file.
        cmdline: Command line arguments passed to launch the process.
        username: Name of the user account running the process.
        create_time: Process creation timestamp (Epoch seconds).
        parent_pid: PID of the parent process.
        sha256: SHA-256 hash of the executable binary.
        status: Current process execution status (e.g., 'running', 'sleeping', 'zombie').
        cpu_percent: Recent CPU utilization percentage.
        memory_rss: Resident set size memory in bytes.
        memory_vms: Virtual memory size in bytes.
        is_elevated: True if process is running with administrative privileges.
        access_denied: True if access to some process details was restricted.
        error_message: Error description if process lookup partially or completely failed.
    """

    pid: int
    name: str | None = None
    exe_path: str | None = None
    cmdline: list[str] | None = None
    username: str | None = None
    create_time: float | None = None
    parent_pid: int | None = None
    sha256: str | None = None
    status: str | None = None
    cpu_percent: float | None = None
    memory_rss: int | None = None
    memory_vms: int | None = None
    is_elevated: bool | None = None
    access_denied: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert process info to a dictionary representation."""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "username": self.username,
            "create_time": self.create_time,
            "parent_pid": self.parent_pid,
            "sha256": self.sha256,
            "status": self.status,
            "cpu_percent": self.cpu_percent,
            "memory_rss": self.memory_rss,
            "memory_vms": self.memory_vms,
            "is_elevated": self.is_elevated,
            "access_denied": self.access_denied,
            "error_message": self.error_message,
        }

    @property
    def is_complete(self) -> bool:
        """Returns True if essential metadata (name, exe_path, sha256) were retrieved successfully."""
        return bool(self.name and self.exe_path and self.sha256 and not self.error_message)
