"""Caching layer for process metadata and executable binary hashes."""

import logging
import threading
import time
from pathlib import Path

from backend.security.models import ProcessInfo

logger = logging.getLogger(__name__)

DEFAULT_METADATA_TTL = 30.0  # seconds for process metadata cache


class ProcessIntelligenceCache:
    """Thread-safe caching layer for process intelligence and executable hashes."""

    def __init__(self, metadata_ttl: float = DEFAULT_METADATA_TTL):
        self._metadata_ttl = metadata_ttl
        self._lock = threading.Lock()
        # Maps pid -> (ProcessInfo, timestamp, create_time)
        self._process_cache: dict[int, tuple[ProcessInfo, float, float | None]] = {}
        # Maps file_path -> (sha256_hash, mtime, size)
        self._hash_cache: dict[str, tuple[str, float, int]] = {}

    def get_process_info(self, pid: int) -> ProcessInfo | None:
        """Retrieve cached ProcessInfo for a given PID if valid."""
        with self._lock:
            entry = self._process_cache.get(pid)
            if entry is None:
                return None

            info, cached_at, _cached_create_time = entry
            now = time.time()

            if (now - cached_at) > self._metadata_ttl:
                logger.debug("Cache expired for PID %d", pid)
                del self._process_cache[pid]
                return None

            return info

    def set_process_info(self, info: ProcessInfo) -> None:
        """Cache ProcessInfo for a given PID."""
        with self._lock:
            self._process_cache[info.pid] = (info, time.time(), info.create_time)

    def get_hash(self, file_path: str | Path) -> str | None:
        """Retrieve cached SHA-256 hash if the file has not been modified."""
        path_str = str(Path(file_path).resolve())
        with self._lock:
            cached = self._hash_cache.get(path_str)
            if cached is None:
                return None

            sha256_hash, cached_mtime, cached_size = cached
            try:
                stat = Path(path_str).stat()
                if stat.st_mtime == cached_mtime and stat.st_size == cached_size:
                    return sha256_hash
                else:
                    logger.debug("File %s modified since cached; invalidating hash", path_str)
                    del self._hash_cache[path_str]
                    return None
            except (OSError, PermissionError, FileNotFoundError):
                self._hash_cache.pop(path_str, None)
                return None

    def set_hash(self, file_path: str | Path, sha256_hash: str) -> None:
        """Cache SHA-256 hash associated with a file path and its current mtime/size."""
        path_str = str(Path(file_path).resolve())
        try:
            stat = Path(path_str).stat()
            with self._lock:
                self._hash_cache[path_str] = (sha256_hash, stat.st_mtime, stat.st_size)
        except (OSError, PermissionError, FileNotFoundError):
            pass

    def invalidate_process(self, pid: int) -> None:
        """Remove a process from the metadata cache."""
        with self._lock:
            self._process_cache.pop(pid, None)

    def clear(self) -> None:
        """Clear all metadata and hash caches."""
        with self._lock:
            self._process_cache.clear()
            self._hash_cache.clear()
