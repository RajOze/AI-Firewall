"""Process Intelligence Engine main module."""

import logging

from backend.security.cache import ProcessIntelligenceCache
from backend.security.models import ProcessInfo
from backend.security.providers.windows import WindowsProcessProvider

logger = logging.getLogger(__name__)


class ProcessIntelligenceEngine:
    """Engine responsible for inspecting system processes and providing intelligence metadata."""

    def __init__(
        self,
        provider: WindowsProcessProvider | None = None,
        cache: ProcessIntelligenceCache | None = None,
    ):
        self.cache = cache or ProcessIntelligenceCache()
        self.provider = provider or WindowsProcessProvider(cache=self.cache)

    def get_process_info(self, pid: int, use_cache: bool = True) -> ProcessInfo:
        """Retrieve metadata and binary intelligence for a given process PID.

        Args:
            pid: Process Identifier.
            use_cache: Whether to use cached metadata if available (default: True).

        Returns:
            ProcessInfo object containing details about the requested process.
        """
        if use_cache:
            cached_info = self.cache.get_process_info(pid)
            if cached_info is not None:
                logger.debug("Cache hit for PID %d", pid)
                return cached_info

        logger.debug("Cache miss for PID %d; querying provider", pid)
        info = self.provider.get_process_info(pid)

        # Do not cache total failure for non-existent process, but cache valid or partial results
        if info.create_time is not None or info.name is not None or info.access_denied:
            self.cache.set_process_info(info)

        return info


# Default global instance for convenience
_default_engine = ProcessIntelligenceEngine()


def get_process_info(pid: int, use_cache: bool = True) -> ProcessInfo:
    """Retrieve metadata and binary intelligence for a given process PID.

    Args:
        pid: Process Identifier.
        use_cache: Whether to use cached metadata if available (default: True).

    Returns:
        ProcessInfo object containing process metadata.
    """
    return _default_engine.get_process_info(pid, use_cache=use_cache)
