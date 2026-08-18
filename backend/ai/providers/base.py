"""Abstract Base Provider for AI Threat Reasoning."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

from backend.ai.schemas import ThreatAdvisory


class ProviderStatus(str, Enum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNCONFIGURED = "UNCONFIGURED"


@dataclass
class ProviderHealth:
    provider_name: str
    status: ProviderStatus
    latency_ms: float | None = None
    message: str = "Operational"


class BaseAIProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def health_check(self) -> ProviderHealth:
        pass

    @abstractmethod
    async def generate_advisory(self, context: dict[str, Any]) -> ThreatAdvisory:
        pass
