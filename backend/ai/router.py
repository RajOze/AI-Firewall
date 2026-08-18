"""AIRouter: Multi-provider orchestration, timeout guardrails, and advisory isolation."""
import asyncio
import logging
import time
from typing import Any

from backend.ai.providers.base import BaseAIProvider, ProviderHealth, ProviderStatus
from backend.ai.providers.gemini_provider import GeminiFlashProvider
from backend.ai.providers.local_fallback import LocalFallbackProvider
from backend.ai.schemas import ThreatAdvisory

logger = logging.getLogger(__name__)


class AIRouter:
    def __init__(
        self,
        primary_provider: BaseAIProvider | None = None,
        fallback_provider: BaseAIProvider | None = None,
        default_timeout_sec: float = 3.0,
    ) -> None:
        self.primary_provider = primary_provider or GeminiFlashProvider(timeout_sec=default_timeout_sec)
        self.fallback_provider = fallback_provider or LocalFallbackProvider()
        self.default_timeout_sec = default_timeout_sec

    async def get_providers_health(self) -> dict[str, ProviderHealth]:
        tasks = [
            self.primary_provider.health_check(),
            self.fallback_provider.health_check(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_map = {}
        for provider, res in zip([self.primary_provider, self.fallback_provider], results):
            if isinstance(res, Exception):
                health_map[provider.provider_name] = ProviderHealth(
                    provider_name=provider.provider_name,
                    status=ProviderStatus.OFFLINE,
                    message=str(res),
                )
            else:
                health_map[provider.provider_name] = res
        return health_map

    async def analyze_threat(
        self,
        context: dict[str, Any],
        timeout_sec: float | None = None,
        force_fallback: bool = False,
    ) -> ThreatAdvisory:
        timeout = timeout_sec or self.default_timeout_sec

        if not force_fallback:
            try:
                advisory = await asyncio.wait_for(
                    self.primary_provider.generate_advisory(context),
                    timeout=timeout,
                )
                logger.info(
                    "Generated threat advisory via primary provider: %s (Severity: %s)",
                    self.primary_provider.provider_name,
                    advisory.severity,
                )
                return advisory
            except asyncio.TimeoutError:
                logger.warning(
                    "Primary AI provider %s timed out after %.2fs; activating local fallback.",
                    self.primary_provider.provider_name,
                    timeout,
                )
            except Exception as exc:
                logger.warning(
                    "Primary AI provider %s failed (%s); activating local fallback.",
                    self.primary_provider.provider_name,
                    exc,
                )

        fallback_advisory = await self.fallback_provider.generate_advisory(context)
        logger.info(
            "Generated threat advisory via fallback provider: %s (Severity: %s)",
            self.fallback_provider.provider_name,
            fallback_advisory.severity,
        )
        return fallback_advisory
