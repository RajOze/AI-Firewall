"""AIRouter: Multi-provider orchestration, timeout guardrails, and advisory isolation."""
import asyncio
import logging
import time
from typing import Any

from backend.ai.providers.base import BaseAIProvider, ProviderHealth, ProviderStatus
from backend.ai.providers.gemini_provider import GeminiFlashProvider
from backend.ai.providers.gemma_provider import GemmaLocalProvider
from backend.ai.providers.local_fallback import LocalFallbackProvider
from backend.ai.schemas import ThreatAdvisory

logger = logging.getLogger(__name__)


class AIRouter:
    def __init__(
        self,
        providers: list[BaseAIProvider] | None = None,
        default_timeout_sec: float = 3.0,
    ) -> None:
        """
        Initialize the AI router with a list of providers in order of preference.

        Args:
            providers: List of providers to try in sequence. If None, defaults to
                       [GeminiFlashProvider, GemmaLocalProvider, LocalFallbackProvider].
            default_timeout_sec: Default timeout for each provider attempt.
        """
        if providers is None:
            self.providers = [
                GeminiFlashProvider(timeout_sec=default_timeout_sec),
                GemmaLocalProvider(timeout_sec=default_timeout_sec),
                LocalFallbackProvider(),
            ]
        else:
            self.providers = providers
        self.default_timeout_sec = default_timeout_sec

    async def get_providers_health(self) -> dict[str, ProviderHealth]:
        """Run health checks on all providers concurrently."""
        tasks = [provider.health_check() for provider in self.providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_map = {}
        for provider, res in zip(self.providers, results):
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
        """
        Analyze threat by trying providers in order until one succeeds.

        Args:
            context: The telemetry and behavioral context for analysis.
            timeout_sec: Timeout for each provider attempt. If None, uses default.
            force_fallback: If True, skip all providers and use the last one (fallback).
        """
        timeout = timeout_sec or self.default_timeout_sec
        providers_to_try = self.providers

        if force_fallback:
            # Use only the last provider (assumed to be the fallback)
            providers_to_try = [self.providers[-1]]

        last_exception: Exception | None = None
        for provider in providers_to_try:
            try:
                advisory = await asyncio.wait_for(
                    provider.generate_advisory(context),
                    timeout=timeout,
                )
                logger.info(
                    "Generated threat advisory via provider: %s (Severity: %s)",
                    provider.provider_name,
                    advisory.severity,
                )
                return advisory
            except asyncio.TimeoutError:
                logger.warning(
                    "Provider %s timed out after %.2fs; trying next provider.",
                    provider.provider_name,
                    timeout,
                )
                last_exception = asyncio.TimeoutError(
                    f"Provider {provider.provider_name} timed out after {timeout}s"
                )
                continue
            except Exception as exc:
                logger.warning(
                    "Provider %s failed (%s); trying next provider.",
                    provider.provider_name,
                    exc,
                )
                last_exception = exc
                continue

        # If all providers failed, raise the last exception or return a generic error?
        # But note: the last provider is the LocalFallbackProvider which should never fail.
        # So we should have returned by now.
        # If we get here, it means the fallback provider also failed, which is unexpected.
        logger.error("All providers failed. Last error: %s", last_exception)
        raise last_exception or RuntimeError("All providers failed to generate advisory")