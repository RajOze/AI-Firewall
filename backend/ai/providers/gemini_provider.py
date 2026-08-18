"""Google Gemini 2.5 Flash Provider for online structured threat reasoning."""
import json
import logging
import os
import time
from typing import Any
import httpx

from backend.ai.prompts import SYSTEM_THREAT_ANALYST_PROMPT, build_analysis_prompt
from backend.ai.providers.base import BaseAIProvider, ProviderHealth, ProviderStatus
from backend.ai.schemas import ThreatAdvisory

logger = logging.getLogger(__name__)


class GeminiFlashProvider(BaseAIProvider):
    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
        timeout_sec: float = 3.0,
    ) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.model = model
        self.timeout_sec = timeout_sec
        self._endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    @property
    def provider_name(self) -> str:
        return f"gemini:{self.model}"

    def is_configured(self) -> bool:
        return bool(self.api_key and not self.api_key.startswith("test-placeholder"))

    async def health_check(self) -> ProviderHealth:
        if not self.is_configured():
            return ProviderHealth(
                provider_name=self.provider_name,
                status=ProviderStatus.UNCONFIGURED,
                message="GEMINI_API_KEY not configured",
            )
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
                url = f"{self._endpoint}?key={self.api_key}"
                payload = {
                    "contents": [{"parts": [{"text": "Health check: respond with 'OK'"}]}],
                    "generationConfig": {"maxOutputTokens": 5},
                }
                resp = await client.post(url, json=payload)
                elapsed_ms = (time.perf_counter() - start) * 1000
                if resp.status_code == 200:
                    return ProviderHealth(
                        provider_name=self.provider_name,
                        status=ProviderStatus.ONLINE,
                        latency_ms=round(elapsed_ms, 2),
                    )
                return ProviderHealth(
                    provider_name=self.provider_name,
                    status=ProviderStatus.DEGRADED,
                    latency_ms=round(elapsed_ms, 2),
                    message=f"HTTP {resp.status_code}: {resp.text[:100]}",
                )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return ProviderHealth(
                provider_name=self.provider_name,
                status=ProviderStatus.OFFLINE,
                latency_ms=round(elapsed_ms, 2),
                message=str(exc),
            )

    async def generate_advisory(self, context: dict[str, Any]) -> ThreatAdvisory:
        if not self.is_configured():
            raise RuntimeError("Gemini API key is not configured.")

        start = time.perf_counter()
        prompt_text = build_analysis_prompt(context)

        request_body = {
            "system_instruction": {
                "parts": [{"text": SYSTEM_THREAT_ANALYST_PROMPT}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt_text}],
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.1,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
            url = f"{self._endpoint}?key={self.api_key}"
            resp = await client.post(url, json=request_body)
            elapsed_ms = (time.perf_counter() - start) * 1000

            if resp.status_code != 200:
                raise RuntimeError(
                    f"Gemini API error (status {resp.status_code}): {resp.text}"
                )

            data = resp.json()
            try:
                candidate = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(candidate)
            except (KeyError, IndexError, json.JSONDecodeError) as exc:
                raise ValueError(f"Failed to parse structured JSON from Gemini response: {exc}")

            parsed["process_name"] = context.get("process_name", "unknown.exe")
            parsed["process_id"] = context.get("process_id")
            parsed["destination_ip"] = context.get("destination_ip")
            parsed["destination_port"] = context.get("destination_port")
            parsed["protocol"] = context.get("protocol", "TCP")
            parsed["provider_name"] = self.provider_name
            parsed["inference_latency_ms"] = round(elapsed_ms, 2)
            parsed["is_fallback"] = False
            parsed["is_advisory_only"] = True

            return ThreatAdvisory.model_validate(parsed)
