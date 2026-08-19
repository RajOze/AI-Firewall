"""Gemma Local Provider for on-device quantized threat reasoning."""
import json
import os
import time
from typing import Any

import logging

from backend.ai.providers.base import BaseAIProvider, ProviderHealth, ProviderStatus
from backend.ai.prompts import SYSTEM_THREAT_ANALYST_PROMPT, build_analysis_prompt
from backend.ai.schemas import ThreatAdvisory

logger = logging.getLogger(__name__)

try:
    from llama_cpp import Llama
    LLAMA_CPP_AVAILABLE = True
except ImportError:
    LLAMA_CPP_AVAILABLE = False
    logger.warning("llama-cpp-python not installed. GemmaLocalProvider will not be functional.")


class GemmaLocalProvider(BaseAIProvider):
    def __init__(
        self,
        model_path: str | None = None,
        n_ctx: int = 2048,
        n_batch: int = 512,
        timeout_sec: float = 3.0,
    ) -> None:
        """
        Initialize the Gemma local provider.

        Args:
            model_path: Path to the quantized Gemma model file (gguf format).
            n_ctx: Context size for the model.
            n_batch: Batch size for prompt processing.
            timeout_sec: Timeout for generating an advisory.
        """
        self.model_path = model_path or os.getenv("GEMMA_MODEL_PATH", "./models/gemma-2b-it-q4_0.gguf")
        self.n_ctx = n_ctx
        self.n_batch = n_batch
        self.timeout_sec = timeout_sec
        self._model: Llama | None = None
        self._load_model()

    def _load_model(self) -> None:
        """Load the quantized Gemma model."""
        if not LLAMA_CPP_AVAILABLE:
            logger.error("Cannot load Gemma model: llama-cpp-python not installed.")
            return
        try:
            self._model = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_batch=self.n_batch,
                # Use GPU if available, else CPU
                n_gpu_layers=0,  # Set to 0 for CPU, or adjust if GPU is available
                verbose=False,
            )
            logger.info(f"Gemma model loaded from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load Gemma model: {e}")
            self._model = None

    @property
    def provider_name(self) -> str:
        return "gemma-local:quantized-v1"

    async def health_check(self) -> ProviderHealth:
        if not LLAMA_CPP_AVAILABLE or self._model is None:
            return ProviderHealth(
                provider_name=self.provider_name,
                status=ProviderStatus.OFFLINE,
                message="Gemma model not available or failed to load",
            )
        # Simple health check: generate a trivial completion to see if the model responds
        start = time.perf_counter()
        try:
            # We'll use a simple prompt to test the model
            response = self._model.create_completion(
                prompt="Health check: respond with 'OK'",
                max_tokens=5,
                temperature=0.0,
                timeout=self.timeout_sec,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            if response and "choices" in response:
                return ProviderHealth(
                    provider_name=self.provider_name,
                    status=ProviderStatus.ONLINE,
                    latency_ms=round(elapsed_ms, 2),
                    message="Gemma model is responsive",
                )
            else:
                return ProviderHealth(
                    provider_name=self.provider_name,
                    status=ProviderStatus.DEGRADED,
                    latency_ms=round(elapsed_ms, 2),
                    message="Unexpected response from model",
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
        if self._model is None:
            raise RuntimeError("Gemma model is not loaded.")

        start = time.perf_counter()
        # Build the full prompt including system instruction and user context
        prompt_text = build_analysis_prompt(context)
        full_prompt = f"{SYSTEM_THREAT_ANALYST_PROMPT}\n\n{prompt_text}"

        # Generate the advisory using the model
        try:
            response = self._model.create_completion(
                prompt=full_prompt,
                response_format={"type": "json_object"},  # Enforce JSON output
                temperature=0.1,
                max_tokens=1024,
                timeout=self.timeout_sec,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            if not response or "choices" not in response or not response["choices"]:
                raise ValueError("Invalid response from Gemma model")

            content = response["choices"][0]["text"]
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as exc:
                # If the model didn't output valid JSON, try to extract JSON from the text
                # Look for the first '{' and last '}'
                try:
                    start_idx = content.index("{")
                    end_idx = content.rindex("}") + 1
                    json_str = content[start_idx:end_idx]
                    parsed = json.loads(json_str)
                except (ValueError, json.JSONDecodeError) as e2:
                    raise ValueError(
                        f"Failed to parse JSON from Gemma response: {exc}. "
                        f"Fallback extraction also failed: {e2}"
                    ) from exc

            # Ensure the required fields from context are present
            parsed.setdefault("process_name", context.get("process_name", "unknown.exe"))
            parsed.setdefault("process_id", context.get("process_id"))
            parsed.setdefault("destination_ip", context.get("destination_ip"))
            parsed.setdefault("destination_port", context.get("destination_port"))
            parsed.setdefault("protocol", context.get("protocol", "TCP"))
            parsed["provider_name"] = self.provider_name
            parsed["inference_latency_ms"] = round(elapsed_ms, 2)
            parsed["is_fallback"] = False
            parsed["is_advisory_only"] = True

            return ThreatAdvisory.model_validate(parsed)
        except Exception as exc:
            logger.error(f"Error generating advisory with Gemma model: {exc}")
            raise