"""Unit tests for GemmaLocalProvider."""
import asyncio
import json
import sys
from unittest.mock import MagicMock, patch
import pytest

from backend.ai.providers.gemma_provider import GemmaLocalProvider
from backend.ai.providers.base import ProviderStatus
from backend.ai.schemas import (
    AdvisoryAction,
    ThreatAdvisory,
    ThreatSeverity,
)


def test_gemma_local_provider_initialization():
    """Test that GemmaLocalProvider initializes correctly."""
    provider = GemmaLocalProvider()
    assert provider.provider_name == "gemma-local:quantized-v1"
    assert provider.model_path == "./models/gemma-2b-it-q4_0.gguf"
    assert provider.n_ctx == 2048
    assert provider.n_batch == 512
    assert provider.timeout_sec == 3.0


def test_gemma_local_provider_custom_params():
    """Test GemmaLocalProvider with custom parameters."""
    provider = GemmaLocalProvider(
        model_path="/custom/path/model.gguf",
        n_ctx=4096,
        n_batch=1024,
        timeout_sec=5.0,
    )
    assert provider.model_path == "/custom/path/model.gguf"
    assert provider.n_ctx == 4096
    assert provider.n_batch == 1024
    assert provider.timeout_sec == 5.0


@pytest.mark.anyio
async def test_gemma_local_provider_health_check_not_available():
    """Test health check when llama-cpp-python is not available."""
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', False):
        provider = GemmaLocalProvider()
        health = await provider.health_check()
        assert health.status == ProviderStatus.OFFLINE
        assert "not available" in health.message.lower()


@pytest.mark.anyio
async def test_gemma_local_provider_health_check_load_failure():
    """Test health check when model fails to load."""
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', True):
        with patch.object(GemmaLocalProvider, '_load_model', return_value=None):
            provider = GemmaLocalProvider()
            health = await provider.health_check()
            assert health.status == ProviderStatus.OFFLINE
            assert "not available or failed to load" in health.message.lower()


@pytest.mark.anyio
async def test_gemma_local_provider_health_check_success():
    """Test successful health check."""
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', True):
        mock_model_instance = MagicMock()
        mock_model_instance.create_completion.return_value = {
            "choices": [{"text": "OK"}]
        }

        with patch.object(GemmaLocalProvider, '_load_model', return_value=mock_model_instance):
            provider = GemmaLocalProvider()
            health = await provider.health_check()

            assert health.status == ProviderStatus.ONLINE
            assert "responsive" in health.message
            assert health.latency_ms is not None and health.latency_ms >= 0
            assert mock_model_instance.create_completion.called


@pytest.mark.anyio
async def test_gemma_local_provider_health_check_timeout():
    """Test health check timeout."""
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', True):
        mock_model_instance = MagicMock()
        mock_model_instance.create_completion.side_effect = asyncio.TimeoutError()

        with patch.object(GemmaLocalProvider, '_load_model', return_value=mock_model_instance):
            provider = GemmaLocalProvider()
            health = await provider.health_check()

            assert health.status == ProviderStatus.OFFLINE
            assert "timeout" in health.message.lower() or "timed out" in health.message.lower()
            assert mock_model_instance.create_completion.called


@pytest.mark.anyio
async def test_gemma_local_provider_generate_advisory_not_loaded():
    """Test generate_advisory when model is not loaded."""
    # Test when LLAMA_CPP_AVAILABLE is False
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', False):
        provider = GemmaLocalProvider()
        with pytest.raises(RuntimeError, match="Gemma model is not available"):
            await provider.generate_advisory({"process_name": "test.exe"})

    # Test when _load_model returns None (but LLAMA_CPP_AVAILABLE is True)
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', True):
        with patch.object(GemmaLocalProvider, '_load_model', return_value=None):
            provider = GemmaLocalProvider()
            with pytest.raises(RuntimeError, match="Failed to load Gemma model"):
                await provider.generate_advisory({"process_name": "test.exe"})


@pytest.mark.anyio
async def test_gemma_local_provider_generate_advisory_success():
    """Test successful advisory generation."""
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', True):
        mock_model_instance = MagicMock()
        mock_response = {
            "choices": [{
                "text": json.dumps({
                    "severity": "MEDIUM",
                    "confidence_score": 0.75,
                    "recommended_action": "ALERT",
                    "summary": "Test threat detected",
                    "detailed_reasoning": "This is a test advisory",
                    "mitre_mappings": [],
                    "evidence": []
                })
            }]
        }
        mock_model_instance.create_completion.return_value = mock_response

        with patch.object(GemmaLocalProvider, '_load_model', return_value=mock_model_instance):
            provider = GemmaLocalProvider()

            context = {
                "process_name": "test.exe",
                "process_id": 1234,
                "destination_ip": "192.168.1.1",
                "destination_port": 8080,
                "protocol": "TCP"
            }

            advisory = await provider.generate_advisory(context)

            # Validate the advisory
            assert isinstance(advisory, ThreatAdvisory)
            assert advisory.severity == ThreatSeverity.MEDIUM
            assert advisory.confidence_score == 0.75
            assert advisory.recommended_action == AdvisoryAction.ALERT
            assert advisory.summary == "Test threat detected"
            assert advisory.detailed_reasoning == "This is a test advisory"
            assert advisory.provider_name == "gemma-local:quantized-v1"
            assert advisory.is_advisory_only is True
            assert advisory.is_fallback is False
            assert advisory.process_name == "test.exe"
            assert advisory.process_id == 1234
            assert advisory.destination_ip == "192.168.1.1"
            assert advisory.destination_port == 8080
            assert advisory.protocol == "TCP"

            assert mock_model_instance.create_completion.called


@pytest.mark.anyio
async def test_gemma_local_provider_generate_advisory_json_extraction():
    """Test advisory generation when model outputs JSON embedded in text."""
    with patch('backend.ai.providers.gemma_provider.LLAMA_CPP_AVAILABLE', True):
        mock_model_instance = MagicMock()
        mock_response = {
            "choices": [{
                "text": "Here is the analysis:\n{\"severity\": \"HIGH\", \"confidence_score\": 0.9, \"recommended_action\": \"BLOCK_RECOMMENDED\", \"summary\": \"Malicious activity\", \"detailed_reasoning\": \"Confirmed threat\", \"mitre_mappings\": [], \"evidence\": []}\nEnd of analysis."
            }]
        }
        mock_model_instance.create_completion.return_value = mock_response

        with patch.object(GemmaLocalProvider, '_load_model', return_value=mock_model_instance):
            provider = GemmaLocalProvider()

            advisory = await provider.generate_advisory({"process_name": "malware.exe"})

            assert advisory.severity == ThreatSeverity.HIGH
            assert advisory.confidence_score == 0.9
            assert advisory.recommended_action == AdvisoryAction.BLOCK_RECOMMENDED
            assert advisory.summary == "Malicious activity"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])