"""Request validation utilities for the AI Firewall."""

from __future__ import annotations

from typing import Any

MAX_PROMPT_LENGTH = 10_000


class RequestValidationError(ValueError):
    """Raised when an incoming request is invalid."""


def validate_request(data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate an incoming request payload.

    Expected format:
        {
            "prompt": "<user prompt>"
        }
    """

    if not isinstance(data, dict):
        raise RequestValidationError("Request body must be a JSON object.")

    if "prompt" not in data:
        raise RequestValidationError("Missing required field: 'prompt'.")

    prompt = data["prompt"]

    if not isinstance(prompt, str):
        raise RequestValidationError("'prompt' must be a string.")

    prompt = prompt.strip()

    if not prompt:
        raise RequestValidationError("'prompt' cannot be empty.")

    if len(prompt) > MAX_PROMPT_LENGTH:
        raise RequestValidationError(
            f"'prompt' exceeds maximum length of {MAX_PROMPT_LENGTH} characters."
        )

    return {"prompt": prompt}
