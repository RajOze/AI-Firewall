from typing import Optional


PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "forget previous instructions",
    "system prompt",
    "developer message",
    "reveal your prompt",
    "reveal the system prompt",
    "bypass",
    "override",
    "act as",
]


def check_prompt_injection(text: str) -> Optional[dict]:
    """
    Detect simple prompt injection attempts using keyword matching.
    Returns a finding dictionary if a threat is detected, otherwise None.
    """

    normalized_text = text.lower().strip()

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in normalized_text:
            return {
                "safe": False,
                "score": 90,
                "category": "Prompt Injection",
                "reason": f"Detected suspicious phrase: '{pattern}'",
            }

    return None