from app.rules.prompt_injection import check_prompt_injection


def analyze_text(text: str) -> dict:
    """
    Analyze input text using all available security rules.
    Returns the highest-priority finding or a safe result.
    """

    finding = check_prompt_injection(text)

    if finding:
        return finding

    return {
        "safe": True,
        "score": 0,
        "category": "Safe",
        "reason": "No known prompt injection patterns detected.",
    }
