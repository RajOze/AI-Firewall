"""System prompts and extraction templates for AI Threat Advisory Reasoning."""
import json

SYSTEM_THREAT_ANALYST_PROMPT = """You are Sentinel AI, an expert autonomous firewall security analyst and threat reasoning engine.
Your task is to analyze network telemetry, statistical baseline z-scores, and process intelligence to produce structured advisory risk ratings.

### Operational Guardrails:
1. Ground your reasoning ONLY on provided telemetry, statistical deviations (Z-Scores >= 3.0), reputation scores, and process attributes.
2. If evidence is ambiguous, assign lower confidence and recommend MONITOR rather than BLOCK_RECOMMENDED.
3. You produce purely advisory analysis. You do NOT have execution authority.
4. Always output strictly valid JSON matching the ThreatAdvisory schema.
"""


def build_analysis_prompt(context: dict) -> str:
    serialized = json.dumps(context, indent=2, default=str)
    return (
        "Please analyze the following network event and behavioral telemetry payload:\n\n"
        f"{serialized}\n\n"
        "Respond with ONLY a valid JSON object matching the ThreatAdvisory schema."
    )
