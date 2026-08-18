"""FastAPI dependency provider for AIRouter."""
from functools import lru_cache

from backend.ai.router import AIRouter


@lru_cache()
def get_ai_router() -> AIRouter:
    """Return a cached singleton instance of AIRouter."""
    return AIRouter()
