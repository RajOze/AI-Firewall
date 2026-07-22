from pydantic import BaseModel


class AnalyzeResponse(BaseModel):
    safe: bool
    score: int
    category: str
    reason: str