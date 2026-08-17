from pydantic import BaseModel


class AnalyzeResponse(BaseModel):
    safe: bool
    score: int
    category: str
    reason: str


class FirewallRuleStatusResponse(BaseModel):
    rule_name: str
    exists: bool

class FirewallRuleResponse(BaseModel):
    name: str
    display_name: str
    enabled: bool
    direction: str
    action: str
    profile: str
