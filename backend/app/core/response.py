from typing import Any
from pydantic import BaseModel, Field

class ApiResponse(BaseModel):
    success: bool = True
    message: str
    data: Any = Field(default_factory=dict)

class ErrorResponse(BaseModel):
    success: bool = False
    message: str
    error: Any = Field(default_factory=dict)
