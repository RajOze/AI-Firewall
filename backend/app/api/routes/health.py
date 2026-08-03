from fastapi import APIRouter
from app.core.response import ApiResponse

router = APIRouter(prefix="/api/v1/health", tags=["Health"])

@router.get("/", response_model=ApiResponse)
async def health():
    return ApiResponse(
        message="Backend healthy",
        data={
            "api": "online",
            "firewall": "pending",
            "ai": "pending",
            "version": "0.1.0"
        }
    )
