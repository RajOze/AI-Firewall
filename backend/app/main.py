from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.core.logging import configure_logging

configure_logging()

app = FastAPI(
    title="Sentinel AI Firewall",
    version="0.1.0",
    description="Production-grade AI-assisted Windows Endpoint Security Platform",
)

app.include_router(health_router)

@app.get("/")
async def root():
    return {
        "success": True,
        "message": "Sentinel AI Firewall Backend is running.",
        "data": {}
    }
