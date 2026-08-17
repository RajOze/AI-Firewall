"""Sentinel AI Firewall Backend Application Entrypoint."""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.api.analyze import router as analyze_router
from app.api.events import router as events_router
from app.api.firewall import router as firewall_router
from app.dependencies.telemetry import get_telemetry_service

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application background workers lifecycle."""
    # Avoid starting continuous thread polling during automated test runs
    is_testing = os.getenv("PYTEST_CURRENT_TEST") is not None
    telemetry_service = get_telemetry_service()
    
    if not is_testing:
        await telemetry_service.start()
        
    try:
        yield
    finally:
        if not is_testing:
            await telemetry_service.stop()


app = FastAPI(
    title="Sentinel AI Firewall",
    description="AI-Driven Windows Firewall & Threat Analysis Engine",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS origins
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(analyze_router)
app.include_router(firewall_router)
app.include_router(events_router)


@app.get("/")
def read_root():
    return {
        "project": "Sentinel AI Firewall",
        "version": "0.1.0",
        "status": "operational",
    }


@app.get("/health")
def read_health():
    return {
        "status": "healthy",
    }
