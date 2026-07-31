from dotenv import load_dotenv
from fastapi import FastAPI

from backend.app.api.telemetry import router as telemetry_router


load_dotenv()


app = FastAPI(
    title="AI Firewall",
    description="Real-Time AI-Assisted Windows Network Security Firewall",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


app.include_router(telemetry_router)


@app.get("/")
def read_root():
    return {
        "project": "AI Firewall",
        "version": "0.1.0",
        "mode": "real-telemetry",
    }


@app.get("/health")
def read_health():
    return {
        "status": "healthy",
    }
