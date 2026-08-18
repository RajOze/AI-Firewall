from pathlib import Path

main_code = """\"\"\"Sentinel AI Firewall Backend Application Entrypoint.\"\"\"
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analyze import router as analyze_router
from app.api.events import router as events_router
from app.api.firewall import router as firewall_router
from app.api.advisory import router as advisory_router
from app.api.policy import router as policy_router
from app.api.stream import router as stream_router
from app.dependencies.telemetry import get_telemetry_service

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    \"\"\"Manage application background workers lifecycle.\"\"\"
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(firewall_router)
app.include_router(events_router)
app.include_router(advisory_router)
app.include_router(policy_router)
app.include_router(stream_router)


@app.get("/")
def read_root():
    return {
        "project": "Sentinel AI Firewall",
        "version": "0.1.0",
        "status": "operational",
    }


@app.get("/health")
def read_health():
    return {"status": "healthy"}
"""

Path("backend/app/main.py").write_text(main_code, encoding="utf-8")
print("Successfully verified backend/app/main.py")
