from app.api.analyze import router as analyze_router
from dotenv import load_dotenv
from fastapi import FastAPI

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AI Firewall",
    description="AI Firewall Backend API",
    version="0.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Register API routes
app.include_router(analyze_router)


@app.get("/")
def read_root():
    return {
        "project": "AI Firewall",
        "version": "0.0.0",
    }


@app.get("/health")
def read_health():
    return {
        "status": "healthy",
    }
