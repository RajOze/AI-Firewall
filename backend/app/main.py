from fastapi import FastAPI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AI Firewall",
    description="AI Firewall Backend API",
    version="0.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.get("/")
def read_root():
    return {
        "project": "AI Firewall",
        "version": "0.0.0"
    }

@app.get("/health")
def read_health():
    return {
        "status": "healthy"
    }
