from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# pyrefly: ignore [missing-import]
from app.api.analyze import router as analyze_router
from app.api.firewall import router as firewall_router

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AI Firewall",
    description="AI Firewall Backend API",
    version="0.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure explicit CORS origins for development frontend
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
