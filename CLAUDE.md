# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Backend (Python/FastAPI)
- **Start development server**: `uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload`
- **Run all unit tests**: `pytest --cov=backend --cov=network tests/unit`
- **Run specific test module**: `pytest tests/unit/security/test_baseline.py -v`
- **Format code with Ruff**: `ruff format .`
- **Check linting with Ruff**: `ruff check .`
- **Auto-fix lint issues**: `ruff check --fix .`
- **Activate virtual environment**: `.\.venv\Scripts\Activate.ps1` (PowerShell) or `source .venv/bin/activate` (bash)

### Frontend (React/Vite)
- **Start development server**: `cd frontend && npm run dev`
- **Lint TypeScript/ESLint**: `cd frontend && npm run lint`
- **Build for production**: `cd frontend && npm run build`
- **Preview production build**: `cd frontend && npm run preview`
- **Electron development**: `cd frontend && npm run electron:dev`

### General
- **Install backend dependencies**: `pip install -r requirements.txt -r requirements-dev.txt`
- **Install frontend dependencies**: `cd frontend && npm install`
- **Run all tests (backend + frontend)**: Run backend tests as above, then `cd frontend && npm run test` (if test script added)

## Code Architecture and Structure

### High-Level Components
The system follows a layered architecture as depicted in the README.md Mermaid diagram:
1. **Host Telemetry Layer**: Collects Windows ETW and process monitoring data
2. **Telemetry Ingestion & Normalization**: Processes raw events into normalized BehavioralEvent format
3. **AI & Risk Engine Pipeline**: 
   - Feature extraction (26 metrics)
   - Online baseline modeling using Welford's algorithm
   - Anomaly detection (Isolation Forest + z-score)
   - Network risk assessment
   - Deterministic risk fusion (0-1.0 score)
4. **Enforcement & Control**: Policy evaluation and Windows Firewall rule management
5. **Presentation Layer**: FastAPI backend API and React 18 + TypeScript dashboard

### Key Directories
- `backend/`: Core FastAPI application and security engine
  - `backend/app/`: API routers, models, dependencies, core configuration
  - `backend/security/`: AI models, baseline engines, feature extraction, risk fusion
  - `backend/app/api/`: REST endpoint handlers (/analyze, /events, /firewall)
  - `backend/app/schemas/`: Pydantic data models
- `frontend/`: React 18 + TypeScript dashboard with Vite
  - `frontend/src/components/`: Reusable UI widgets (charts, KPI cards)
  - `frontend/src/pages/`: Dashboard views (Dashboard, Firewall, Alerts, Assistant)
  - `frontend/src/services/`: API clients and real-time WebSocket hooks
- `network/`: Low-level packet capture and ETW event handling
- `tests/`: Test suites organized by type (unit, integration, security)
- `configs/`: Environment and profile configuration files
- `docs/`: Technical specifications and design records
- `scripts/`: Automation and utility scripts

### Important Files
- `backend/app/main.py`: Application entry point with lifespan events
- `backend/security/baseline.py`: Welford accumulator implementation and behavioral baseline engine
- `backend/security/risk_fusion.py`: Deterministic multi-signal risk scoring engine
- `frontend/src/services/api.ts`: Centralized API client with request interception
- `pyproject.toml`: Build configuration and tooling settings (Ruff, pytest, etc.)
- `requirements.txt`: Production Python dependencies
- `requirements-dev.txt`: Development dependencies (testing, linting)

### Data Flow
Telemetry flows from Windows kernel telemetry → normalization (BehavioralEvent) → feature extraction → baseline modeling → anomaly detection → network risk assessment → risk fusion → policy evaluation → firewall enforcement → API/dashboard presentation.

**Note**: The system is designed for zero cloud dependency with all processing occurring locally. The React dashboard connects to the FastAPI backend via REST and WebSocket for real-time updates.