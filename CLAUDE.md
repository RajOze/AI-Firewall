# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Backend (FastAPI)
- **Start backend service** (requires Administrator privileges for firewall access):
  ```powershell
  .\.venv\Scripts\Activate.ps1
  uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
  ```
- **API base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc Documentation**: `http://127.0.0.1:8000/redoc`

### Frontend (React + Vite)
- **Start frontend development server**:
  ```powershell
  cd frontend
  npm run dev
  ```
- **Vite Dev Server**: `http://localhost:5173`

### Dependency Installation
- **Initial setup** (run once after cloning):
  ```powershell
  # Clone the repository
  git clone https://github.com/RajOze/AI-Firewall.git
  cd AI-Firewall

  # Create and activate Python virtual environment
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1

  # Install core and development dependencies
  pip install --upgrade pip setuptools wheel
  pip install -r requirements.txt -r requirements-dev.txt

  # Install frontend dependencies
  cd frontend
  npm install
  cd ..
  ```

### Code Quality & Linting
- **Python formatting and linting** (using Ruff):
  ```powershell
  # Format code
  ruff format .

  # Check for lint errors
  ruff check .

  # Fix auto-fixable lint issues
  ruff check --fix .
  ```
- **Frontend linting and TypeScript validation**:
  ```powershell
  cd frontend
  npm run lint
  npm run build # Validates TypeScript types and bundle generation
  ```

### Testing
- **Run all unit tests with coverage**:
  ```powershell
  pytest --cov=backend --cov=network tests/unit
  ```
- **Run specific test modules**:
  ```powershell
  pytest tests/unit/security/test_baseline.py -v
  pytest tests/unit/firewall/test_validator.py -v
  ```

## High-Level Architecture

### System Overview
Sentinel AI Firewall follows a layered architecture that decouples telemetry capture from analytics and policy enforcement through asynchronous pipelines:

1. **Host Telemetry & Ingestion Layer**: Captures Windows ETW/Netstat and process lifecycle events into an async telemetry ring buffer.
2. **Feature & Context Normalization Layer**: Normalizes events, enriches with process integrity data (SHA-256, Authenticode), and extracts 26-dimensional behavioral features.
3. **Real-Time AI & Risk Analytics Layer**:
   - Online Welford accumulators for O(1) statistical baselining
   - Isolation Forest anomaly detection
   - Specialized network risk evaluation
   - Deterministic risk fusion engine (mathematically bounded 0.0-1.0 scoring)
4. **Policy & Enforcement Layer**: Evaluates risk against thresholds and interfaces with Windows Firewall provider for rule enforcement.
5. **Control Plane & Presentation Layer**: FastAPI REST API serves the React 18 + TypeScript management console.

### Key Components
- **Backend** (`backend/`):
  - `app/`: FastAPI routers, models, services, dependencies
  - `security/`: AI & risk pipeline (baseline, features, anomaly, network_risk, risk_fusion)
  - `firewall/`: Windows Firewall rule providers and validators
  - `telemetry/`: Ingestion worker and repository

- **Frontend** (`frontend/src/`):
  - `components/`: Reusable UI widgets and telemetry charts
  - `pages/`: Dashboard, Firewall, Alerts, AI Assistant views
  - `services/`: REST API clients and real-time hooks
  - `types/`: TypeScript interfaces

- **Security Analytics** (`backend/security/`):
  - `baseline.py`: Welford accumulators and behavioral baseline engine
  - `features.py`: 26-dimensional FeatureExtractor
  - `anomaly.py`: Isolation Forest and statistical z-score model
  - `network_risk.py`: Specialized network threat evaluator
  - `risk_fusion.py`: Deterministic multi-signal risk fusion
  - `scoring.py`: Threat score and categorization engine

### Development Workflows
- **Adding new feature metrics**: Modify `backend/security/features.py`, update `FEATURE_VERSION`, and adjust unit tests.
- **Creating new security models**: Inherit from `BaseSecurityModel` (`backend/security/base_model.py`).
- **Adding REST API endpoints**: Create/modify routers in `backend/app/api/`, define schemas in `backend/app/schemas/`, and mount in `backend/app/main.py`.

### Git Conventions
- Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages (e.g., `feat: add automated quarantine cooldown timer`).
- PR checklist includes passing Ruff checks, TypeScript builds, ≥85% test coverage, and documentation updates.

## Common Troubleshooting
- **Permission errors**: Launch PowerShell terminal using "Run as Administrator" for firewall/socket API access.
- **DLL load errors**: Run `python .venv/Scripts/pywin32_postinstall.py -install` for missing pywin32 binaries.
- **CORS errors**: Ensure frontend runs on port 5173 or add port to `origins` in `backend/app/main.py`.