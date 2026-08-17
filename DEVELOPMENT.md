# Sentinel AI Firewall — Developer Guide

## 1. Development Environment Setup

### 1.1 Prerequisites
- **OS**: Windows 10/11 or Windows Server 2019/2022 (x86_64).
- **Python**: Version 3.11.0 or higher.
- **Node.js**: Version 18.0.0 or higher (LTS recommended) with npm 9.0+.
- **PowerShell**: Version 5.1 or PowerShell 7+ with script execution enabled:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```
- **Git**: Configured with LF/CRLF auto-handling.

---

### 1.2 Initial Repository Initialization

```powershell
# Clone the repository
git clone https://github.com/RajOze/AI-Firewall.git
cd AI-Firewall

# Create and activate a Python virtual environment
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

---

## 2. Running the Development Stack

To facilitate rapid local iteration, the backend and frontend can be started in parallel terminals.

### 2.1 Starting the FastAPI Backend

```powershell
# In terminal 1 (Elevated as Administrator for live firewall inspection):
.\.venv\Scripts\Activate.ps1
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **API Base URL**: `http://127.0.0.1:8000`
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc UI**: `http://127.0.0.1:8000/redoc`

### 2.2 Starting the React Frontend

```powershell
# In terminal 2:
cd frontend
npm run dev
```
- **Vite Dev Server**: `http://localhost:5173`

---

## 3. Codebase Architecture & Structure Tour

```text
AI-Firewall/
├── backend/
│   ├── app/
│   │   ├── api/              # FastAPI route handlers (/analyze, /events, /firewall)
│   │   ├── core/             # Application configuration, logging & lifespan
│   │   ├── dependencies/     # Dependency injection providers (telemetry, firewall)
│   │   ├── firewall/         # Windows Firewall provider, validator, service
│   │   ├── models/           # Request/Response data models
│   │   ├── schemas/          # Pydantic schemas (events, telemetry, rules)
│   │   └── telemetry/        # Telemetry ingestion worker and repository
│   └── security/             # AI Analytics, Baseline & Risk Engine
│       ├── base_model.py     # BaseSecurityModel abstract base class
│       ├── baseline.py       # BehavioralBaselineEngine & Welford accumulators
│       ├── features.py       # FeatureExtractor (26 canonical metrics)
│       ├── anomaly.py        # AnomalyDetectionEngine & Isolation Forest
│       ├── network_risk.py   # Specialized NetworkRiskModel
│       └── risk_fusion.py    # Multi-signal RiskFusionEngine
├── frontend/
│   ├── src/
│   │   ├── components/       # UI components (KPI cards, charts, rule modals)
│   │   ├── pages/            # View pages (Dashboard, Firewall, Alerts, Assistant)
│   │   ├── services/         # Axios/Fetch API client integrations
│   │   └── types/            # TypeScript interfaces
└── tests/
    ├── unit/                 # Fast unit tests for all core modules
    ├── integration/          # API & provider integration tests
    └── security/             # Input sanitization & poisoning tests
```

---

## 4. Engineering Workflows & Extending the System

### 4.1 Adding a New Feature Metric to `FeatureExtractor`
1. Navigate to `backend/security/features.py`.
2. Define the new metric name in `FEATURE_NAMES` or `BehavioralFeatures`.
3. Increment `FEATURE_VERSION` (e.g. from `"1.0"` to `"1.1"`).
4. Implement numerical extraction logic in `FeatureExtractor.extract_vector()`.
5. Ensure default neutral imputation is handled when data is absent.
6. Update corresponding unit tests in `tests/unit/security/test_features.py`.

### 4.2 Creating a New Security Model
All machine learning and heuristic models must inherit from `BaseSecurityModel`:

```python
# backend/security/base_model.py
from backend.security.base_model import BaseSecurityModel, ModelOutput

class CustomHeuristicModel(BaseSecurityModel):
    def __init__(self) -> None:
        super().__init__(
            model_name="custom_heuristic",
            model_version="0.1.0",
            feature_version="1.0",
        )

    def fit(self, X, y=None):
        return self

    def predict(self, X):
        # Return binary classifications
        ...

    def score(self, X) -> list[ModelOutput]:
        # Return standardized ModelOutput dataclasses with reason codes
        ...
```

### 4.3 Adding a New REST API Endpoint
1. Create or open the relevant router in `backend/app/api/`.
2. Define Pydantic request and response schemas in `backend/app/schemas/`.
3. Use dependency injection (`Depends(...)`) to access core singletons.
4. Mount the router in `backend/app/main.py`.

---

## 5. Code Quality, Linting & Testing Standards

### 5.1 Python Code Style (Ruff & Mypy)
We enforce strict formatting and linting via **Ruff**:

```powershell
# Format code
ruff format .

# Check for lint errors
ruff check .

# Fix auto-fixable lint issues
ruff check --fix .
```

### 5.2 Frontend Code Quality (ESLint & TypeScript)
```powershell
cd frontend
npm run lint
npm run build # Validates TypeScript types and bundle generation
```

### 5.3 Executing Automated Test Suites
```powershell
# Run all unit tests with coverage
pytest --cov=backend --cov=network tests/unit

# Run specific test modules
pytest tests/unit/security/test_baseline.py -v
pytest tests/unit/firewall/test_validator.py -v
```

---

## 6. Git Conventions & Pull Request Workflow

### 6.1 Conventional Commit Format
All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat: add automated quarantine cooldown timer`
- `fix: resolve port validation boundary check in firewall validator`
- `docs: update AI architecture mathematical equations`
- `test: add adversarial baseline poisoning unit tests`
- `refactor: optimize Welford accumulator calculation loop`

### 6.2 PR Checklist
- [ ] Code passes `ruff check .` and `ruff format --check .` with 0 issues.
- [ ] TypeScript builds cleanly with `npm run build`.
- [ ] All new logic is covered by unit tests ($\ge 85\%$ coverage).
- [ ] No hardcoded paths or plain credentials.
- [ ] Documentation updated to reflect schema or API modifications.

---

## 7. Troubleshooting Common Local Issues

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| `PermissionError: [WinError 5] Access is denied` | Firewall or socket APIs require elevated rights. | Launch PowerShell terminal using **Run as Administrator**. |
| `ImportError: DLL load failed while importing win32api` | Missing or unlinked `pywin32` system binaries. | Run `python .venv/Scripts/pywin32_postinstall.py -install` in your venv. |
| `CORS Error: Access to XMLHttpRequest blocked` | Frontend port mismatch with allowed origins. | Ensure frontend is running on port 5173 or add your port to `origins` in `backend/app/main.py`. |
