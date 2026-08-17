# Changelog

All notable changes to **Sentinel AI Firewall** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Automated background baseline snapshot persistence to encrypted local storage.
- Autonomous active firewall quarantine enforcement for `CRITICAL` risk scores.
- Dynamic rule cooldown timer to automatically unblock expired transient threat connections.
- Native Windows Filtering Platform (WFP) callout driver for sub-microsecond packet drops.

---

## [0.2.0-beta] - 2026-08-15

### Added
- **Behavioral Baseline Engine (`BehavioralBaselineEngine`)**: Single-pass online running mean ($\bar{x}$) and variance ($\sigma^2$) tracking per `behavior_identity_key` using Welford's algorithm ($O(1)$ time and memory).
- **Baseline Poisoning Defense**: Automatic statistical freeze when incoming observations trigger an anomaly score $\ge 0.7$ or are classified as `SUSPICIOUS`.
- **26-Dimensional Feature Extractor (`FeatureExtractor`)**: Transforms raw socket and process events into normalized numerical feature vectors for statistical and ML models.
- **Isolation Forest Anomaly Model (`IsolationForestAnomalyModel`)**: Lightweight scikit-learn tree ensemble model with feature versioning and offline joblib persistence.
- **Specialized Network Risk Model (`NetworkRiskModel`)**: Evaluation of high-risk C2 ports (22, 23, 135, 139, 445, 3389, 4444, 6667, 8080), destination diversity, and traffic symmetry.
- **Deterministic Risk Fusion Engine (`RiskFusionEngine`)**: Weighted deterministic threat synthesis ($40\% \text{ Anomaly} + 35\% \text{ Process} + 25\% \text{ Network}$) outputting bounded threat scores, risk categories, and explainable reason codes.
- **Observability REST Endpoints**: Added `GET /events/stats` and `GET /events/baseline` to inspect telemetry throughput and in-memory behavioral baselines.
- **Explainable AI Payloads**: Structured reason codes with empirical measurements attached to all telemetry and anomaly alerts.

### Changed
- Refactored `TelemetryService` to utilize asynchronous background workers with non-blocking bounded ring buffer ingestion.
- Upgraded process enrichment to include SHA-256 file hashing, Authenticode digital signature verification, and LRU result caching.
- Enhanced React dashboard to display live baseline maturity states (`NEW`, `OBSERVING`, `KNOWN_BENIGN`) and confidence levels.

### Fixed
- Fixed command injection vulnerability in `WindowsFirewallProvider` by enforcing strict whitelist regex validation on rule names and port numbers.
- Resolved memory leak caused by un-evicted ephemeral UDP socket handles during sustained network load.
- Corrected race condition in Windows Firewall rule querying by ensuring idempotent presence checks.

---

## [0.1.0-alpha] - 2026-02-10

### Added
- Initial project scaffolding with FastAPI backend and React 18 + Vite frontend.
- Native Windows socket discovery and active TCP/UDP connection polling via `pywin32` and `psutil`.
- Windows Firewall provider with PowerShell and `netsh advfirewall` execution bridges.
- REST API endpoints for `/analyze` and `/firewall/rules`.
- Glassmorphic web management console with live KPI metric cards, event table, and rule manager.
- Unit and integration test suite with `pytest` and `pytest-cov`.
