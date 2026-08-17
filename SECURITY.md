# Security Policy — Sentinel AI Firewall

## 1. Overview & Commitment

Security is the core mission of Sentinel AI Firewall. As a security product operating with administrative privileges on host systems, our codebase, models, and dependencies are held to the highest standards of software integrity, privacy preservation, and defensive resilience.

---

## 2. Supported Versions

Security updates and patches are actively provided for the following versions:

| Version Tier | Status | Support Level |
| :--- | :--- | :--- |
| `0.2.x` (Current Development / Phase 2) | Active | Critical, High, and Medium security patches |
| `0.1.x` (Phase 1 Baseline) | Maintenance | Critical security fixes only |
| `< 0.1.0` | End of Life (EOL) | No security updates provided |

---

## 3. Reporting a Vulnerability

We appreciate the efforts of security researchers and engineers who responsibly disclose vulnerabilities.

### 3.1 Disclosure Process
- **Email**: Report vulnerabilities directly to `security@sentinel-firewall.local` or via GitHub Private Vulnerability Reporting.
- **Encryption**: For sensitive disclosures, please encrypt your communication using our PGP public key (Key ID: `0x7A9B1C3D`, available in project releases).
- **Required Information**:
  1. Detailed description of the vulnerability (e.g., Command Injection, Baseline Poisoning, Denial of Service).
  2. Proof of Concept (PoC) script or step-by-step reproduction instructions.
  3. Affected component(s) (e.g., `backend/app/firewall/validator.py`, `backend/security/baseline.py`).
  4. Potential impact assessment and suggested remediation, if known.

### 3.2 Response Service Level Agreements (SLAs)
- **Initial Acknowledgment**: Within 24 hours of receipt.
- **Triage & Severity Assessment**: Within 48 hours.
- **Fix Delivery & Disclosure Advisory**: Within 14 days (or coordinated disclosure timeline).

---

## 4. Security Architecture & Controls

Sentinel AI Firewall implements rigorous defense-in-depth controls across all system layers:

### 4.1 Principle of Least Privilege & Windows Boundaries
- **Administrator Elevation**: Firewall manipulation (`netsh advfirewall` and PowerShell `New-NetFirewallRule`) requires elevated administrator tokens. Non-privileged user accounts cannot alter or purge firewall rules.
- **Process Isolation**: The background FastAPI service and telemetry collector operate in dedicated processes with restricted IPC channels.

### 4.2 Strict Input Validation & Command Injection Prevention
To eliminate command injection vulnerabilities when executing system-level firewall commands:
- All input strings (rule names, remote IP addresses, ports, protocol names) undergo strict whitelist regex validation before command construction.
- Rule names are restricted to `^[a-zA-Z0-9_\-\. ]{1,128}$`.
- Port parameters are validated strictly within the integer range `0 <= port <= 65535`.
- Shell execution is performed with parameter arrays rather than raw shell concatenation.

```python
# Reference implementation: backend/app/firewall/validator.py
VALID_RULE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-\. ]{1,128}$")

def validate_rule_name(rule_name: str) -> None:
    if not VALID_RULE_NAME_RE.match(rule_name.strip()):
        raise FirewallValidationError(f"Invalid rule name characters: '{rule_name}'")
```

### 4.3 Baseline Poisoning & Adversarial ML Defense
Adversarial attacks aiming to train the adaptive baseline to accept malicious behavior (slow-drip exfiltration or mimicry) are mitigated via multi-tiered safeguards:
1. **Unvalidated Event Protection**: Newly observed behavioral identities (`NEW`) are subjected to observation buffers before metric accumulation.
2. **Statistical Freeze**: If an event generates an anomaly score $\ge 0.7$ or triggers high-risk heuristic flags, online Welford statistical updates are immediately **frozen**.
3. **Quarantine Isolation**: Quarantined records never update baseline metrics.

### 4.4 Cryptographic Process Integrity
- Every executing binary associated with network telemetry is resolved to its disk image.
- Binary hashes are computed using **SHA-256**.
- Windows Authenticode digital signatures and certificate chains are verified via Win32 `WinVerifyTrust` APIs to distinguish legitimate signed software from unauthorized unsigned payloads.

### 4.5 Data Privacy & Zero Telemetry Exfiltration
- **Local-First Architecture**: All telemetry, baseline metrics, machine learning inference, and firewall audit logs remain 100% on the local host.
- No packet payloads, process lists, or network endpoints are transmitted to third-party cloud infrastructure.

---

## 5. Secure Development Lifecycle (SDLC)

To prevent vulnerabilities from entering production:
- **Static Analysis (SAST)**: Automated `ruff` linting, `mypy` strict type checking, and `bandit` security scanning on every pull request.
- **Dependency Auditing**: Continuous dependency vulnerability scanning via GitHub Dependabot and `pip-audit`.
- **Automated Regression Testing**: Comprehensive security test suites testing command injection, baseline tampering, boundary violations, and malformed network packet ingestion.
