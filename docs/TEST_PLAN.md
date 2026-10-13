# Comprehensive Test Plan & Verification Results

## 1. Test Strategy Overview
The testing framework uses deterministic synthetic fixtures stored in `data/sample_events/` and pytest integration suites. All tests execute independently without relying on live external networks, uncontrolled internet endpoints, or real attacks.

---

## 2. Test Execution Matrix

| Test Suite | Module Under Test | Owner | Status | Details |
| :--- | :--- | :--- | :--- | :--- |
| `test_detectors.py` | Phishing Detector | Aastha | **PASSED** | Benign URLs vs Malicious URLs; IP in URL, entropy, keywords, RF classification. |
| `test_detectors.py` | Login Threat Detector | Nidhi | **PASSED** | Sliding window brute force; failure burst vs 3 failures followed by success. |
| `test_detectors.py` | Port-Scan Detector | Radhika | **PASSED** | Connection burst over 12 distinct ports; deduplication within window. |
| `test_detectors.py` | Web-Attack Detector | Swanandi | **PASSED** | SQL injection, XSS, Path traversal signatures; evidence sanitization. |
| `test_detectors.py` | Honeytoken Detector | Aastha | **PASSED** | Canary access trigger; secret masking verified (`...` format). |
| `test_correlation.py`| Alert Correlator | Nidhi | **PASSED** | Aggregation of related alerts; isolation of unrelated alerts. |
| `test_correlation.py`| IP Rotation Scenario | Nidhi | **PASSED** | Rotated IP linked via common target user and honeytoken; NetworkX graph verified. |
| `test_risk.py` | Risk Scoring Function | Aastha | **PASSED** | 0-100 bounds; severity weights; multi-stage bonuses; diminishing returns. |
| `test_risk.py` | Risk Decay Model | Aastha | **PASSED** | 24h exponential decay; critical evidence floor preservation verified. |
| `test_api.py` | Health Check | Swanandi | **PASSED** | `GET /api/health` operational response. |
| `test_api.py` | Phishing Detection API | Aastha | **PASSED** | `POST /api/detect/phishing-url` feature breakdown and alert creation. |
| `test_api.py` | Event Ingestion & Flow | Swanandi | **PASSED** | Ingest → Alert → Incident → Graph → Feedback → Simulated Response. |
| `test_pipeline.py` | Multi-Stage Campaign | Swanandi | **PASSED** | 7-stage attack chain ingestion; unified incident; Critical risk tier; narrative. |

---

## 3. Detailed Scenario Results

### 3.1 Scenario 1: Phishing URL Detection
- **Input**: `http://192.168.1.105/login/bank-verify.php`
- **Expected Outcome**: `is_phishing: true`, `confidence >= 0.70`, `rule_flags` includes `"Host is a raw numerical IP address"`.
- **Actual Result**: `is_phishing: true`, `confidence: 0.90`. Generated StandardAlert with severity `HIGH`.

### 3.2 Scenario 2: Login Threat Detection (Credential Stuffing Sequence)
- **Input**: 3 failed login attempts from `198.51.100.10` targeting user `alice`, followed by 1 successful login.
- **Expected Outcome**: Trigger `SUSPICIOUS_LOGIN_SEQUENCE` alert with category `credential_access`.
- **Actual Result**: Alert generated with severity `HIGH`, confidence `0.88`, evidence recording 3 prior failures.

### 3.3 Scenario 3: Port-Scan Reconnaissance
- **Input**: 12 synthetic TCP connections from `203.0.113.5` to distinct ports (21 through 32) within 60s.
- **Expected Outcome**: Port scan alert generated with distinct ports count >= 10; subsequent packets suppressed.
- **Actual Result**: StandardAlert generated with category `reconnaissance`, distinct ports count 12, severity `MEDIUM`.

### 3.4 Scenario 4: Web Application Exploits
- **Input 1**: `GET /api/items?id=1 UNION SELECT password FROM users--`
- **Input 2**: `POST /feedback` with `<script>alert('xss')</script>`
- **Expected Outcome**: SQL injection and XSS alerts generated; evidence HTML-escaped.
- **Actual Result**: `SQLI_UNION_SELECT` and `XSS_SCRIPT_TAG` matched. Payloads sanitized safely.

### 3.5 Scenario 5: Honeytoken Deception
- **Input**: API access referencing `HONEYTOKEN_AWS_DEV_KEY_9921`.
- **Expected Outcome**: Alert with severity `CRITICAL`, confidence `0.98`. Token masked in output.
- **Actual Result**: Alert generated. `masked_honeytoken` output: `"HONE...921"`. Secret token protected.

### 3.6 Scenario 6: IP-Rotation Evaluation (Baseline vs Graph-Assisted)
- **Experiment Setup**:
  - Phase 1: Attacker IP `198.51.100.45` targets user `admin_svc`.
  - Phase 2: Attacker rotates to IP `203.0.113.88` targeting same user and honeytoken decoy.
- **Baseline Correlation (IP Only)**: Fails to correlate Phase 1 and Phase 2; produces 2 disconnected incidents (missed multi-stage campaign).
- **Graph-Assisted Correlation**: NetworkX graph links `198.51.100.45` → `admin_svc` → `203.0.113.88` via shared user and token edges. Both phases correlate into a unified incident with Critical risk tier.
- **Accuracy Improvement**: 100% campaign continuity maintained across egress IP rotation.

### 3.7 Scenario 7: Risk Decay Preservation
- **Input**: Honeytoken alert with elapsed time of 48 hours (half-life = 24h).
- **Expected Outcome**: Raw decayed score drops, but preservation floor ensures risk score remains $\ge 40.0$.
- **Actual Result**: Decayed score maintained at 44.9; preservation note added to explanation breakdown. Raw evidence preserved intact in database.

---

## 4. How to Execute Tests

```bash
# From workspace root
python -m pytest -v
```
All 12 test cases execute synchronously in under 3 seconds.
