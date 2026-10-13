# AI Cyber Threat Intelligence & Automated Response Platform

An integrated, lightweight Security Operations Center (SOC) platform designed to detect suspicious activity, correlate multi-vector security events, track entity relationships using NetworkX graph intelligence, calculate deterministic risk scores with decay modeling, synthesize explainable incident narratives, and record audited simulated responses.

Developed as a four-member academic prototype prioritizing correctness, explainability, architectural integration, and live demonstration reliability.

---

## 1. Project Overview & Problem Statement

Modern security operations are plagued by alert fatigue and fragmented threat detection. Traditional tools generate isolated alerts, leaving human analysts to manually piece together multi-stage cyberattacks. 

When attackers rotate egress IP addresses or employ deception-evasion techniques, basic IP-based correlation systems fail. This platform demonstrates how a unified, lightweight pipeline can:
1. Ingest raw events and validate them with strict Pydantic schemas.
2. Detect threats across 5 distinct vectors (Phishing URLs, Brute-Force Logins, Port Scans, Web Exploits, and Honeytoken Deceptions).
3. Connect related activity—including across IP rotations—using NetworkX entity graph analysis.
4. Prioritize incidents using a bounded ($0$ to $100$), explainable risk function with exponential half-life decay.
5. Generate fact-based, chronological incident narratives without LLM hallucinations.
6. Provide security analysts with an information-dense, modern **Light-Theme Dashboard** to submit feedback and trigger audited dry-run containment actions.

---

## 2. Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2.0
- **Database**: PostgreSQL (Docker containerized) with SQLite fallback for rapid local execution
- **Frontend**: React 18, Vite, Tailwind CSS (Strict Light Theme), Axios, Lucide Icons, Chart.js
- **Intelligence & Analytics**: NetworkX (multi-graph relationship analysis), scikit-learn (Random Forest phishing classification), deterministic state machines
- **Deployment & Testing**: Docker, Docker Compose, Pytest

---

## 3. Four-Member Implementation Ownership

| Member | Primary Modules & Responsibilities |
| :--- | :--- |
| **Aastha** | Phishing URL Detection (Random Forest + Lexical features), Honeytoken / Deception Detection, Risk Scoring Function, Risk Decay Model & Tests |
| **Nidhi** | Login Threat Detection (sliding window + sequences), Alert Correlation Engine, NetworkX Graph Analysis, IP-Rotation Evaluation |
| **Radhika** | Port-Scan Detection (distinct ports recon), React SOC Dashboard, Incident Visualization, Analyst Feedback & Simulated Response Controls, Docker Compose |
| **Swanandi** | Web-Attack Detection (SQLi, XSS, Path Traversal), FastAPI Architecture & Routers, Shared Schemas & API Contract, Database Persistence, Incident Narrative Synthesizer, Integration Test Suite |

---

## 4. System Architecture & Event Flow

```
Security Event / URL Submission
  → Pydantic Schema Validation
  → Multi-Vector Detection Modules
  → Standardized Alert Production
  → Correlation & Incident Aggregation
  → NetworkX Relationship Graph
  → Deterministic Risk Score & Tier
  → Exponential Risk Decay (with Protection Floor)
  → 7-Section Factual Narrative
  → PostgreSQL / SQLite Storage
  → React Light-Theme Dashboard
  → Analyst Feedback & Audited Dry-Run Response
```

---

## 5. Prerequisites & Environment Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Docker and Docker Compose (optional for containerized deployment)

### Local Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/swanandiz-07/AI-CYBER-THREAT-PLATFORM.git
   cd AI-CYBER-THREAT-PLATFORM
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```

3. **Backend Setup**:
   ```bash
   # Install backend dependencies
   pip install -r backend/requirements.txt

   # Start FastAPI server
   cd backend
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
   The backend API will be live at `http://localhost:8000`  
   Interactive OpenAPI Swagger docs: `http://localhost:8000/docs`

4. **Frontend Setup**:
   ```bash
   # Open a new terminal in the frontend directory
   cd frontend
   npm install
   npm run dev
   ```
   The React dashboard will be live at `http://localhost:5173`

---

## 6. Docker & Containerized Execution

To run the complete platform using Docker Compose (PostgreSQL, FastAPI Backend, and React Frontend):

```bash
# Build and start all services in the background
docker compose up --build -d

# Verify running containers and health checks
docker compose ps

# View backend logs in real time
docker compose logs -f backend

# Shutdown platform (preserves PostgreSQL data volume)
docker compose down
```

- **Frontend Dashboard**: `http://localhost:3000`
- **Backend API**: `http://localhost:8000`
- **Swagger Documentation**: `http://localhost:8000/docs`
- **Health Check Endpoint**: `http://localhost:8000/api/health`

---

## 7. How to Run Tests

The platform includes 12 automated unit, detector, risk, correlation, and end-to-end integration tests:

```bash
# From the project root
python -m pytest -v
```

All 12 tests execute in under 3 seconds:
- `test_detectors.py`: Verifies all 5 threat detectors (positive, negative, and edge cases).
- `test_risk.py`: Verifies bounded risk scoring and half-life decay with honeytoken floor preservation.
- `test_correlation.py`: Verifies incident grouping and the IP-rotation evasion scenario.
- `test_api.py`: Tests API health, ingestion, feedback, and simulated response.
- `test_pipeline.py`: Executes the full 7-stage coordinated cyber campaign.

---

## 8. Step-by-Step Live Demonstration Script

Follow this script for a reliable demonstration during team reviews or evaluations:

1. **Open the Dashboard**: Navigate to `http://localhost:5173` (or `http://localhost:3000` in Docker). Notice the clean, professional light theme, summary metric cards, and risk distribution breakdown.
2. **Access Event Simulator**: Click on **Event Simulator** in the top navigation (`/simulator`).
3. **Execute Multi-Stage Attack Chain**:
   - Under the **Multi-Stage Campaign** tab, click **Launch Correlated Attack Chain**.
   - Notice the live JSON response returning the created incident ID (e.g., `inc_...`).
   - Click **Inspect Details**.
4. **Inspect Incident Details**:
   - **Risk Gauge**: View the calculated score (Critical tier, $\ge 85$).
   - **NetworkX Graph**: Interact with the entity graph visualizer showing the attacker IP, targeted account, victim URI, and honeytoken trap.
   - **Incident Narrative**: Review the 7-section factual report synthesizing what occurred in chronological order.
   - **Simulate Risk Decay**: Click the **Apply Decay** toggle to demonstrate exponential time decay while verifying that the honeytoken preservation floor keeps the incident prioritized.
5. **Submit Analyst Feedback**:
   - Select **True Positive**, type an analyst note (`"Confirmed multi-stage brute force and honeytoken activation"`), and click **Submit Analyst Feedback**.
   - Observe the feedback saved to the database and displayed on the incident card.
6. **Trigger Simulated Response**:
   - Select **Simulate Blocking Attacker Source IP**, enter a reason, and click **Initiate Simulated Action** → **Confirm Dry-Run**.
   - Observe the dry-run outcome recorded in the **Response Audit History** without modifying real infrastructure.
7. **Test Individual Detectors**:
   - Return to `/simulator` and test the **Phishing URL Detector** with `http://192.168.1.105/login/bank-verify.php` to observe the Random Forest feature classification and entropy score.

---

## 9. Known Limitations & Responsible Operations

- **Demonstration Scope**: All response actions (`SIMULATE_BLOCK_IP`, `SIMULATE_DISABLE_ACCOUNT`) are safe dry-runs. The platform does not alter external firewalls or production Active Directory servers.
- **Controlled Deception**: Honeytokens are synthetic canary strings created strictly for demonstration purposes. No real secrets or production credentials are used.
- **Network Scanning**: The port-scan detector processes synthetic connection event records. It does not perform active scans of external IP ranges.

---

## 10. Acceptance Checklist

- [x] Repository structure matches specified academic layout.
- [x] Shared Pydantic contracts and API specifications documented (`docs/API_CONTRACT.md`).
- [x] All 5 detection modules implemented and independently tested.
- [x] Alert correlation and NetworkX graph intelligence functional.
- [x] IP-rotation evasion scenario verified.
- [x] Deterministic risk scoring and exponential decay implemented.
- [x] Factual 7-section incident narrative synthesizer complete.
- [x] Modern, clean **Light-Theme SOC Dashboard** built with React & Tailwind.
- [x] Analyst feedback and simulated response actions persisted with audit trail.
- [x] Dockerfiles and Docker Compose configuration tested.
- [x] All 12 automated test cases passing.