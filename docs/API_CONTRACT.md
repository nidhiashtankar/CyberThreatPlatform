# API Contract & Schema Specifications

## Overview
This document specifies the shared interface contracts, request/response models, and error behaviors for the **AI Cyber Threat Intelligence & Automated Response Platform**. All schemas are validated at runtime via Pydantic v2.

---

## 1. Team Ownership of Interfaces

| Component / Endpoint | Primary Owner | Module Responsibility |
| :--- | :--- | :--- |
| Shared Schemas & Core Pipeline | Swanandi | `schemas/event.py`, `schemas/alert.py`, `schemas/incident.py` |
| Event Ingestion API | Swanandi | `POST /api/events/ingest`, `GET /api/events` |
| Phishing URL Detection API | Aastha | `POST /api/detect/phishing-url`, Random Forest Model |
| Honeytoken Deception API | Aastha | Controlled decoy trigger handling & secret masking |
| Login Threat Detector | Nidhi | Sliding window authentication monitoring & sequence rules |
| Port-Scan Detector | Radhika | Network connection threshold analysis & deduplication |
| Web-Attack Detector | Swanandi | Signature-based SQLi, XSS, and Path Traversal detection |
| Graph Analysis API | Nidhi | `GET /api/incidents/{id}/graph`, NetworkX entity graph |
| Risk Scoring & Decay Services | Aastha | Deterministic scoring and exponential half-life decay |
| Narrative Generation | Swanandi | Fact-based 7-section chronological reporting |
| Feedback & Response APIs | Radhika | `POST /api/incidents/{id}/feedback`, `POST /api/incidents/{id}/respond` |

---

## 2. Core Data Models

### 2.1 Security Event (`SecurityEvent`)
Represents an incoming raw security event ingested from endpoint sensors, proxies, WAFs, or network flow collectors.

```json
{
  "event_id": "evt_abc123456789",
  "event_type": "http_request",
  "timestamp": "2026-10-13T10:30:00Z",
  "source_ip": "198.51.100.45",
  "user_id": "admin_svc",
  "target": "/api/v1/auth",
  "source_module": "waf_collector",
  "evidence": {
    "method": "POST",
    "uri": "/api/v1/auth",
    "body": "username=admin_svc' OR '1'='1'--",
    "status_code": 401
  },
  "metadata": {}
}
```

### 2.2 Standard Alert (`StandardAlert`)
Every detection module produces a strictly standardized alert:

```json
{
  "alert_id": "alt_web_78a1bc29",
  "event_id": "evt_abc123456789",
  "detector": "web_attack",
  "category": "web_exploitation",
  "severity": "high",
  "confidence": 0.90,
  "source_ip": "198.51.100.45",
  "user_id": "admin_svc",
  "target": "/api/v1/auth",
  "timestamp": "2026-10-13T10:30:00Z",
  "title": "Web Attack Indicator: Sql Injection Signature Matched",
  "evidence": {
    "attack_type": "SQL_INJECTION",
    "signature_matched": "SQLI_OR_1_EQUALS_1",
    "matched_snippet": "OR '1'='1'",
    "source_ip": "198.51.100.45"
  },
  "recommended_action": "Block malicious input pattern at Web Application Firewall (WAF).",
  "incident_id": "inc_f4a902b1c3"
}
```

### 2.3 Incident (`Incident`)
Aggregates correlated alerts into a unified actionable threat record:

```json
{
  "incident_id": "inc_f4a902b1c3",
  "title": "Web Attack Indicator: Sql Injection Signature Matched",
  "summary": "Detected WEB_ATTACK activity: Web Attack Indicator: Sql Injection Signature Matched",
  "status": "open",
  "risk_score": 85.0,
  "risk_tier": "Critical",
  "linked_alerts": [...],
  "alert_ids": ["alt_web_78a1bc29", "alt_login_seq_45b", "alt_decoy_99c"],
  "related_entities": {
    "ips": ["198.51.100.45"],
    "users": ["admin_svc"],
    "targets": ["/api/v1/auth", "cloud-storage-vault"],
    "tokens": ["HONE...921"],
    "urls": []
  },
  "first_seen": "2026-10-13T10:30:00Z",
  "last_seen": "2026-10-13T10:33:00Z",
  "evidence": {},
  "timeline": [...],
  "risk_score_explanation": [
    {"category": "Alert Contribution", "reason": "[WEB_ATTACK] Sql Injection", "points": 22.5},
    {"category": "Critical Threat Bonus", "reason": "Honeytoken / Canary decoy trap activated", "points": 25.0}
  ],
  "incident_narrative": "### 1. Executive Summary & Observations...",
  "analyst_feedback": null,
  "response_actions": []
}
```

---

## 3. Endpoints Specification

### `GET /api/health`
- **Description**: Verifies service status, uptime, and database connectivity.
- **Response**: `200 OK`
```json
{
  "status": "healthy",
  "service": "AI Cyber Threat Intelligence & Automated Response Platform",
  "version": "1.0.0",
  "environment": "production",
  "timestamp": "2026-10-13T11:00:00Z"
}
```

### `POST /api/events/ingest`
- **Description**: Ingests security event, triggers detectors, correlates alerts, and updates incidents.
- **Idempotency**: Submitting identical `event_id` returns `duplicate_acknowledged` without duplicating alerts.
- **Request**: `SecurityEvent` payload
- **Response**: `200 OK` (`EventIngestResponse`)

### `POST /api/detect/phishing-url`
- **Description**: Dedicated endpoint to classify a URL using the Random Forest model and lexical heuristics.
- **Request**: `{"url": "http://192.168.1.105/login/bank-verify.php"}`
- **Response**: `200 OK`
```json
{
  "valid": true,
  "url": "http://192.168.1.105/login/bank-verify.php",
  "is_phishing": true,
  "confidence": 0.90,
  "features": {
    "has_ip_in_url": 1,
    "keyword_count": 2,
    "entropy": 3.4
  },
  "evidence": {
    "rule_flags": ["Host is a raw numerical IP address"]
  },
  "alert_generated": true,
  "alert_id": "alt_phish_12ab34cd"
}
```

### `GET /api/alerts`
- **Query Parameters**: `severity`, `detector`, `category`, `source_ip`, `limit`, `offset`
- **Response**: Array of `StandardAlert`

### `GET /api/incidents`
- **Query Parameters**: `status`, `risk_tier`, `limit`, `offset`
- **Response**: Array of `Incident`

### `GET /api/incidents/{incident_id}`
- **Query Parameters**: `apply_decay` (boolean)
- **Response**: Full `Incident` object including narrative, timeline, and score explanation.

### `GET /api/incidents/{incident_id}/graph`
- **Response**: `IncidentGraphResponse`
```json
{
  "incident_id": "inc_f4a902b1c3",
  "nodes": [
    {"id": "ip_198.51.100.45", "label": "198.51.100.45", "type": "ip", "role": "attacker_origin"},
    {"id": "user_admin_svc", "label": "admin_svc", "type": "user", "role": "targeted_account"}
  ],
  "edges": [
    {"source": "ip_198.51.100.45", "target": "user_admin_svc", "relationship": "AUTHENTICATED_AS", "evidence": "Activity observed targeting admin_svc"}
  ],
  "node_count": 6,
  "edge_count": 5,
  "key_hubs": ["198.51.100.45 (degree=0.80)"]
}
```

### `POST /api/incidents/{incident_id}/feedback`
- **Request**:
```json
{
  "verdict": "true_positive",
  "notes": "Verified SQL injection attempt and brute force login activity.",
  "analyst_id": "analyst_swanandi"
}
```
- **Response**: `200 OK` (`FeedbackRecord`)

### `POST /api/incidents/{incident_id}/respond`
- **Request**:
```json
{
  "action_type": "SIMULATE_BLOCK_IP",
  "reason": "Block attacker IP at perimeter.",
  "analyst_id": "analyst_radhika",
  "parameters": {"ip": "198.51.100.45"}
}
```
- **Response**: `200 OK` (`ResponseActionRecord`)
