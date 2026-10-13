from fastapi.testclient import TestClient
import pytest
from app.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_api_phishing_detection():
    # Test malicious URL
    response = client.post(
        "/api/detect/phishing-url",
        json={"url": "http://192.168.1.105/login/bank-verify.php"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["is_phishing"] is True
    assert data["confidence"] > 0.6
    assert data["alert_generated"] is True
    assert data["alert_id"] is not None


def test_api_event_ingest_and_incident_flow():
    import uuid
    unique_event_id = f"test_evt_api_{uuid.uuid4().hex[:8]}"
    sqli_payload = {
        "event_id": unique_event_id,
        "event_type": "http_request",
        "timestamp": "2026-10-13T12:00:00Z",
        "source_ip": "198.51.100.99",
        "user_id": "admin_api",
        "target": "/api/v1/users",
        "evidence": {
            "method": "POST",
            "body": "user=admin' OR '1'='1'--",
            "uri": "/api/v1/users"
        }
    }
    res = client.post("/api/events/ingest", json=sqli_payload)
    assert res.status_code == 200
    ingest_data = res.json()
    assert ingest_data["status"] == "processed"
    assert ingest_data["generated_alerts_count"] >= 1
    incident_id = ingest_data["incident_id"]
    assert incident_id is not None

    # Retrieve Incident details
    inc_res = client.get(f"/api/incidents/{incident_id}")
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    assert inc_data["incident_id"] == incident_id
    assert inc_data["risk_score"] > 0
    assert len(inc_data["linked_alerts"]) >= 1
    assert "Executive Summary" in inc_data["incident_narrative"]

    # Retrieve Incident Graph
    graph_res = client.get(f"/api/incidents/{incident_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert graph_data["node_count"] >= 2
    assert graph_data["edge_count"] >= 1

    # Submit Analyst Feedback
    fb_payload = {
        "verdict": "true_positive",
        "notes": "Verified SQL injection attack targeting login endpoint.",
        "analyst_id": "analyst_swanandi"
    }
    fb_res = client.post(f"/api/incidents/{incident_id}/feedback", json=fb_payload)
    assert fb_res.status_code == 200
    fb_data = fb_res.json()
    assert fb_data["verdict"] == "true_positive"

    # Trigger Simulated Response Action
    resp_payload = {
        "action_type": "SIMULATE_BLOCK_IP",
        "reason": "Immediate perimeter quarantine of SQLi attacker IP.",
        "analyst_id": "analyst_radhika",
        "parameters": {"ip": "198.51.100.99"}
    }
    action_res = client.post(f"/api/incidents/{incident_id}/respond", json=resp_payload)
    assert action_res.status_code == 200
    action_data = action_res.json()
    assert action_data["simulation_status"] == "SIMULATED_SUCCESS"
    assert "[DRY-RUN]" in action_data["outcome"]
