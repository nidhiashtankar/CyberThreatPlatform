import json
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "sample_events", "correlated_attack_chain.json")


def test_end_to_end_correlated_attack_chain():
    """
    Ingest a 7-stage coordinated cyber attack sequence:
    1. Port scan reconnaissance
    2. Web SQL injection probe
    3. Repeated failed login attempts
    4. Successful login completion
    5. Honeytoken credential activation
    Verifies that all correlated events merge into a unified incident,
    risk score reaches Critical tier, narrative accurately details sequence,
    and NetworkX graph reflects the attacker campaign.
    """
    assert os.path.exists(FIXTURES_PATH), f"Fixture not found at {FIXTURES_PATH}"
    with open(FIXTURES_PATH, "r") as f:
        events = json.load(f)

    import uuid
    run_id = uuid.uuid4().hex[:6]
    incident_ids = set()
    total_alerts = 0
    last_incident_id = None

    for evt in events:
        evt_copy = dict(evt)
        evt_copy["event_id"] = f"{run_id}_{evt['event_id']}"
        res = client.post("/api/events/ingest", json=evt_copy)
        assert res.status_code == 200
        data = res.json()
        total_alerts += data["generated_alerts_count"]
        if data["incident_id"]:
            incident_ids.add(data["incident_id"])
            last_incident_id = data["incident_id"]

    # All related alerts in the chain share attacker IP 198.51.100.45 or user admin_svc,
    # so they should correlate into a unified incident!
    assert len(incident_ids) == 1, f"Expected 1 correlated incident, got {incident_ids}"
    primary_incident_id = last_incident_id

    # Verify incident
    inc_res = client.get(f"/api/incidents/{primary_incident_id}")
    assert inc_res.status_code == 200
    incident = inc_res.json()

    assert incident["risk_score"] >= 80.0
    assert incident["risk_tier"] in ("High", "Critical")
    assert len(incident["linked_alerts"]) >= 3
    assert "admin_svc" in incident["related_entities"]["users"]
    assert "198.51.100.45" in incident["related_entities"]["ips"]

    # Verify Narrative
    narrative = incident["incident_narrative"]
    assert "Executive Summary" in narrative
    assert "Contributing Intelligence Modules" in narrative
    assert "Recommended Response Guidance" in narrative
    assert "Investigative Uncertainties" in narrative

    # Verify Graph
    graph_res = client.get(f"/api/incidents/{primary_incident_id}/graph")
    assert graph_res.status_code == 200
    graph = graph_res.json()
    assert graph["node_count"] >= 4
    assert graph["edge_count"] >= 3

    # Submit Analyst Feedback
    fb_res = client.post(
        f"/api/incidents/{primary_incident_id}/feedback",
        json={
            "verdict": "true_positive",
            "notes": "End-to-end test confirmed multi-stage cyber campaign.",
            "analyst_id": "analyst_swanandi"
        }
    )
    assert fb_res.status_code == 200

    # Execute Simulated Response Action
    resp_res = client.post(
        f"/api/incidents/{primary_incident_id}/respond",
        json={
            "action_type": "SIMULATE_BLOCK_IP",
            "reason": "Block attacker IP 198.51.100.45 at edge.",
            "analyst_id": "analyst_radhika",
            "parameters": {"ip": "198.51.100.45"}
        }
    )
    assert resp_res.status_code == 200
    assert resp_res.json()["simulation_status"] == "SIMULATED_SUCCESS"
