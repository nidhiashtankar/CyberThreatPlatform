import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base
from app.db.models import AlertModel, IncidentModel, EventModel
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.services.correlation import correlator
from app.services.graph_analysis import graph_builder

# Setup in-memory SQLite database for testing correlation
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_correlation_and_ip_rotation(db_session):
    now = datetime.now(timezone.utc)

    # 1. Alert 1 from Initial IP 198.51.100.45 targeting user 'admin_svc'
    evt1 = EventModel(id="evt_rot_1", event_type="login_attempt", timestamp=now, source_ip="198.51.100.45", user_id="admin_svc")
    db_session.add(evt1)
    db_session.commit()

    a1 = StandardAlert(
        alert_id="alt_rot_1",
        event_id="evt_rot_1",
        detector=AlertDetector.LOGIN,
        category=AlertCategory.CREDENTIAL_ACCESS,
        severity=AlertSeverity.HIGH,
        confidence=0.88,
        source_ip="198.51.100.45",
        user_id="admin_svc",
        target="internal_portal",
        timestamp=now,
        title="Brute Force Sequence Detected",
        evidence={"user": "admin_svc"},
        recommended_action="Investigate IP"
    )
    a1_db = AlertModel(
        id=a1.alert_id,
        event_id=a1.event_id,
        detector=a1.detector,
        category=a1.category,
        severity=a1.severity,
        confidence=a1.confidence,
        source_ip=a1.source_ip,
        user_id=a1.user_id,
        target=a1.target,
        timestamp=a1.timestamp,
        title=a1.title,
        evidence=a1.evidence,
        recommended_action=a1.recommended_action
    )
    db_session.add(a1_db)
    db_session.commit()

    inc1 = correlator.correlate_alert(db_session, a1)
    assert inc1 is not None
    assert "198.51.100.45" in inc1.related_entities["ips"]
    assert "admin_svc" in inc1.related_entities["users"]

    # 2. Alert 2: Attacker rotated IP to 203.0.113.88, targeting the SAME user 'admin_svc' and honeytoken
    evt2 = EventModel(id="evt_rot_2", event_type="honeytoken_access", timestamp=now, source_ip="203.0.113.88", user_id="admin_svc")
    db_session.add(evt2)
    db_session.commit()

    a2 = StandardAlert(
        alert_id="alt_rot_2",
        event_id="evt_rot_2",
        detector=AlertDetector.HONEYTOKEN,
        category=AlertCategory.DECEPTION,
        severity=AlertSeverity.CRITICAL,
        confidence=0.98,
        source_ip="203.0.113.88",
        user_id="admin_svc",
        target="canary_trap",
        timestamp=now,
        title="Canary Token Triggered",
        evidence={"masked_honeytoken": "HONE...921"},
        recommended_action="Revoke"
    )
    a2_db = AlertModel(
        id=a2.alert_id,
        event_id=a2.event_id,
        detector=a2.detector,
        category=a2.category,
        severity=a2.severity,
        confidence=a2.confidence,
        source_ip=a2.source_ip,
        user_id=a2.user_id,
        target=a2.target,
        timestamp=a2.timestamp,
        title=a2.title,
        evidence=a2.evidence,
        recommended_action=a2.recommended_action
    )
    db_session.add(a2_db)
    db_session.commit()

    # Correlate second alert
    inc2 = correlator.correlate_alert(db_session, a2)

    # Must correlate into the SAME incident despite the IP rotation!
    assert inc2.id == inc1.id
    assert "198.51.100.45" in inc2.related_entities["ips"]
    assert "203.0.113.88" in inc2.related_entities["ips"]
    assert "admin_svc" in inc2.related_entities["users"]

    # Test NetworkX graph construction for this incident
    graph_data = graph_builder.build_graph_for_alerts(inc2.id, [a1, a2])
    node_ids = {n.id for n in graph_data.nodes}
    assert "ip_198.51.100.45" in node_ids
    assert "ip_203.0.113.88" in node_ids
    assert "user_admin_svc" in node_ids
    assert graph_data.edge_count >= 4
