from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl
from app.db.session import get_db
from app.db.models import EventModel, AlertModel
from app.schemas.event import SecurityEvent, EventIngestResponse
from app.schemas.alert import StandardAlert
from app.detectors import dispatch_event_to_detectors
from app.detectors.phishing.detector import phishing_detector
from app.services.correlation import correlator

router = APIRouter(tags=["Events & Detection"])


class PhishingUrlRequest(BaseModel):
    url: str


class PhishingUrlResponse(BaseModel):
    valid: bool
    url: str
    is_phishing: bool
    confidence: float
    features: Dict[str, Any]
    evidence: Dict[str, Any]
    alert_generated: bool
    alert_id: Optional[str] = None


@router.post("/events/ingest", response_model=EventIngestResponse)
def ingest_security_event(event: SecurityEvent, db: Session = Depends(get_db)):
    """
    Ingest a security event into the SOC platform.
    Runs active detection modules, persists event and alerts, and executes alert correlation.
    """
    # 1. Idempotency check: if event_id already exists, return existing status
    existing_event = db.query(EventModel).filter(EventModel.id == event.event_id).first()
    if existing_event:
        existing_alerts = db.query(AlertModel).filter(AlertModel.event_id == event.event_id).all()
        alert_ids = [a.id for a in existing_alerts]
        inc_id = existing_alerts[0].incident_id if existing_alerts else None
        return EventIngestResponse(
            status="duplicate_acknowledged",
            event_id=event.event_id,
            generated_alerts_count=len(alert_ids),
            alert_ids=alert_ids,
            incident_id=inc_id,
            message="Event already ingested. Existing alerts and correlation preserved."
        )

    # 2. Persist event
    event_db = EventModel(
        id=event.event_id,
        event_type=event.event_type,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        user_id=event.user_id,
        target=event.target,
        source_module=event.source_module or "simulator",
        evidence=event.evidence,
        metadata_json=event.metadata or {}
    )
    db.add(event_db)
    db.commit()

    # 3. Dispatch to detection modules
    generated_alerts = dispatch_event_to_detectors(event)
    alert_ids = []
    last_incident_id = None

    # 4. Persist alerts and correlate
    for alert in generated_alerts:
        alert_db = AlertModel(
            id=alert.alert_id,
            event_id=event.event_id,
            detector=alert.detector.value if hasattr(alert.detector, "value") else str(alert.detector),
            category=alert.category.value if hasattr(alert.category, "value") else str(alert.category),
            severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            confidence=alert.confidence,
            source_ip=alert.source_ip,
            user_id=alert.user_id,
            target=alert.target,
            timestamp=alert.timestamp,
            title=alert.title,
            evidence=alert.evidence,
            recommended_action=alert.recommended_action,
            incident_id=None
        )
        db.add(alert_db)
        db.commit()

        # Correlate alert into incident
        incident = correlator.correlate_alert(db, alert)
        last_incident_id = incident.id
        alert_ids.append(alert.alert_id)

    return EventIngestResponse(
        status="processed",
        event_id=event.event_id,
        generated_alerts_count=len(alert_ids),
        alert_ids=alert_ids,
        incident_id=last_incident_id,
        message=f"Event ingested successfully. Generated {len(alert_ids)} alert(s)."
    )


@router.post("/detect/phishing-url", response_model=PhishingUrlResponse)
def detect_phishing_url(payload: PhishingUrlRequest, db: Session = Depends(get_db)):
    """
    Test individual URL against the Random Forest classifier and lexical heuristics.
    Produces an alert if malicious.
    """
    analysis = phishing_detector.analyze_url(payload.url)
    if not analysis.get("valid"):
        raise HTTPException(status_code=400, detail=analysis.get("error", "Invalid URL"))

    alert_id = None
    if analysis["is_phishing"]:
        # Synthesize a SecurityEvent and run detector to produce alert
        event = SecurityEvent(
            event_type="url_submission",
            target=payload.url,
            source_module="analyst_submission",
            evidence={"url": payload.url}
        )
        # Ingest and alert
        db_event = EventModel(
            id=event.event_id,
            event_type=event.event_type,
            timestamp=event.timestamp,
            target=event.target,
            source_module=event.source_module,
            evidence=event.evidence,
            metadata_json={}
        )
        db.add(db_event)
        db.commit()

        alert = phishing_detector.process_event(event)
        if alert:
            alert_db = AlertModel(
                id=alert.alert_id,
                event_id=event.event_id,
                detector=alert.detector.value if hasattr(alert.detector, "value") else str(alert.detector),
                category=alert.category.value if hasattr(alert.category, "value") else str(alert.category),
                severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                confidence=alert.confidence,
                source_ip=alert.source_ip,
                user_id=alert.user_id,
                target=alert.target,
                timestamp=alert.timestamp,
                title=alert.title,
                evidence=alert.evidence,
                recommended_action=alert.recommended_action,
                incident_id=None
            )
            db.add(alert_db)
            db.commit()
            correlator.correlate_alert(db, alert)
            alert_id = alert.alert_id

    return PhishingUrlResponse(
        valid=analysis["valid"],
        url=analysis["url"],
        is_phishing=analysis["is_phishing"],
        confidence=analysis["confidence"],
        features=analysis["features"],
        evidence=analysis["evidence"],
        alert_generated=bool(alert_id),
        alert_id=alert_id
    )


@router.get("/events")
def list_events(
    limit: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve recent security events."""
    query = db.query(EventModel).order_by(EventModel.timestamp.desc())
    if event_type:
        query = query.filter(EventModel.event_type == event_type)
    events = query.limit(limit).all()
    return [
        {
            "event_id": e.id,
            "event_type": e.event_type,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source_ip": e.source_ip,
            "user_id": e.user_id,
            "target": e.target,
            "source_module": e.source_module,
            "evidence": e.evidence
        }
        for e in events
    ]
