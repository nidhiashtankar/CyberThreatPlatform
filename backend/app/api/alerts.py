from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.session import get_db
from app.db.models import AlertModel
from app.schemas.alert import StandardAlert

router = APIRouter(tags=["Alerts"])


@router.get("/alerts", response_model=List[StandardAlert])
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    detector: Optional[str] = Query(None, description="Filter by detector module"),
    category: Optional[str] = Query(None, description="Filter by attack category"),
    source_ip: Optional[str] = Query(None, description="Filter by attacker source IP"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Retrieve standardized security alerts with optional filtering.
    """
    query = db.query(AlertModel).order_by(AlertModel.timestamp.desc())

    if severity:
        query = query.filter(AlertModel.severity == severity.lower())
    if detector:
        query = query.filter(AlertModel.detector == detector.lower())
    if category:
        query = query.filter(AlertModel.category == category.lower())
    if source_ip:
        query = query.filter(AlertModel.source_ip == source_ip)

    alerts_db = query.offset(offset).limit(limit).all()

    return [
        StandardAlert(
            alert_id=a.id,
            event_id=a.event_id,
            detector=a.detector,
            category=a.category,
            severity=a.severity,
            confidence=a.confidence,
            source_ip=a.source_ip,
            user_id=a.user_id,
            target=a.target,
            timestamp=a.timestamp,
            title=a.title,
            evidence=a.evidence or {},
            recommended_action=a.recommended_action,
            incident_id=a.incident_id
        )
        for a in alerts_db
    ]


@router.get("/alerts/{alert_id}", response_model=StandardAlert)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """Retrieve full details and evidence for a specific alert."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    return StandardAlert(
        alert_id=alert.id,
        event_id=alert.event_id,
        detector=alert.detector,
        category=alert.category,
        severity=alert.severity,
        confidence=alert.confidence,
        source_ip=alert.source_ip,
        user_id=alert.user_id,
        target=alert.target,
        timestamp=alert.timestamp,
        title=alert.title,
        evidence=alert.evidence or {},
        recommended_action=alert.recommended_action,
        incident_id=alert.incident_id
    )
