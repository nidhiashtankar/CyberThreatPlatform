from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import uuid
from app.db.session import get_db
from app.db.models import IncidentModel, AlertModel, FeedbackModel, ResponseActionModel
from app.schemas.incident import (
    Incident,
    FeedbackRequest,
    FeedbackRecord,
    ResponseActionRequest,
    ResponseActionRecord,
    IncidentGraphResponse
)
from app.schemas.alert import StandardAlert
from app.services.graph_analysis import graph_builder
from app.services.response import response_service
from app.services.risk_decay import calculate_decayed_risk

router = APIRouter(tags=["Incidents"])


def _map_incident_model_to_schema(inc: IncidentModel, db: Session) -> Incident:
    alerts_db = db.query(AlertModel).filter(AlertModel.incident_id == inc.id).all()
    alerts = [
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
            incident_id=inc.id
        )
        for a in alerts_db
    ]

    feedback_rec = None
    if inc.feedback:
        feedback_rec = FeedbackRecord(
            feedback_id=inc.feedback.id,
            incident_id=inc.id,
            verdict=inc.feedback.verdict,
            notes=inc.feedback.notes or "",
            analyst_id=inc.feedback.analyst_id,
            timestamp=inc.feedback.timestamp
        )

    responses_list = []
    if inc.response_actions:
        responses_list = [
            ResponseActionRecord(
                action_id=act.id,
                incident_id=inc.id,
                action_type=act.action_type,
                analyst_id=act.analyst_id,
                timestamp=act.timestamp,
                reason=act.reason,
                simulation_status=act.simulation_status,
                outcome=act.outcome,
                parameters=act.parameters or {}
            )
            for act in inc.response_actions
        ]

    return Incident(
        incident_id=inc.id,
        title=inc.title,
        summary=inc.summary,
        status=inc.status,
        risk_score=inc.risk_score,
        risk_tier=inc.risk_tier,
        linked_alerts=alerts,
        alert_ids=[a.alert_id for a in alerts],
        related_entities=inc.related_entities or {},
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        evidence=inc.evidence or {},
        timeline=inc.timeline or [],
        risk_score_explanation=inc.risk_score_explanation or [],
        incident_narrative=inc.incident_narrative or "",
        analyst_feedback=feedback_rec,
        response_actions=responses_list
    )


@router.get("/incidents", response_model=List[Incident])
def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status: open, investigating, contained, closed"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier: Low, Medium, High, Critical"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """List security incidents with filtering options."""
    query = db.query(IncidentModel).order_by(IncidentModel.last_seen.desc())

    if status:
        query = query.filter(IncidentModel.status == status.lower())
    if risk_tier:
        query = query.filter(IncidentModel.risk_tier == risk_tier)

    incidents_db = query.offset(offset).limit(limit).all()
    return [_map_incident_model_to_schema(inc, db) for inc in incidents_db]


@router.get("/incidents/{incident_id}", response_model=Incident)
def get_incident_detail(
    incident_id: str,
    apply_decay: bool = Query(False, description="Simulate time decay based on current timestamp"),
    db: Session = Depends(get_db)
):
    """Retrieve complete incident details, narrative, linked alerts, and evidence."""
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    schema = _map_incident_model_to_schema(inc, db)

    if apply_decay and schema.linked_alerts:
        decayed_score, decayed_tier, decay_breakdown = calculate_decayed_risk(
            schema.linked_alerts,
            reference_time=datetime.now(timezone.utc)
        )
        schema.risk_score = decayed_score
        schema.risk_tier = decayed_tier
        schema.risk_score_explanation = decay_breakdown

    return schema


@router.get("/incidents/{incident_id}/graph", response_model=IncidentGraphResponse)
def get_incident_graph(incident_id: str, db: Session = Depends(get_db)):
    """
    Build and return NetworkX entity-relationship graph for the incident.
    """
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    alerts_db = db.query(AlertModel).filter(AlertModel.incident_id == incident_id).all()
    alerts = [
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
            incident_id=inc.id
        )
        for a in alerts_db
    ]

    return graph_builder.build_graph_for_alerts(incident_id, alerts)


@router.post("/incidents/{incident_id}/feedback", response_model=FeedbackRecord)
def submit_analyst_feedback(
    incident_id: str,
    feedback_req: FeedbackRequest,
    db: Session = Depends(get_db)
):
    """
    Submit and persist analyst validation feedback for an incident.
    """
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    existing_fb = db.query(FeedbackModel).filter(FeedbackModel.incident_id == incident_id).first()
    if existing_fb:
        existing_fb.verdict = feedback_req.verdict.value
        existing_fb.notes = feedback_req.notes or ""
        existing_fb.analyst_id = feedback_req.analyst_id or "analyst"
        existing_fb.timestamp = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing_fb)
        return FeedbackRecord(
            feedback_id=existing_fb.id,
            incident_id=incident_id,
            verdict=existing_fb.verdict,
            notes=existing_fb.notes,
            analyst_id=existing_fb.analyst_id,
            timestamp=existing_fb.timestamp
        )

    new_fb = FeedbackModel(
        id=f"fb_{uuid.uuid4().hex[:10]}",
        incident_id=incident_id,
        verdict=feedback_req.verdict.value,
        notes=feedback_req.notes or "",
        analyst_id=feedback_req.analyst_id or "analyst",
        timestamp=datetime.now(timezone.utc)
    )
    db.add(new_fb)
    db.commit()
    db.refresh(new_fb)

    return FeedbackRecord(
        feedback_id=new_fb.id,
        incident_id=incident_id,
        verdict=new_fb.verdict,
        notes=new_fb.notes,
        analyst_id=new_fb.analyst_id,
        timestamp=new_fb.timestamp
    )


@router.post("/incidents/{incident_id}/respond", response_model=ResponseActionRecord)
def trigger_simulated_response(
    incident_id: str,
    action_req: ResponseActionRequest,
    db: Session = Depends(get_db)
):
    """
    Trigger an audited, dry-run simulated response action against an incident.
    """
    try:
        return response_service.execute_simulated_action(db, incident_id, action_req)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
