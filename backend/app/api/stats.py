from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.db.models import IncidentModel, AlertModel, EventModel

router = APIRouter(tags=["Dashboard Statistics"])


@router.get("/stats/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregated SOC metric summary for the light-theme dashboard."""
    total_incidents = db.query(func.count(IncidentModel.id)).scalar() or 0
    active_incidents = db.query(func.count(IncidentModel.id)).filter(
        IncidentModel.status.in_(["open", "investigating"])
    ).scalar() or 0
    
    high_critical_incidents = db.query(func.count(IncidentModel.id)).filter(
        IncidentModel.risk_tier.in_(["High", "Critical"])
    ).scalar() or 0

    total_alerts = db.query(func.count(AlertModel.id)).scalar() or 0
    total_events = db.query(func.count(EventModel.id)).scalar() or 0

    # Risk Tier distribution
    tier_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    tier_rows = db.query(IncidentModel.risk_tier, func.count(IncidentModel.id)).group_by(IncidentModel.risk_tier).all()
    for tier, count in tier_rows:
        if tier in tier_counts:
            tier_counts[tier] = count

    # Detector distribution
    detector_counts = {}
    det_rows = db.query(AlertModel.detector, func.count(AlertModel.id)).group_by(AlertModel.detector).all()
    for det, count in det_rows:
        detector_counts[det] = count

    # Recent incidents
    recent_incidents = (
        db.query(IncidentModel)
        .order_by(IncidentModel.last_seen.desc())
        .limit(5)
        .all()
    )

    # Recent alerts
    recent_alerts = (
        db.query(AlertModel)
        .order_by(AlertModel.timestamp.desc())
        .limit(6)
        .all()
    )

    return {
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "high_critical_incidents": high_critical_incidents,
        "total_alerts": total_alerts,
        "total_events": total_events,
        "risk_tier_distribution": tier_counts,
        "detector_distribution": detector_counts,
        "recent_incidents": [
            {
                "id": inc.id,
                "title": inc.title,
                "status": inc.status,
                "risk_score": inc.risk_score,
                "risk_tier": inc.risk_tier,
                "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
                "alert_count": len(inc.alerts) if inc.alerts else 0
            }
            for inc in recent_incidents
        ],
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "detector": a.detector,
                "severity": a.severity,
                "confidence": a.confidence,
                "source_ip": a.source_ip,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None
            }
            for a in recent_alerts
        ]
    }
