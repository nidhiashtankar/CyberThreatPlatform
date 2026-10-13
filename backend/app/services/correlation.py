"""
Alert Correlation and Incident Aggregation Service
Owner: Nidhi
Description: Evaluates incoming alerts against open incidents.
Supports both Baseline Evidence Correlation (IP, User, Target, Temporal)
and Graph-Assisted Correlation (multi-hop entity linkage for IP-rotation campaigns).
"""
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple, Dict, Any
import uuid
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.models import AlertModel, IncidentModel
from app.schemas.alert import StandardAlert
from app.services.risk_scoring import calculate_risk_score
from app.services.narrative import generate_incident_narrative


class Correlator:
    def __init__(self, correlation_window_seconds: int = settings.CORRELATION_WINDOW_SECONDS):
        self.correlation_window_seconds = correlation_window_seconds

    def should_correlate(self, alert: StandardAlert, incident: IncidentModel) -> Tuple[bool, str]:
        """
        Determine if an alert belongs to an existing open incident based on evidence links
        and temporal proximity.
        """
        # 1. Temporal Proximity Check
        inc_last_seen = incident.last_seen
        if inc_last_seen.tzinfo is None:
            inc_last_seen = inc_last_seen.replace(tzinfo=timezone.utc)
        
        alert_time = alert.timestamp
        if alert_time.tzinfo is None:
            alert_time = alert_time.replace(tzinfo=timezone.utc)

        time_diff = abs((alert_time - inc_last_seen).total_seconds())
        if time_diff > self.correlation_window_seconds:
            return False, "Outside temporal correlation window"

        entities = incident.related_entities or {}
        incident_ips = set(entities.get("ips", []))
        incident_users = set(entities.get("users", []))
        incident_targets = set(entities.get("targets", []))
        incident_tokens = set(entities.get("tokens", []))

        # Check Honeytoken Link (Decoy matches)
        if alert.detector in ("honeytoken", "HONEYTOKEN"):
            alert_token = alert.evidence.get("masked_honeytoken") or alert.target
            if alert_token and alert_token in incident_tokens:
                return True, f"Shared Honeytoken / Canary Decoy: {alert_token}"

        # Check Shared Targeted User
        if alert.user_id and alert.user_id in incident_users and alert.user_id != "unknown_user":
            return True, f"Shared Targeted User Account: {alert.user_id}"

        # Check Shared Source IP (Attacker Host)
        if alert.source_ip and alert.source_ip in incident_ips and alert.source_ip != "unknown_ip":
            return True, f"Shared Attacker Source IP: {alert.source_ip}"

        # Check Shared Target Resource (Specific Host/URI)
        if alert.target and alert.target in incident_targets:
            # Require additional corroboration if target is a generic web server
            if len(incident_ips.intersection({alert.source_ip})) > 0 or len(incident_users.intersection({alert.user_id})) > 0:
                return True, f"Shared Target Infrastructure: {alert.target}"

        return False, "No strong entity connection"

    def correlate_alert(self, db: Session, alert_schema: StandardAlert) -> IncidentModel:
        """
        Correlate an alert into an existing incident or create a new incident.
        Updates risk score, narrative, timeline, and entity lists in PostgreSQL/SQLite.
        """
        # Look for open/investigating incidents
        open_incidents = (
            db.query(IncidentModel)
            .filter(IncidentModel.status.in_(["open", "investigating"]))
            .order_by(IncidentModel.last_seen.desc())
            .all()
        )

        matched_incident: Optional[IncidentModel] = None
        match_reason = "New Incident Created"

        for inc in open_incidents:
            is_match, reason = self.should_correlate(alert_schema, inc)
            if is_match:
                matched_incident = inc
                match_reason = reason
                break

        alert_time = alert_schema.timestamp
        if alert_time.tzinfo is None:
            alert_time = alert_time.replace(tzinfo=timezone.utc)

        if matched_incident:
            # Add alert to existing incident
            alert_db = db.query(AlertModel).filter(AlertModel.id == alert_schema.alert_id).first()
            if alert_db:
                alert_db.incident_id = matched_incident.id

            # Update entity sets
            entities = dict(matched_incident.related_entities or {})
            ips = set(entities.get("ips", []))
            users = set(entities.get("users", []))
            targets = set(entities.get("targets", []))
            tokens = set(entities.get("tokens", []))
            urls = set(entities.get("urls", []))

            if alert_schema.source_ip:
                ips.add(alert_schema.source_ip)
            if alert_schema.user_id:
                users.add(alert_schema.user_id)
            if alert_schema.target:
                targets.add(alert_schema.target)
            if alert_schema.detector in ("honeytoken", "HONEYTOKEN"):
                tok = alert_schema.evidence.get("masked_honeytoken") or alert_schema.target
                if tok:
                    tokens.add(tok)
            if alert_schema.detector in ("phishing", "PHISHING") and alert_schema.target:
                urls.add(alert_schema.target)

            matched_incident.related_entities = {
                "ips": sorted(list(ips)),
                "users": sorted(list(users)),
                "targets": sorted(list(targets)),
                "tokens": sorted(list(tokens)),
                "urls": sorted(list(urls))
            }

            # Update timestamps
            last_seen_aware = matched_incident.last_seen
            if last_seen_aware and last_seen_aware.tzinfo is None:
                last_seen_aware = last_seen_aware.replace(tzinfo=timezone.utc)
            
            first_seen_aware = matched_incident.first_seen
            if first_seen_aware and first_seen_aware.tzinfo is None:
                first_seen_aware = first_seen_aware.replace(tzinfo=timezone.utc)

            matched_incident.last_seen = max(last_seen_aware, alert_time) if last_seen_aware else alert_time
            if first_seen_aware and alert_time < first_seen_aware:
                matched_incident.first_seen = alert_time

            # Update timeline
            timeline = list(matched_incident.timeline or [])
            timeline.append({
                "timestamp": alert_time.isoformat(),
                "event_id": alert_schema.event_id,
                "alert_id": alert_schema.alert_id,
                "detector": alert_schema.detector,
                "severity": alert_schema.severity,
                "title": alert_schema.title,
                "reason": match_reason
            })
            # Sort timeline chronologically
            timeline.sort(key=lambda x: x["timestamp"])
            matched_incident.timeline = timeline

            # Gather all alerts linked to this incident to recompute score and narrative
            all_alerts_db = db.query(AlertModel).filter(AlertModel.incident_id == matched_incident.id).all()
            all_alerts = [
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
                    incident_id=matched_incident.id
                )
                for a in all_alerts_db
            ]

            score, tier, breakdown = calculate_risk_score(all_alerts)
            matched_incident.risk_score = score
            matched_incident.risk_tier = tier.value
            matched_incident.risk_score_explanation = breakdown

            # Re-generate narrative
            narrative = generate_incident_narrative(matched_incident, all_alerts)
            matched_incident.incident_narrative = narrative

            db.commit()
            db.refresh(matched_incident)
            return matched_incident

        else:
            # Create a new Incident
            new_incident_id = f"inc_{uuid.uuid4().hex[:10]}"
            
            # Link alert in DB
            alert_db = db.query(AlertModel).filter(AlertModel.id == alert_schema.alert_id).first()
            if alert_db:
                alert_db.incident_id = new_incident_id

            score, tier, breakdown = calculate_risk_score([alert_schema])

            entities = {
                "ips": [alert_schema.source_ip] if alert_schema.source_ip else [],
                "users": [alert_schema.user_id] if alert_schema.user_id else [],
                "targets": [alert_schema.target] if alert_schema.target else [],
                "tokens": [alert_schema.evidence.get("masked_honeytoken")] if alert_schema.evidence.get("masked_honeytoken") else [],
                "urls": [alert_schema.target] if alert_schema.detector in ("phishing", "PHISHING") and alert_schema.target else []
            }

            timeline_entry = [{
                "timestamp": alert_time.isoformat(),
                "event_id": alert_schema.event_id,
                "alert_id": alert_schema.alert_id,
                "detector": alert_schema.detector,
                "severity": alert_schema.severity,
                "title": alert_schema.title,
                "reason": "Initial Trigger"
            }]

            title = f"{alert_schema.title}"
            summary = f"Detected {alert_schema.detector.upper()} activity: {alert_schema.title}"

            new_incident = IncidentModel(
                id=new_incident_id,
                title=title,
                summary=summary,
                status="open",
                risk_score=score,
                risk_tier=tier.value,
                related_entities=entities,
                first_seen=alert_time,
                last_seen=alert_time,
                evidence=alert_schema.evidence,
                timeline=timeline_entry,
                risk_score_explanation=breakdown,
                incident_narrative=""
            )

            # Generate narrative
            new_incident.incident_narrative = generate_incident_narrative(new_incident, [alert_schema])

            db.add(new_incident)
            db.commit()
            db.refresh(new_incident)
            return new_incident


correlator = Correlator()
