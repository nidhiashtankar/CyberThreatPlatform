"""
Simulated Response Action Service
Owner: Radhika
Description: Safely handles dry-run, auditable containment actions (simulated IP blocking,
account disabling, incident containment). Prevents accidental modification of real systems.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import uuid
from sqlalchemy.orm import Session
from app.db.models import IncidentModel, ResponseActionModel
from app.schemas.incident import (
    ResponseActionType,
    ResponseActionRequest,
    ResponseActionRecord,
    IncidentStatus
)


class ResponseService:
    def __init__(self):
        pass

    def execute_simulated_action(
        self,
        db: Session,
        incident_id: str,
        request: ResponseActionRequest
    ) -> ResponseActionRecord:
        """
        Execute a dry-run simulated response action and record an immutable audit entry.
        """
        incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID '{incident_id}' not found.")

        now = datetime.now(timezone.utc)
        action_id = f"act_{uuid.uuid4().hex[:10]}"
        action_type = request.action_type
        analyst = request.analyst_id or "demo_analyst"
        reason = request.reason
        params = request.parameters or {}

        # Construct safe dry-run outcomes
        if action_type == ResponseActionType.SIMULATE_BLOCK_IP:
            target_ip = params.get("ip") or (incident.related_entities.get("ips", ["0.0.0.0"])[0] if incident.related_entities else "Unknown")
            outcome = (
                f"[DRY-RUN] Simulated firewall rule created: iptables -A INPUT -s {target_ip} -j DROP. "
                "No real network traffic was blocked."
            )
            params["simulated_firewall_rule"] = f"DROP {target_ip}/32"

        elif action_type == ResponseActionType.SIMULATE_DISABLE_ACCOUNT:
            target_user = params.get("user") or (incident.related_entities.get("users", ["target_user"])[0] if incident.related_entities else "Unknown")
            outcome = (
                f"[DRY-RUN] Simulated Active Directory / IAM lockout for user '{target_user}'. "
                "Revoked active OAuth tokens in simulation. No production directory was modified."
            )
            params["simulated_lockout_account"] = target_user

        elif action_type == ResponseActionType.CONTAIN_INCIDENT:
            incident.status = IncidentStatus.CONTAINED.value
            outcome = (
                f"Incident status updated to 'CONTAINED'. Simulated host quarantine dispatched. "
                f"Analyst '{analyst}' verified threat vector neutralization."
            )

        elif action_type == ResponseActionType.INVESTIGATE_INCIDENT:
            incident.status = IncidentStatus.INVESTIGATING.value
            outcome = (
                f"Incident status changed to 'INVESTIGATING'. Forensics ticket spawned. "
                f"Assigned to analyst '{analyst}'."
            )

        elif action_type == ResponseActionType.RESET_HONEYTOKEN:
            token_id = params.get("token") or "Decoy Canary Token"
            outcome = (
                f"[DRY-RUN] Simulated decoy credential cycling for '{token_id}'. "
                "Canary secret marked rotated in deception management catalog."
            )
            params["rotated_decoy"] = token_id

        else:
            outcome = f"[DRY-RUN] Action {action_type} recorded successfully in simulation mode."

        # Persist audit record in DB
        action_db = ResponseActionModel(
            id=action_id,
            incident_id=incident_id,
            action_type=action_type.value if hasattr(action_type, "value") else str(action_type),
            analyst_id=analyst,
            timestamp=now,
            reason=reason,
            simulation_status="SIMULATED_SUCCESS",
            outcome=outcome,
            parameters=params
        )

        db.add(action_db)
        db.commit()
        db.refresh(action_db)

        return ResponseActionRecord(
            action_id=action_db.id,
            incident_id=action_db.incident_id,
            action_type=action_type,
            analyst_id=action_db.analyst_id,
            timestamp=action_db.timestamp,
            reason=action_db.reason,
            simulation_status=action_db.simulation_status,
            outcome=action_db.outcome,
            parameters=action_db.parameters or {}
        )


response_service = ResponseService()
