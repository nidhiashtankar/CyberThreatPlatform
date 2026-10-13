from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field
from app.schemas.alert import StandardAlert


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class RiskTier(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FeedbackVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class FeedbackRequest(BaseModel):
    verdict: FeedbackVerdict
    notes: Optional[str] = ""
    analyst_id: Optional[str] = "analyst_swanandi"


class FeedbackRecord(BaseModel):
    feedback_id: str = Field(default_factory=lambda: f"fb_{uuid.uuid4().hex[:10]}")
    incident_id: str
    verdict: FeedbackVerdict
    notes: str
    analyst_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResponseActionType(str, Enum):
    SIMULATE_BLOCK_IP = "SIMULATE_BLOCK_IP"
    SIMULATE_DISABLE_ACCOUNT = "SIMULATE_DISABLE_ACCOUNT"
    INVESTIGATE_INCIDENT = "INVESTIGATE_INCIDENT"
    CONTAIN_INCIDENT = "CONTAIN_INCIDENT"
    RESET_HONEYTOKEN = "RESET_HONEYTOKEN"


class ResponseActionRequest(BaseModel):
    action_type: ResponseActionType
    reason: str
    analyst_id: Optional[str] = "analyst_radhika"
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ResponseActionRecord(BaseModel):
    action_id: str = Field(default_factory=lambda: f"act_{uuid.uuid4().hex[:10]}")
    incident_id: str
    action_type: ResponseActionType
    analyst_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str
    simulation_status: str = "SIMULATED_SUCCESS"
    outcome: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # ip, user, target, url, honeytoken, alert
    role: Optional[str] = "entity"  # attacker, victim, decoy, artifact, alert
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    evidence: str
    timestamp: Optional[str] = None


class IncidentGraphResponse(BaseModel):
    incident_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    node_count: int
    edge_count: int
    key_hubs: List[str] = Field(default_factory=list)


class Incident(BaseModel):
    incident_id: str = Field(
        default_factory=lambda: f"inc_{uuid.uuid4().hex[:12]}",
        description="Unique incident identifier"
    )
    title: str = Field(..., description="High-level incident summary title")
    summary: str = Field(..., description="Summary explanation of the aggregated incident")
    status: IncidentStatus = Field(default=IncidentStatus.OPEN)
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calculated risk score 0 to 100")
    risk_tier: RiskTier = Field(..., description="Low, Medium, High, Critical")
    linked_alerts: List[StandardAlert] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)
    related_entities: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "ips": [],
            "users": [],
            "targets": [],
            "tokens": [],
            "urls": []
        }
    )
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score_explanation: List[Dict[str, Any]] = Field(default_factory=list)
    incident_narrative: str = Field("", description="Generated chronological explanation")
    analyst_feedback: Optional[FeedbackRecord] = None
    response_actions: List[ResponseActionRecord] = Field(default_factory=list)
