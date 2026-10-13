from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field, field_validator


class SecurityEvent(BaseModel):
    """
    Standard Security Event schema ingested into the SOC platform.
    Validated with Pydantic.
    """
    event_id: str = Field(
        default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}",
        description="Unique identifier for the security event"
    )
    event_type: str = Field(
        ...,
        description="Type of event: login_attempt, network_connection, http_request, honeytoken_access, url_submission"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the event occurred"
    )
    source_ip: Optional[str] = Field(None, description="Originating IPv4 or IPv6 address")
    user_id: Optional[str] = Field(None, description="Username or account identifier")
    target: Optional[str] = Field(None, description="Target host, service, port, or asset")
    source_module: Optional[str] = Field("simulator", description="Source sensor or collector module")
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detector-specific evidence or raw payload attributes"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional context, headers, or metadata"
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                # Handle ISO timestamps
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(timezone.utc)
        return v or datetime.now(timezone.utc)

    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "evt_sample_001",
                "event_type": "login_attempt",
                "timestamp": "2026-10-13T10:00:00Z",
                "source_ip": "198.51.100.45",
                "user_id": "admin",
                "target": "auth_portal",
                "source_module": "auth_collector",
                "evidence": {
                    "status": "failed",
                    "auth_method": "password"
                }
            }
        }


class EventIngestResponse(BaseModel):
    status: str
    event_id: str
    generated_alerts_count: int
    alert_ids: list[str]
    incident_id: Optional[str] = None
    message: str
