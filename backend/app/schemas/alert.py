from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field, field_validator


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertDetector(str, Enum):
    PHISHING = "phishing"
    LOGIN = "login"
    PORT_SCAN = "port_scan"
    WEB_ATTACK = "web_attack"
    HONEYTOKEN = "honeytoken"


class AlertCategory(str, Enum):
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    RECONNAISSANCE = "reconnaissance"
    WEB_EXPLOITATION = "web_exploitation"
    DECEPTION = "deception"


class StandardAlert(BaseModel):
    """
    Standardized Alert structure output by every detection module.
    Validated with Pydantic.
    """
    alert_id: str = Field(
        default_factory=lambda: f"alt_{uuid.uuid4().hex[:12]}",
        description="Unique alert identifier"
    )
    event_id: str = Field(..., description="ID of the triggering security event")
    detector: AlertDetector = Field(..., description="Detection module that raised this alert")
    category: AlertCategory = Field(..., description="MITRE ATT&CK or security threat category")
    severity: AlertSeverity = Field(..., description="Severity level: low, medium, high, critical")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detection confidence score between 0.0 and 1.0"
    )
    source_ip: Optional[str] = Field(None, description="Attacker or client IP address")
    user_id: Optional[str] = Field(None, description="Targeted or implicated user account")
    target: Optional[str] = Field(None, description="Target host, URI, or honeypot resource")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of alert generation"
    )
    title: str = Field(..., description="Concise human-readable title of the alert")
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized evidence, matched signatures, counts, and indicators"
    )
    recommended_action: str = Field(..., description="Actionable SOC guidance")
    incident_id: Optional[str] = Field(None, description="Correlated incident ID if grouped")

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(timezone.utc)
        return v or datetime.now(timezone.utc)

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alt_demo_001",
                "event_id": "evt_sample_001",
                "detector": "login",
                "category": "credential_access",
                "severity": "high",
                "confidence": 0.90,
                "source_ip": "198.51.100.45",
                "user_id": "admin",
                "target": "auth_portal",
                "timestamp": "2026-10-13T10:02:00Z",
                "title": "Brute Force Attack Followed by Successful Login",
                "evidence": {
                    "failed_count": 6,
                    "window_seconds": 120,
                    "suspicious_sequence": True
                },
                "recommended_action": "Force password reset and terminate active sessions for user 'admin'."
            }
        }
