from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Float,
    DateTime,
    Text,
    JSON,
    ForeignKey
)
from sqlalchemy.orm import relationship
from app.db.session import Base


class EventModel(Base):
    __tablename__ = "events"

    id = Column(String(64), primary_key=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    target = Column(String(255), nullable=True)
    source_module = Column(String(64), default="simulator")
    evidence = Column(JSON, default=dict)
    metadata_json = Column(JSON, default=dict)


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True)
    event_id = Column(String(64), ForeignKey("events.id", ondelete="CASCADE"), index=True)
    detector = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    source_ip = Column(String(64), nullable=True, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    target = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    title = Column(String(255), nullable=False)
    evidence = Column(JSON, default=dict)
    recommended_action = Column(Text, nullable=False)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)

    incident = relationship("IncidentModel", back_populates="alerts")


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    status = Column(String(32), default="open", index=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_tier = Column(String(32), default="Low", index=True)
    related_entities = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    evidence = Column(JSON, default=dict)
    timeline = Column(JSON, default=list)
    risk_score_explanation = Column(JSON, default=list)
    incident_narrative = Column(Text, default="")

    alerts = relationship("AlertModel", back_populates="incident", cascade="all, delete-orphan", passive_deletes=True)
    feedback = relationship("FeedbackModel", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    response_actions = relationship("ResponseActionModel", back_populates="incident", cascade="all, delete-orphan")


class FeedbackModel(Base):
    __tablename__ = "feedback"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), unique=True)
    verdict = Column(String(32), nullable=False)
    notes = Column(Text, default="")
    analyst_id = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("IncidentModel", back_populates="feedback")


class ResponseActionModel(Base):
    __tablename__ = "response_actions"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    action_type = Column(String(64), nullable=False)
    analyst_id = Column(String(64), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    reason = Column(Text, nullable=False)
    simulation_status = Column(String(64), default="SIMULATED_SUCCESS")
    outcome = Column(Text, nullable=False)
    parameters = Column(JSON, default=dict)

    incident = relationship("IncidentModel", back_populates="response_actions")
