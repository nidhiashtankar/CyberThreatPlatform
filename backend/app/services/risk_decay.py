"""
Risk Decay Service
Owner: Aastha
Description: Applies exponential half-life time decay to stale alerts while preserving
critical historical evidence, deception traps, and audit logs.
"""
from datetime import datetime, timezone
import math
from typing import List, Dict, Any, Tuple
from app.core.config import settings
from app.schemas.alert import StandardAlert, AlertSeverity, AlertDetector
from app.schemas.incident import RiskTier
from app.services.risk_scoring import calculate_risk_score


def calculate_decayed_risk(
    alerts: List[StandardAlert],
    reference_time: datetime,
    half_life_hours: float = settings.RISK_DECAY_HALF_LIFE_HOURS
) -> Tuple[float, RiskTier, List[Dict[str, Any]]]:
    """
    Calculate decayed risk score while maintaining critical evidence protection floors.
    """
    if not alerts:
        return 0.0, RiskTier.LOW, [{"reason": "No alerts to decay", "points": 0.0}]

    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    # First calculate the base un-decayed score and breakdown
    base_score, _, raw_breakdown = calculate_risk_score(alerts)

    decay_reasons = []
    weighted_decayed_sum = 0.0
    total_weights = 0.0

    has_honeytoken = False
    has_critical_alert = False

    for alert in alerts:
        alert_time = alert.timestamp
        if alert_time.tzinfo is None:
            alert_time = alert_time.replace(tzinfo=timezone.utc)

        elapsed_seconds = max(0.0, (reference_time - alert_time).total_seconds())
        elapsed_hours = elapsed_seconds / 3600.0

        # Half-life exponential decay factor: factor = 2 ** (-elapsed_hours / half_life)
        decay_factor = math.pow(2.0, -elapsed_hours / max(1.0, half_life_hours))
        
        # Check critical protection floor:
        if alert.detector in (AlertDetector.HONEYTOKEN, "honeytoken"):
            has_honeytoken = True
            # Honeytoken decay is bounded at minimum 0.70 factor
            decay_factor = max(0.70, decay_factor)
        
        if alert.severity in (AlertSeverity.CRITICAL, "critical"):
            has_critical_alert = True
            # Critical alerts cannot decay below 0.50
            decay_factor = max(0.50, decay_factor)

        decay_reasons.append({
            "alert_id": alert.alert_id,
            "detector": alert.detector,
            "elapsed_hours": round(elapsed_hours, 2),
            "decay_factor": round(decay_factor, 3),
            "reason": f"Alert '{alert.title}' occurred {elapsed_hours:.1f}h ago (Decay factor: {decay_factor:.2f})"
        })

        weighted_decayed_sum += decay_factor
        total_weights += 1.0

    avg_decay = weighted_decayed_sum / max(1.0, total_weights)
    decayed_score = base_score * avg_decay

    # Evidence preservation floor
    protection_note = None
    if has_honeytoken:
        protection_note = "Honeytoken preservation floor enforced (minimum 40.0 risk score preserved)"
        if decayed_score < 40.0:
            decayed_score = 40.0
    elif has_critical_alert:
        protection_note = "Critical alert preservation floor enforced (minimum 30.0 risk score preserved)"
        if decayed_score < 30.0:
            decayed_score = 30.0

    final_decayed_score = round(max(0.0, min(100.0, decayed_score)), 1)

    # Determine decayed risk tier
    if final_decayed_score >= 85.0:
        tier = RiskTier.CRITICAL
    elif final_decayed_score >= 60.0:
        tier = RiskTier.HIGH
    elif final_decayed_score >= 30.0:
        tier = RiskTier.MEDIUM
    else:
        tier = RiskTier.LOW

    explanations = [
        {
            "category": "Decay Summary",
            "base_score": base_score,
            "decayed_score": final_decayed_score,
            "average_decay_factor": round(avg_decay, 3),
            "half_life_hours": half_life_hours,
            "preservation_note": protection_note
        }
    ]
    explanations.extend(decay_reasons)

    return final_decayed_score, tier, explanations
