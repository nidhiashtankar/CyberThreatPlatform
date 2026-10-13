"""
Risk Scoring Service
Owner: Aastha
Description: Deterministic, bounded (0-100), explainable risk calculation.
Evaluates alert severity, confidence, duplicate mitigation, honeytoken triggers,
and multi-stage attack progression with an itemized scoring explanation.
"""
from typing import List, Dict, Any, Tuple
from app.schemas.alert import StandardAlert, AlertSeverity, AlertCategory, AlertDetector
from app.schemas.incident import RiskTier


SEVERITY_BASE_WEIGHTS = {
    AlertSeverity.CRITICAL: 40.0,
    AlertSeverity.HIGH: 25.0,
    AlertSeverity.MEDIUM: 15.0,
    AlertSeverity.LOW: 5.0,
}


def calculate_risk_score(alerts: List[StandardAlert]) -> Tuple[float, RiskTier, List[Dict[str, Any]]]:
    """
    Calculate deterministic risk score (0-100), risk tier, and itemized reasons.
    """
    if not alerts:
        return 0.0, RiskTier.LOW, [{"reason": "No alerts associated with incident", "points": 0.0}]

    raw_score = 0.0
    breakdown: List[Dict[str, Any]] = []

    # 1. Base weights by severity & confidence with diminishing returns for repeated detector types
    detector_counts: Dict[str, int] = {}
    for alert in alerts:
        det_name = alert.detector.value if hasattr(alert.detector, "value") else str(alert.detector)
        detector_counts[det_name] = detector_counts.get(det_name, 0) + 1
        count = detector_counts[det_name]

        # Diminishing returns: 1st alert: 100%, 2nd: 50%, 3rd+: 20%
        if count == 1:
            multiplier = 1.0
        elif count == 2:
            multiplier = 0.5
        else:
            multiplier = 0.2

        sev = alert.severity if isinstance(alert.severity, AlertSeverity) else AlertSeverity(alert.severity)
        base = SEVERITY_BASE_WEIGHTS.get(sev, 10.0)
        conf = max(0.1, min(1.0, alert.confidence))
        alert_pts = round(base * conf * multiplier, 2)
        raw_score += alert_pts

        breakdown.append({
            "category": "Alert Contribution",
            "reason": f"[{alert.detector.upper()}] {alert.title} (Severity: {alert.severity}, Conf: {alert.confidence:.2f}, Iteration: {count})",
            "points": alert_pts
        })

    # 2. Bonus for high-confidence Honeytoken Trigger
    has_honeytoken = any(
        alert.detector in (AlertDetector.HONEYTOKEN, "honeytoken")
        for alert in alerts
    )
    if has_honeytoken:
        ht_bonus = 25.0
        raw_score += ht_bonus
        breakdown.append({
            "category": "Critical Threat Bonus",
            "reason": "Honeytoken / Canary decoy trap activated (Near-certain active adversary)",
            "points": ht_bonus
        })

    # 3. Multi-detector Corroboration Bonus
    unique_detectors = {alert.detector for alert in alerts}
    if len(unique_detectors) >= 3:
        corr_bonus = 15.0
        raw_score += corr_bonus
        breakdown.append({
            "category": "Corroboration Bonus",
            "reason": f"Corroborated across {len(unique_detectors)} distinct detection modules",
            "points": corr_bonus
        })
    elif len(unique_detectors) == 2:
        corr_bonus = 8.0
        raw_score += corr_bonus
        breakdown.append({
            "category": "Corroboration Bonus",
            "reason": f"Corroborated across 2 distinct detection modules",
            "points": corr_bonus
        })

    # 4. Multi-Stage Attack Progression Bonus (e.g. Recon -> Credential Access / Exploitation)
    categories = {alert.category for alert in alerts}
    is_multi_stage = (
        (AlertCategory.RECONNAISSANCE in categories or "reconnaissance" in categories) and
        (AlertCategory.CREDENTIAL_ACCESS in categories or AlertCategory.WEB_EXPLOITATION in categories)
    )
    if is_multi_stage:
        prog_bonus = 12.0
        raw_score += prog_bonus
        breakdown.append({
            "category": "Attack Progression Bonus",
            "reason": "Multi-stage attack sequence identified (Reconnaissance combined with Exploitation/Credential Access)",
            "points": prog_bonus
        })

    # Bound strictly between 0 and 100
    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    # Determine Risk Tier
    if final_score >= 85.0:
        tier = RiskTier.CRITICAL
    elif final_score >= 60.0:
        tier = RiskTier.HIGH
    elif final_score >= 30.0:
        tier = RiskTier.MEDIUM
    else:
        tier = RiskTier.LOW

    return final_score, tier, breakdown
