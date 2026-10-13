from datetime import datetime, timezone, timedelta
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.incident import RiskTier
from app.services.risk_scoring import calculate_risk_score
from app.services.risk_decay import calculate_decayed_risk


def test_risk_scoring_bounds_and_tiers():
    # Empty alerts
    score, tier, breakdown = calculate_risk_score([])
    assert score == 0.0
    assert tier == RiskTier.LOW

    # High severity alert
    a1 = StandardAlert(
        alert_id="alt_1",
        event_id="evt_1",
        detector=AlertDetector.LOGIN,
        category=AlertCategory.CREDENTIAL_ACCESS,
        severity=AlertSeverity.HIGH,
        confidence=0.9,
        title="Brute Force Login",
        evidence={},
        recommended_action="Reset password"
    )
    score1, tier1, _ = calculate_risk_score([a1])
    assert 20.0 <= score1 <= 30.0

    # Multi-stage alerts with Honeytoken trigger -> Critical tier
    a2 = StandardAlert(
        alert_id="alt_2",
        event_id="evt_2",
        detector=AlertDetector.PORT_SCAN,
        category=AlertCategory.RECONNAISSANCE,
        severity=AlertSeverity.MEDIUM,
        confidence=0.8,
        title="Port Scan",
        evidence={},
        recommended_action="Firewall rule"
    )
    a3 = StandardAlert(
        alert_id="alt_3",
        event_id="evt_3",
        detector=AlertDetector.HONEYTOKEN,
        category=AlertCategory.DECEPTION,
        severity=AlertSeverity.CRITICAL,
        confidence=0.98,
        title="Canary Token Activated",
        evidence={},
        recommended_action="Isolate host"
    )

    multi_score, multi_tier, multi_breakdown = calculate_risk_score([a1, a2, a3])
    assert multi_score >= 85.0
    assert multi_tier == RiskTier.CRITICAL
    assert multi_score <= 100.0


def test_risk_decay_preserves_critical_evidence():
    now = datetime.now(timezone.utc)
    stale_time = now - timedelta(hours=48)

    # 48 hours old Honeytoken alert (half-life = 24h)
    ht_alert = StandardAlert(
        alert_id="alt_ht_stale",
        event_id="evt_ht",
        detector=AlertDetector.HONEYTOKEN,
        category=AlertCategory.DECEPTION,
        severity=AlertSeverity.CRITICAL,
        confidence=0.98,
        timestamp=stale_time,
        title="Canary Decoy Activated",
        evidence={"masked_honeytoken": "HONE...921"},
        recommended_action="Quarantine"
    )

    decayed_score, decayed_tier, explanations = calculate_decayed_risk(
        [ht_alert],
        reference_time=now,
        half_life_hours=24.0
    )

    # Must preserve honeytoken protection floor of 40.0
    assert decayed_score >= 40.0
    assert any("preservation floor" in str(e).lower() for e in explanations)
