"""
Incident Narrative Generation Service
Description: Constructs explainable, fact-based markdown narratives for security incidents.
Synthesizes chronological event progression, contributing detectors, entity links,
risk score derivation, tactical containment advice, and investigative uncertainties.
"""
from datetime import datetime
from typing import List, Dict, Any, TYPE_CHECKING
from app.schemas.alert import StandardAlert

if TYPE_CHECKING:
    from app.db.models import IncidentModel


def generate_incident_narrative(incident: Any, alerts: List[StandardAlert]) -> str:
    """
    Generate an explainable, factual narrative covering the 7 mandatory SOC reporting sections.
    """
    if not alerts:
        return "No alerts currently associated with this incident record."

    # 1. Sort alerts chronologically
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    first_time = sorted_alerts[0].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    last_time = sorted_alerts[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    # 2. Contributing detectors & categories
    contributing_detectors = sorted(list({a.detector.upper() for a in sorted_alerts}))
    contributing_categories = sorted(list({a.category.replace('_', ' ').title() for a in sorted_alerts}))

    # 3. Related entities
    entities = incident.related_entities or {}
    ips = entities.get("ips", [])
    users = entities.get("users", [])
    targets = entities.get("targets", [])
    tokens = entities.get("tokens", [])
    urls = entities.get("urls", [])

    # 4. Chronological sequence bullet points
    sequence_bullets = []
    for idx, alert in enumerate(sorted_alerts, 1):
        t_str = alert.timestamp.strftime("%H:%M:%S UTC")
        src = f" from {alert.source_ip}" if alert.source_ip else ""
        tgt = f" against {alert.target}" if alert.target else ""
        usr = f" (user: {alert.user_id})" if alert.user_id else ""
        sequence_bullets.append(
            f"{idx}. **[{t_str}] [{alert.detector.upper()}]** {alert.title}{src}{tgt}{usr} "
            f"*(Severity: {alert.severity}, Confidence: {alert.confidence:.2f})*"
        )
    sequence_md = "\n".join(sequence_bullets)

    # 5. Entity correlation rationale
    entity_rationale = []
    if ips:
        entity_rationale.append(f"- **Source IP Address(es)**: {', '.join(ips)}")
    if users:
        entity_rationale.append(f"- **Targeted User Account(s)**: {', '.join(users)}")
    if targets:
        entity_rationale.append(f"- **Target Infrastructure / URIs**: {', '.join(targets)}")
    if tokens:
        entity_rationale.append(f"- **Decoy Trap / Honeytoken(s)**: {', '.join(tokens)} *(Canary trigger confirms attacker engagement)*")
    if urls:
        entity_rationale.append(f"- **Phishing Lure URL(s)**: {', '.join(urls)}")
    if len(ips) > 1:
        entity_rationale.append(
            "- **Multi-IP Activity**: Activity originated from multiple IPs. Correlation linked them "
            f"via common authentication target '{users[0] if users else 'account'}' and temporal proximity."
        )
    entity_md = "\n".join(entity_rationale) if entity_rationale else "- No specific external entities identified."

    # 6. Risk score derivation explanation
    risk_score = getattr(incident, "risk_score", 0.0)
    risk_tier = getattr(incident, "risk_tier", "Low")
    risk_reasons = getattr(incident, "risk_score_explanation", []) or []
    
    risk_bullets = []
    for r in risk_reasons[:4]:
        reason_text = r.get("reason", "")
        pts = r.get("points", 0.0)
        risk_bullets.append(f"- {reason_text}: **+{pts} pts**")
    risk_md = "\n".join(risk_bullets) if risk_bullets else "- Base severity evaluation applied."

    # 7. Recommended Response Actions
    recommended_actions = []
    for alert in sorted_alerts:
        if alert.recommended_action and alert.recommended_action not in recommended_actions:
            recommended_actions.append(alert.recommended_action)
    action_bullets = "\n".join([f"- {action}" for action in recommended_actions[:3]])

    # 8. Remaining Uncertainties
    uncertainties = [
        "- **Attacker True Origin**: Public source IP addresses may reflect VPN, Tor exit nodes, or open proxies rather than the physical attacker origin.",
        "- **Compromise Verification**: Automated alerts represent detection thresholds and signature hits. Actual unauthorized data exfiltration requires host-level forensic confirmation."
    ]
    if "honeytoken" in [a.detector.lower() for a in sorted_alerts]:
        uncertainties.append("- **Decoy Awareness**: It is unknown whether the adversary identified the honeytoken as a trap or believed it to be a valid production credential.")
    uncertainties_md = "\n".join(uncertainties)

    narrative = f"""1. EXECUTIVE SUMMARY & OBSERVATIONS
Between **{first_time}** and **{last_time}**, the automated threat platform detected **{len(alerts)} security alert(s)** spanning **{len(contributing_detectors)} detection module(s)** ({', '.join(contributing_detectors)}). The observed activities align with the following threat categories: {', '.join(contributing_categories)}.

2. CHRONOLOGICAL TIMELINE OF OBSERVED EVENTS
{sequence_md}

3. CONTRIBUTING INTELLIGENCE MODULES
The incident incorporates findings from:
- {', '.join([f'**{d}**' for d in contributing_detectors])}

4. ENTITY CORRELATION & RELATIONSHIPS
Alerts were correlated into a unified incident based on shared infrastructure and temporal continuity:
{entity_md}

5. RISK ASSESSMENT & SCORE DERIVATION
- **Assigned Risk Score**: **{risk_score}/100**
- **Risk Tier**: **{risk_tier}**
- **Key Scoring Contributors**:
{risk_md}

6. RECOMMENDED RESPONSE GUIDANCE
{action_bullets}

7. INVESTIGATIVE UNCERTAINTIES & OPERATIONAL CAVEATS
{uncertainties_md}
"""
    return narrative.strip()
