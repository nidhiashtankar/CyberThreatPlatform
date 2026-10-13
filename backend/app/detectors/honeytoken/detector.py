"""
Honeytoken / Deception Detection Module
Owner: Aastha
Description: Detects interaction with deliberately seeded decoy credentials,
synthetic API tokens, and canary resources. Generates high-confidence, critical alerts
while protecting the decoy token from exposure.
"""
from typing import Dict, Any, Optional, Set
import uuid
from app.core.config import settings
from app.core.security import mask_sensitive_token, sanitize_evidence_text
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.event import SecurityEvent


class HoneytokenDetector:
    def __init__(self, honeytokens: Optional[Set[str]] = None):
        self.honeytokens = honeytokens or settings.HONEYTOKEN_IDENTIFIERS

    def check_for_honeytoken(self, token_candidate: str) -> Optional[str]:
        """Check if any registered honeytoken is present in the token candidate."""
        if not token_candidate or not isinstance(token_candidate, str):
            return None
        
        for decoy in self.honeytokens:
            if decoy.lower() in token_candidate.lower():
                return decoy
        return None

    def process_event(self, event: SecurityEvent) -> Optional[StandardAlert]:
        """
        Process security event for honeytoken triggers.
        """
        matched_decoy = None
        decoy_type = "Synthetic Credential"

        # Check explicit honeytoken event
        if event.event_type in ("honeytoken_access", "decoy_trigger", "canary_token_alert"):
            token_val = event.evidence.get("token") or event.evidence.get("honeytoken_id") or event.target
            matched_decoy = self.check_for_honeytoken(str(token_val)) or str(token_val)
            decoy_type = event.evidence.get("decoy_type", "Canary API Token")
        else:
            # Check implicit triggers in headers, body, or credentials
            for key, val in event.evidence.items():
                if isinstance(val, str):
                    hit = self.check_for_honeytoken(val)
                    if hit:
                        matched_decoy = hit
                        decoy_type = f"Seeded Variable ({key})"
                        break

            if not matched_decoy and event.user_id:
                hit = self.check_for_honeytoken(event.user_id)
                if hit:
                    matched_decoy = hit
                    decoy_type = "Decoy Service Account"

            if not matched_decoy and event.target:
                hit = self.check_for_honeytoken(event.target)
                if hit:
                    matched_decoy = hit
                    decoy_type = "Decoy Asset / Canary URI"

        if not matched_decoy:
            return None

        masked_token = mask_sensitive_token(matched_decoy)
        source_ip = event.source_ip or "Unknown IP"
        user_id = event.user_id or "Decoy Invoker"

        evidence = {
            "decoy_type": sanitize_evidence_text(decoy_type),
            "masked_honeytoken": masked_token,
            "source_ip": source_ip,
            "targeted_resource": sanitize_evidence_text(str(event.target or "Honeytoken Trap")),
            "note": "Deception trigger activated. Honeytokens are never used in legitimate operations.",
            "access_timestamp": event.timestamp.isoformat()
        }

        return StandardAlert(
            alert_id=f"alt_decoy_{uuid.uuid4().hex[:8]}",
            event_id=event.event_id,
            detector=AlertDetector.HONEYTOKEN,
            category=AlertCategory.DECEPTION,
            severity=AlertSeverity.CRITICAL,
            confidence=0.98,
            source_ip=event.source_ip,
            user_id=event.user_id,
            target=f"Decoy Trap: {masked_token}",
            timestamp=event.timestamp,
            title=f"Deception Trigger: Honeytoken Activated by {source_ip}",
            evidence=evidence,
            recommended_action=(
                f"Immediately revoke credentials associated with '{masked_token}'. "
                f"Quarantine source IP '{source_ip}' and initiate compromised asset containment."
            )
        )


honeytoken_detector = HoneytokenDetector()
