"""
Phishing URL Detection Module
Owner: Aastha
Description: Analyzes submitted URLs using Random Forest feature classification
and explainable lexical heuristics. Produces standardized alerts.
"""
from typing import Dict, Any, Optional, Tuple
import uuid
import numpy as np
from app.detectors.phishing.features import extract_url_features
from app.detectors.phishing.model import get_phishing_model
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.event import SecurityEvent


class PhishingDetector:
    def __init__(self):
        self.model = None

    def _ensure_model(self):
        if self.model is None:
            self.model = get_phishing_model()

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Safely analyze a URL without opening or connecting to it.
        Returns prediction, confidence, and feature evidence.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return {
                "valid": False,
                "is_phishing": False,
                "confidence": 0.0,
                "error": "Empty or invalid URL provided",
                "evidence": {}
            }

        url = url.strip()
        try:
            extraction = extract_url_features(url)
            features = extraction["features"]
            feat_vector = extraction["feature_vector"]
            evidence = extraction["evidence"]

            self._ensure_model()
            X = np.array([feat_vector])
            pred_class = int(self.model.predict(X)[0])
            pred_proba = self.model.predict_proba(X)[0]
            confidence = float(pred_proba[pred_class])

            # Explainable rule-based corroboration
            rule_flags = []
            if features["has_ip_in_url"]:
                rule_flags.append("Host is a raw numerical IP address")
            if features["has_suspicious_tld"]:
                rule_flags.append(f"Suspicious or high-risk TLD detected")
            if features["keyword_count"] >= 2:
                rule_flags.append(f"Multiple credential/authentication keywords ({', '.join(evidence['matched_keywords'])})")
            if features["entropy"] > 4.2:
                rule_flags.append(f"High domain entropy ({features['entropy']}), possible algorithmic generation")
            if "@" in url:
                rule_flags.append("URL contains '@' symbol, possible credential obfuscation")

            # Corroborate ML with rule indicators
            is_phishing = bool(pred_class == 1 or len(rule_flags) >= 2)
            if is_phishing and confidence < 0.65:
                confidence = max(confidence, 0.70 + (0.05 * len(rule_flags)))
                confidence = min(0.98, confidence)

            evidence["rule_flags"] = rule_flags
            evidence["model_prediction"] = "phishing" if pred_class == 1 else "legitimate"
            evidence["ml_confidence"] = round(float(pred_proba[1]), 4)

            return {
                "valid": True,
                "url": url,
                "is_phishing": is_phishing,
                "confidence": round(confidence, 4),
                "features": features,
                "evidence": evidence
            }
        except Exception as e:
            return {
                "valid": False,
                "is_phishing": False,
                "confidence": 0.0,
                "error": f"URL analysis error: {str(e)}",
                "evidence": {"raw_url": url}
            }

    def process_event(self, event: SecurityEvent) -> Optional[StandardAlert]:
        """
        Process a security event (e.g. url_submission or event with url in evidence).
        Returns a StandardAlert if phishing is detected, or None otherwise.
        """
        target_url = None
        if event.event_type in ("url_submission", "phishing_url"):
            target_url = event.target or event.evidence.get("url")
        elif "url" in event.evidence:
            target_url = event.evidence.get("url")

        if not target_url:
            return None

        result = self.analyze_url(target_url)
        if not result["valid"] or not result["is_phishing"]:
            return None

        confidence = result["confidence"]
        if confidence >= 0.85:
            severity = AlertSeverity.HIGH
        elif confidence >= 0.70:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        alert = StandardAlert(
            alert_id=f"alt_phish_{uuid.uuid4().hex[:8]}",
            event_id=event.event_id,
            detector=AlertDetector.PHISHING,
            category=AlertCategory.INITIAL_ACCESS,
            severity=severity,
            confidence=confidence,
            source_ip=event.source_ip,
            user_id=event.user_id,
            target=target_url,
            timestamp=event.timestamp,
            title=f"Suspicious Phishing URL Identified: {result['evidence']['hostname'] or target_url[:30]}",
            evidence=result["evidence"],
            recommended_action=(
                f"Block domain '{result['evidence'].get('hostname', 'target')}' on web gateways and "
                "search mail logs for incoming links containing this URL."
            )
        )
        return alert


phishing_detector = PhishingDetector()
