"""
Web-Attack Detection Module
Owner: Swanandi
Description: Evaluates simulated HTTP request records against deterministic signatures
for SQL Injection (SQLi), Cross-Site Scripting (XSS), and Path Traversal.
Produces sanitized evidence to prevent secondary injection.
"""
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
import uuid
from app.core.security import sanitize_evidence_text
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.event import SecurityEvent


# Signatures compiled for fast matching
SQLI_PATTERNS = [
    (re.compile(r"(\b(UNION(\s+ALL)?\s+SELECT)\b)", re.IGNORECASE), "SQLI_UNION_SELECT"),
    (re.compile(r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?)", re.IGNORECASE), "SQLI_OR_1_EQUALS_1"),
    (re.compile(r"(\bAND\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?)", re.IGNORECASE), "SQLI_AND_1_EQUALS_1"),
    (re.compile(r"(--\s*$|/\*.*?\*/|;\s*--)", re.IGNORECASE), "SQLI_SQL_COMMENT_INJECTION"),
    (re.compile(r"(\b(DROP|ALTER|TRUNCATE)\s+TABLE\b)", re.IGNORECASE), "SQLI_SCHEMA_TAMPERING"),
    (re.compile(r"(\b(EXEC|EXECUTE)\s*\(|\bxp_cmdshell\b)", re.IGNORECASE), "SQLI_COMMAND_EXECUTION"),
    (re.compile(r"(\b(BENCHMARK|PG_SLEEP|WAITFOR\s+DELAY)\b)", re.IGNORECASE), "SQLI_TIME_BASED_BLIND"),
]

XSS_PATTERNS = [
    (re.compile(r"(<\s*script[^>]*>.*?</\s*script\s*>|<\s*script[^>]*>)", re.IGNORECASE | re.DOTALL), "XSS_SCRIPT_TAG"),
    (re.compile(r"(javascript\s*:\s*[^\s\"'>]+)", re.IGNORECASE), "XSS_JAVASCRIPT_URI"),
    (re.compile(r"(\bon(?:error|load|click|mouseover|focus|blur)\s*=)", re.IGNORECASE), "XSS_EVENT_HANDLER"),
    (re.compile(r"(document\.(?:cookie|location|domain))", re.IGNORECASE), "XSS_DOCUMENT_ACCESS"),
    (re.compile(r"(<\s*iframe[^>]*>|<\s*img[^>]+src=[^>]+onerror\s*=)", re.IGNORECASE), "XSS_EMBEDDED_FRAME_IMG"),
    (re.compile(r"(\beval\s*\(|\bwindow\[['\"]eval['\"]\])", re.IGNORECASE), "XSS_EVAL_EXECUTION"),
]

TRAVERSAL_PATTERNS = [
    (re.compile(r"(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e\/)", re.IGNORECASE), "PATH_TRAVERSAL_DOT_DOT_SLASH"),
    (re.compile(r"(/etc/(?:passwd|shadow|hosts|issue|os-release))", re.IGNORECASE), "PATH_TRAVERSAL_SENSITIVE_UNIX_FILE"),
    (re.compile(r"([a-z]:[/\\](?:windows|winnt|boot\.ini|system32))", re.IGNORECASE), "PATH_TRAVERSAL_WINDOWS_SYSTEM_FILE"),
]


class WebAttackDetector:
    def __init__(self):
        pass

    def _normalize_string(self, text: str) -> str:
        """Decode URL encoding up to 2 times to catch double-encoding bypasses."""
        if not text:
            return ""
        decoded = text
        for _ in range(2):
            try:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break
        return decoded

    def inspect_payload(self, text: str) -> List[Dict[str, str]]:
        """Scan string against all signature sets."""
        if not text:
            return []
        
        normalized = self._normalize_string(text)
        matches = []

        # Check SQLi
        for pattern, sig_name in SQLI_PATTERNS:
            found = pattern.search(normalized)
            if found:
                matches.append({
                    "attack_type": "SQL_INJECTION",
                    "signature": sig_name,
                    "matched_snippet": sanitize_evidence_text(found.group(0)[:100]),
                    "confidence": 0.90
                })

        # Check XSS
        for pattern, sig_name in XSS_PATTERNS:
            found = pattern.search(normalized)
            if found:
                matches.append({
                    "attack_type": "CROSS_SITE_SCRIPTING",
                    "signature": sig_name,
                    "matched_snippet": sanitize_evidence_text(found.group(0)[:100]),
                    "confidence": 0.88
                })

        # Check Path Traversal
        for pattern, sig_name in TRAVERSAL_PATTERNS:
            found = pattern.search(normalized)
            if found:
                matches.append({
                    "attack_type": "PATH_TRAVERSAL",
                    "signature": sig_name,
                    "matched_snippet": sanitize_evidence_text(found.group(0)[:100]),
                    "confidence": 0.92
                })

        return matches

    def process_event(self, event: SecurityEvent) -> Optional[StandardAlert]:
        """
        Process HTTP request event and return StandardAlert if signature matched.
        """
        if event.event_type not in ("http_request", "web_request", "web_attack_event", "api_call"):
            return None

        # Inspect all request components
        request_uri = event.target or event.evidence.get("uri") or event.evidence.get("path") or ""
        query_string = event.evidence.get("query_string") or event.evidence.get("params") or ""
        body = event.evidence.get("body") or event.evidence.get("payload") or ""
        headers = str(event.evidence.get("headers") or "")
        method = event.evidence.get("method", "GET")

        search_corpus = f"{request_uri} {query_string} {body} {headers}"
        matches = self.inspect_payload(search_corpus)

        if not matches:
            return None

        # Take primary highest confidence match
        primary = matches[0]
        attack_type = primary["attack_type"]
        confidence = primary["confidence"]
        
        severity = AlertSeverity.HIGH if attack_type in ("SQL_INJECTION", "PATH_TRAVERSAL") else AlertSeverity.MEDIUM
        if len(matches) > 1:
            severity = AlertSeverity.HIGH
            confidence = min(0.96, confidence + 0.05)

        title = f"Web Attack Indicator: {attack_type.replace('_', ' ').title()} Signature Matched"

        sanitized_evidence = {
            "attack_type": attack_type,
            "signature_matched": primary["signature"],
            "all_matches": matches,
            "matched_snippet": primary["matched_snippet"],
            "request_method": sanitize_evidence_text(str(method)),
            "request_uri": sanitize_evidence_text(str(request_uri)),
            "source_ip": event.source_ip,
            "disclaimer": "Signature match indicates suspicious payload; verify backend execution independently."
        }

        return StandardAlert(
            alert_id=f"alt_web_{uuid.uuid4().hex[:8]}",
            event_id=event.event_id,
            detector=AlertDetector.WEB_ATTACK,
            category=AlertCategory.WEB_EXPLOITATION,
            severity=severity,
            confidence=round(confidence, 4),
            source_ip=event.source_ip,
            user_id=event.user_id,
            target=sanitize_evidence_text(str(request_uri) or "Web Application"),
            timestamp=event.timestamp,
            title=title,
            evidence=sanitized_evidence,
            recommended_action=(
                f"Block malicious input pattern '{primary['signature']}' at Web Application Firewall (WAF). "
                f"Inspect web server logs for URI '{sanitize_evidence_text(str(request_uri))}'."
            )
        )


web_attack_detector = WebAttackDetector()
