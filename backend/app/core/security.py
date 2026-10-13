import html
import re
from typing import Any, Dict


def sanitize_evidence_text(text: str) -> str:
    """
    Sanitize text evidence to prevent XSS and injection attacks.
    Escapes HTML entities and strips non-printable control characters.
    """
    if not isinstance(text, str):
        return str(text)
    
    # Strip dangerous null bytes and raw control characters
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    # HTML escape
    return html.escape(cleaned, quote=True)


def mask_sensitive_token(token: str) -> str:
    """
    Safely mask honeytokens or sensitive secrets before returning in API or logs.
    Shows only the first 4 and last 3 characters if length > 8.
    """
    if not token or len(token) <= 8:
        return "[REDACTED_SECRET]"
    return f"{token[:4]}...{token[-3:]}"


def sanitize_dict_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively sanitize dictionary values for safe frontend rendering.
    """
    sanitized = {}
    for k, v in data.items():
        if isinstance(v, str):
            sanitized[k] = sanitize_evidence_text(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_dict_evidence(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_evidence_text(item) if isinstance(item, str)
                else (sanitize_dict_evidence(item) if isinstance(item, dict) else item)
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized
