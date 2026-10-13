import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".club", ".work", ".icu", ".cam", ".vip", ".fit"
}

SENSITIVE_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "banking",
    "signin", "password", "wallet", "confirm", "security", "auth",
    "invoice", "recover", "authenticate", "portal", "support"
]

IP_PATTERN = re.compile(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract lexical, structural, and entropy features from a URL.
    Returns both a dictionary of features and raw values.
    """
    if not url.startswith(("http://", "https://")):
        # Normalise for parsing
        parse_target = "http://" + url
    else:
        parse_target = url

    try:
        parsed = urlparse(parse_target)
        netloc = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        netloc = ""
        path = ""
        query = ""

    hostname = netloc.split(":")[0].lower() if ":" in netloc else netloc.lower()

    # Feature metrics
    url_len = len(url)
    domain_len = len(hostname)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    at_count = url.count("@")
    digit_count = sum(c.isdigit() for c in url)
    subdomains = max(0, len(hostname.split(".")) - 2) if hostname else 0
    has_ip = 1 if bool(IP_PATTERN.match(url) or re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname)) else 0
    has_suspicious_tld = 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    
    keyword_matches = [kw for kw in SENSITIVE_KEYWORDS if kw in url.lower()]
    keyword_count = len(keyword_matches)
    
    entropy = calculate_entropy(hostname)
    has_https = 1 if url.lower().startswith("https://") else 0
    query_len = len(query)

    feature_dict = {
        "url_length": url_len,
        "domain_length": domain_len,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_count": at_count,
        "digit_count": digit_count,
        "subdomain_count": subdomains,
        "has_ip_in_url": has_ip,
        "has_suspicious_tld": has_suspicious_tld,
        "keyword_count": keyword_count,
        "entropy": entropy,
        "has_https": has_https,
        "query_length": query_len,
    }

    evidence = {
        "url": url,
        "hostname": hostname,
        "matched_keywords": keyword_matches,
        "has_ip_address": bool(has_ip),
        "suspicious_tld": bool(has_suspicious_tld),
        "domain_entropy": entropy,
        "subdomains": subdomains
    }

    return {
        "features": feature_dict,
        "feature_vector": [
            url_len, domain_len, dot_count, hyphen_count, at_count,
            digit_count, subdomains, has_ip, has_suspicious_tld,
            keyword_count, entropy, has_https, query_len
        ],
        "evidence": evidence
    }
