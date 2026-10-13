import pytest
from datetime import datetime, timezone
from app.schemas.event import SecurityEvent
from app.detectors.phishing.detector import phishing_detector
from app.detectors.login.detector import login_detector
from app.detectors.port_scan.detector import port_scan_detector
from app.detectors.web_attack.detector import web_attack_detector
from app.detectors.honeytoken.detector import honeytoken_detector


def test_phishing_detector_benign_and_malicious():
    # Benign URL
    benign_res = phishing_detector.analyze_url("https://www.google.com/search?q=test")
    assert benign_res["valid"] is True
    assert benign_res["is_phishing"] is False

    # Malicious URL with IP address and sensitive keywords
    phish_res = phishing_detector.analyze_url("http://192.168.1.105/login/bank-verify.php")
    assert phish_res["valid"] is True
    assert phish_res["is_phishing"] is True
    assert phish_res["confidence"] >= 0.70
    assert "Host is a raw numerical IP address" in phish_res["evidence"]["rule_flags"]

    # Invalid URL handling
    invalid_res = phishing_detector.analyze_url("")
    assert invalid_res["valid"] is False


def test_login_threat_detector():
    login_detector.reset()

    # Step 1: 3 failed attempts (below burst threshold 5)
    for i in range(3):
        evt = SecurityEvent(
            event_id=f"evt_fail_{i}",
            event_type="login_attempt",
            timestamp=datetime.now(timezone.utc),
            source_ip="198.51.100.10",
            user_id="alice",
            evidence={"status": "failed"}
        )
        alert = login_detector.process_event(evt)
        assert alert is None

    # Step 2: 4th attempt is successful -> should trigger SUSPICIOUS_LOGIN_SEQUENCE
    succ_evt = SecurityEvent(
        event_id="evt_succ_1",
        event_type="login_attempt",
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.10",
        user_id="alice",
        evidence={"status": "success"}
    )
    alert = login_detector.process_event(succ_evt)
    assert alert is not None
    assert alert.category == "credential_access"
    assert "Suspicious Login Sequence" in alert.title
    assert alert.evidence["failed_attempts_in_window"] >= 3


def test_port_scan_detector():
    port_scan_detector.reset()

    # Send 12 connections to distinct ports
    alert = None
    for port in range(1, 13):
        evt = SecurityEvent(
            event_id=f"evt_port_{port}",
            event_type="network_connection",
            timestamp=datetime.now(timezone.utc),
            source_ip="203.0.113.5",
            target="10.0.0.1",
            evidence={"destination_ip": "10.0.0.1", "destination_port": port, "protocol": "TCP"}
        )
        res = port_scan_detector.process_event(evt)
        if res:
            alert = res

    assert alert is not None
    assert alert.category == "reconnaissance"
    assert alert.evidence["distinct_ports_count"] >= 10


def test_web_attack_detector():
    # SQLi test
    sqli_evt = SecurityEvent(
        event_id="evt_sqli_test",
        event_type="http_request",
        target="/api/items",
        source_ip="198.51.100.22",
        evidence={
            "method": "GET",
            "query_string": "id=1 UNION SELECT password FROM users--"
        }
    )
    alert_sqli = web_attack_detector.process_event(sqli_evt)
    assert alert_sqli is not None
    assert alert_sqli.category == "web_exploitation"
    assert "SQL_INJECTION" in alert_sqli.evidence["attack_type"]

    # XSS test
    xss_evt = SecurityEvent(
        event_id="evt_xss_test",
        event_type="http_request",
        target="/feedback",
        source_ip="198.51.100.22",
        evidence={
            "method": "POST",
            "body": "<script>alert('xss')</script>"
        }
    )
    alert_xss = web_attack_detector.process_event(xss_evt)
    assert alert_xss is not None
    assert alert_xss.evidence["attack_type"] == "CROSS_SITE_SCRIPTING"


def test_honeytoken_detector():
    evt = SecurityEvent(
        event_id="evt_honey_test",
        event_type="honeytoken_access",
        source_ip="198.51.100.99",
        target="canary_resource",
        evidence={
            "token": "HONEYTOKEN_AWS_DEV_KEY_9921",
            "action": "AssumeRole"
        }
    )
    alert = honeytoken_detector.process_event(evt)
    assert alert is not None
    assert alert.severity == "critical"
    assert alert.confidence >= 0.95
    # Token must be masked in evidence
    assert "HONEYTOKEN_AWS_DEV_KEY_9921" not in alert.evidence["masked_honeytoken"]
    assert "..." in alert.evidence["masked_honeytoken"]
