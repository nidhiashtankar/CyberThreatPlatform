from typing import List
from app.schemas.event import SecurityEvent
from app.schemas.alert import StandardAlert
from app.detectors.phishing.detector import phishing_detector
from app.detectors.login.detector import login_detector
from app.detectors.port_scan.detector import port_scan_detector
from app.detectors.web_attack.detector import web_attack_detector
from app.detectors.honeytoken.detector import honeytoken_detector


def dispatch_event_to_detectors(event: SecurityEvent) -> List[StandardAlert]:
    """
    Evaluate an incoming SecurityEvent across all relevant detection modules.
    Returns any alerts generated.
    """
    alerts: List[StandardAlert] = []

    # 1. Honeytoken check (runs universally on any event that might touch a decoy)
    try:
        ht_alert = honeytoken_detector.process_event(event)
        if ht_alert:
            alerts.append(ht_alert)
    except Exception as e:
        print(f"Error in HoneytokenDetector: {e}")

    # 2. Login threat detector
    if event.event_type in ("login_attempt", "authentication", "auth_attempt"):
        try:
            log_alert = login_detector.process_event(event)
            if log_alert:
                alerts.append(log_alert)
        except Exception as e:
            print(f"Error in LoginThreatDetector: {e}")

    # 3. Port scan detector
    if event.event_type in ("network_connection", "connection_attempt", "port_scan_event"):
        try:
            scan_alert = port_scan_detector.process_event(event)
            if scan_alert:
                alerts.append(scan_alert)
        except Exception as e:
            print(f"Error in PortScanDetector: {e}")

    # 4. Web attack detector
    if event.event_type in ("http_request", "web_request", "web_attack_event", "api_call"):
        try:
            web_alert = web_attack_detector.process_event(event)
            if web_alert:
                alerts.append(web_alert)
        except Exception as e:
            print(f"Error in WebAttackDetector: {e}")

    # 5. Phishing detector
    if event.event_type in ("url_submission", "phishing_url") or "url" in event.evidence:
        try:
            phish_alert = phishing_detector.process_event(event)
            if phish_alert:
                alerts.append(phish_alert)
        except Exception as e:
            print(f"Error in PhishingDetector: {e}")

    return alerts
