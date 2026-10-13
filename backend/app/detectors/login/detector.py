"""
Login Threat Detection Module
Owner: Nidhi
Description: Evaluates authentication events in sliding time windows.
Detects repeated authentication failures, brute-force bursts, and credential stuffing
patterns (failures followed by success) without false compromise claims.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import uuid
from collections import defaultdict, deque
from app.core.config import settings
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.event import SecurityEvent


class LoginAttemptRecord:
    def __init__(self, timestamp: datetime, status: str, user_id: Optional[str], source_ip: Optional[str]):
        self.timestamp = timestamp
        self.status = status.lower()
        self.user_id = user_id
        self.source_ip = source_ip


class LoginThreatDetector:
    def __init__(
        self,
        failed_threshold: int = settings.LOGIN_FAILED_THRESHOLD,
        window_seconds: int = settings.LOGIN_WINDOW_SECONDS
    ):
        self.failed_threshold = failed_threshold
        self.window_seconds = window_seconds
        
        # Track history per IP and per (IP, User)
        self.ip_history: Dict[str, deque[LoginAttemptRecord]] = defaultdict(deque)
        self.user_history: Dict[str, deque[LoginAttemptRecord]] = defaultdict(deque)
        
        # Track recently alerted windows to prevent redundant flooding
        self.alerted_keys: Dict[str, datetime] = {}

    def _clean_stale_records(self, history: deque, current_time: datetime):
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        while history and history[0].timestamp < cutoff:
            history.popleft()

    def process_event(self, event: SecurityEvent) -> Optional[StandardAlert]:
        """
        Process login event and detect brute-force or credential stuffing patterns.
        """
        if event.event_type not in ("login_attempt", "authentication", "auth_attempt"):
            return None

        status = str(event.evidence.get("status") or event.evidence.get("result") or "unknown").lower()
        if status not in ("failed", "success", "failure"):
            # Check if event has failure indicator
            if event.evidence.get("success") is False:
                status = "failed"
            elif event.evidence.get("success") is True:
                status = "success"
            else:
                return None

        event_time = event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        source_ip = event.source_ip or "unknown_ip"
        user_id = event.user_id or "unknown_user"

        record = LoginAttemptRecord(event_time, status, user_id, source_ip)

        # Update IP history
        ip_deque = self.ip_history[source_ip]
        self._clean_stale_records(ip_deque, event_time)
        ip_deque.append(record)

        # Update User history
        if user_id != "unknown_user":
            user_deque = self.user_history[user_id]
            self._clean_stale_records(user_deque, event_time)
            user_deque.append(record)

        # Pattern 1: Repeated failures followed by a successful login (Suspicious Authentication Sequence)
        if status == "success":
            recent_failures_ip = [r for r in ip_deque if r.status in ("failed", "failure") and r.timestamp < event_time]
            recent_failures_user = [r for r in self.user_history[user_id] if r.status in ("failed", "failure") and r.timestamp < event_time]
            
            failures_count = max(len(recent_failures_ip), len(recent_failures_user))
            if failures_count >= 3:
                # Deduplication check
                dedup_key = f"seq_{source_ip}_{user_id}"
                last_alert = self.alerted_keys.get(dedup_key)
                if last_alert and (event_time - last_alert).total_seconds() < 60:
                    return None
                self.alerted_keys[dedup_key] = event_time

                return StandardAlert(
                    alert_id=f"alt_login_seq_{uuid.uuid4().hex[:8]}",
                    event_id=event.event_id,
                    detector=AlertDetector.LOGIN,
                    category=AlertCategory.CREDENTIAL_ACCESS,
                    severity=AlertSeverity.HIGH,
                    confidence=0.88,
                    source_ip=source_ip if source_ip != "unknown_ip" else None,
                    user_id=user_id if user_id != "unknown_user" else None,
                    target=event.target or "Authentication Service",
                    timestamp=event_time,
                    title=f"Suspicious Login Sequence: {failures_count} Failures Followed by Success",
                    evidence={
                        "rule_matched": "FAILED_ATTEMPTS_FOLLOWED_BY_SUCCESS",
                        "failed_attempts_in_window": failures_count,
                        "window_seconds": self.window_seconds,
                        "source_ip": source_ip,
                        "targeted_account": user_id,
                        "subsequent_status": "success",
                        "note": "Potential brute-force or credential stuffing success requiring immediate verification."
                    },
                    recommended_action=(
                        f"Review session activity for user '{user_id}' from IP '{source_ip}'. "
                        "Require MFA or prompt for immediate password change."
                    )
                )

        # Pattern 2: High volume of failed attempts (Brute Force Burst)
        if status in ("failed", "failure"):
            failed_attempts = [r for r in ip_deque if r.status in ("failed", "failure")]
            failed_count = len(failed_attempts)
            
            if failed_count >= self.failed_threshold:
                dedup_key = f"burst_{source_ip}"
                last_alert = self.alerted_keys.get(dedup_key)
                if last_alert and (event_time - last_alert).total_seconds() < 60:
                    return None
                self.alerted_keys[dedup_key] = event_time

                targeted_users = list({r.user_id for r in failed_attempts if r.user_id})

                return StandardAlert(
                    alert_id=f"alt_login_burst_{uuid.uuid4().hex[:8]}",
                    event_id=event.event_id,
                    detector=AlertDetector.LOGIN,
                    category=AlertCategory.CREDENTIAL_ACCESS,
                    severity=AlertSeverity.MEDIUM if failed_count < 10 else AlertSeverity.HIGH,
                    confidence=0.85,
                    source_ip=source_ip if source_ip != "unknown_ip" else None,
                    user_id=user_id if user_id != "unknown_user" else None,
                    target=event.target or "Authentication Service",
                    timestamp=event_time,
                    title=f"Repeated Authentication Failures ({failed_count} attempts)",
                    evidence={
                        "rule_matched": "EXCESSIVE_FAILED_LOGINS",
                        "failed_count": failed_count,
                        "threshold": self.failed_threshold,
                        "window_seconds": self.window_seconds,
                        "source_ip": source_ip,
                        "targeted_users": targeted_users
                    },
                    recommended_action=(
                        f"Temporarily rate-limit or challenge IP '{source_ip}' via CAPTCHA. "
                        "Monitor authentication service for distributed attempts."
                    )
                )

        return None

    def reset(self):
        """Reset state for clean testing."""
        self.ip_history.clear()
        self.user_history.clear()
        self.alerted_keys.clear()


login_detector = LoginThreatDetector()
