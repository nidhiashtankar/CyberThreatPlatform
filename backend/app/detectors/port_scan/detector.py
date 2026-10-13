"""
Port-Scan Detection Module
Owner: Radhika
Description: Analyzes synthetic network connection events within a sliding time window.
Detects horizontal and vertical port scanning behavior with deduplication.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set
import uuid
from collections import defaultdict, deque
from app.core.config import settings
from app.schemas.alert import StandardAlert, AlertCategory, AlertDetector, AlertSeverity
from app.schemas.event import SecurityEvent


class ConnectionRecord:
    def __init__(self, timestamp: datetime, target_ip: str, port: int, protocol: str):
        self.timestamp = timestamp
        self.target_ip = target_ip
        self.port = port
        self.protocol = protocol


class PortScanDetector:
    def __init__(
        self,
        port_threshold: int = settings.PORT_SCAN_PORT_THRESHOLD,
        window_seconds: int = settings.PORT_SCAN_WINDOW_SECONDS
    ):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        
        # Track connections per source_ip
        self.ip_connections: Dict[str, deque[ConnectionRecord]] = defaultdict(deque)
        
        # Track alert suppression window per source_ip
        self.alerted_ips: Dict[str, datetime] = {}

    def _clean_stale_connections(self, history: deque, current_time: datetime):
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        while history and history[0].timestamp < cutoff:
            history.popleft()

    def process_event(self, event: SecurityEvent) -> Optional[StandardAlert]:
        """
        Process synthetic connection event and detect port scanning.
        """
        if event.event_type not in ("network_connection", "connection_attempt", "port_scan_event"):
            return None

        source_ip = event.source_ip
        if not source_ip:
            return None

        # Extract destination port and target IP
        target = event.target or event.evidence.get("destination_ip") or "target_host"
        port = event.evidence.get("destination_port") or event.evidence.get("port")
        protocol = str(event.evidence.get("protocol", "TCP")).upper()

        try:
            port = int(port) if port is not None else 0
        except (ValueError, TypeError):
            port = 0

        if port <= 0:
            return None

        event_time = event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        record = ConnectionRecord(event_time, str(target), port, protocol)

        history = self.ip_connections[source_ip]
        self._clean_stale_connections(history, event_time)
        history.append(record)

        # Unique destination ports targeted
        distinct_ports = {c.port for c in history}
        distinct_targets = {c.target_ip for c in history}

        if len(distinct_ports) >= self.port_threshold or len(distinct_targets) >= self.port_threshold:
            # Check deduplication window: suppress re-alerting the same IP within the active window
            last_alert_time = self.alerted_ips.get(source_ip)
            if last_alert_time and (event_time - last_alert_time).total_seconds() < self.window_seconds:
                return None
            self.alerted_ips[source_ip] = event_time

            scanned_ports_sample = sorted(list(distinct_ports))[:15]
            scanned_targets_sample = list(distinct_targets)[:5]

            severity = AlertSeverity.HIGH if len(distinct_ports) >= 25 else AlertSeverity.MEDIUM
            confidence = min(0.95, 0.75 + (0.02 * len(distinct_ports)))

            return StandardAlert(
                alert_id=f"alt_scan_{uuid.uuid4().hex[:8]}",
                event_id=event.event_id,
                detector=AlertDetector.PORT_SCAN,
                category=AlertCategory.RECONNAISSANCE,
                severity=severity,
                confidence=round(confidence, 4),
                source_ip=source_ip,
                user_id=event.user_id,
                target=f"{len(distinct_targets)} host(s) ({', '.join(scanned_targets_sample)})",
                timestamp=event_time,
                title=f"Port Reconnaissance Detected: {len(distinct_ports)} Ports Probed by {source_ip}",
                evidence={
                    "rule_matched": "DISTINCT_PORTS_THRESHOLD_EXCEEDED",
                    "source_ip": source_ip,
                    "distinct_ports_count": len(distinct_ports),
                    "distinct_targets_count": len(distinct_targets),
                    "probed_ports_sample": scanned_ports_sample,
                    "probed_targets_sample": scanned_targets_sample,
                    "window_seconds": self.window_seconds,
                    "threshold": self.port_threshold
                },
                recommended_action=(
                    f"Isolate or apply firewall throttling to source IP '{source_ip}'. "
                    "Review external perimeter logs for targeted services."
                )
            )

        return None

    def reset(self):
        """Reset state for clean testing."""
        self.ip_connections.clear()
        self.alerted_ips.clear()


port_scan_detector = PortScanDetector()
