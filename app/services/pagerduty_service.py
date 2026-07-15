"""
PagerDuty Integration Service.
Provides integration with PagerDuty for alerting and incident management.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PagerDutyAlert:
    """PagerDuty alert payload."""

    title: str = ""
    severity: str = "critical"
    body: str = ""
    custom_details: Dict[str, Any] = field(default_factory=dict)
    source: str = "guardrail-ai"
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None)
    )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "routing_key": settings.PAGERDUTY_ROUTING_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": self.title,
                "severity": self.severity,
                "source": self.source,
                "timestamp": self.timestamp.isoformat(),
                "custom_details": self.custom_details,
            },
        }


class PagerDutyConfig:
    """PagerDuty configuration manager."""

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Get PagerDuty configuration."""
        return {
            "enabled": getattr(settings, "PAGERDUTY_ENABLED", False),
            "api_key": getattr(settings, "PAGERDUTY_API_KEY", ""),
            "routing_key": getattr(settings, "PAGERDUTY_ROUTING_KEY", ""),
            "service_id": getattr(settings, "PAGERDUTY_SERVICE_ID", ""),
            "integration_key": getattr(settings, "PAGERDUTY_INTEGRATION_KEY", ""),
            "retry_count": getattr(settings, "PAGERDUTY_RETRY_COUNT", 3),
            "retry_interval": getattr(settings, "PAGERDUTY_RETRY_INTERVAL", 5),
        }


class PagerDutyClient:
    """PagerDuty Events API v2 client."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token token={config.get('api_key')}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.pagerduty+json;version=2",
            }
        )
        self._event_queue: queue.Queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

    def _worker(self):
        """Background worker to process alerts."""
        while self._running:
            try:
                alert = self._event_queue.get(timeout=1)
                self._send_alert(alert)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"PagerDuty worker error: {e}")

    def _send_alert(self, alert: PagerDutyAlert) -> bool:
        """Send alert to PagerDuty."""
        retry_count = self.config.get("retry_count", 3)
        retry_interval = self.config.get("retry_interval", 5)

        payload = alert.to_payload()
        url = "https://events.pagerduty.com/v2/enqueue"

        for attempt in range(retry_count):
            try:
                response = self.session.post(url, json=payload, timeout=10)

                if response.status_code in (200, 201, 202):
                    logger.info(f"PagerDuty alert sent: {alert.title}")
                    return True
                else:
                    logger.warning(f"PagerDuty API error: {response.status_code}")
            except Exception as e:
                logger.warning(f"PagerDuty send attempt {attempt + 1} failed: {e}")

            if attempt < retry_count - 1:
                time.sleep(retry_interval)

        logger.error(f"Failed to send PagerDuty alert after {retry_count} attempts")
        return False

    def start(self):
        """Start the background worker."""
        if not self._running:
            self._running = True
            self._worker_thread = threading.Thread(target=self._worker, daemon=True)
            self._worker_thread.start()
            logger.info("PagerDuty client started")

    def stop(self):
        """Stop the background worker."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=10)
        logger.info("PagerDuty client stopped")

    def send(self, alert: PagerDutyAlert) -> bool:
        """Queue alert for sending."""
        if self._running:
            self._event_queue.put(alert)
            return True
        return False

    def send_trigger(self, title: str, severity: str = "critical", **kwargs) -> bool:
        """Send a trigger event."""
        alert = PagerDutyAlert(
            title=title,
            severity=severity,
            custom_details=kwargs,
        )
        return self.send(alert)

    def send_resolve(self, incident_key: str, title: str = "") -> bool:
        """Send a resolve event."""
        payload = {
            "routing_key": self.config.get("routing_key"),
            "event_action": "resolve",
            "incident_key": incident_key,
            "payload": {
                "summary": title or "Resolved",
                "source": "guardrail-ai",
            },
        }
        try:
            response = self.session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=10,
            )
            return response.status_code in (200, 201, 202)
        except Exception as e:
            logger.error(f"Failed to send resolve event: {e}")
            return False


class PagerDutyService:
    """Main PagerDuty integration service."""

    def __init__(self):
        self.config = PagerDutyConfig.get_config()
        self.client: Optional[PagerDutyClient] = None

        if self.config.get("enabled"):
            if self.config.get("routing_key") or self.config.get("integration_key"):
                self.client = PagerDutyClient(self.config)
            else:
                logger.warning("PagerDuty enabled but missing routing/integration key")

    def start(self):
        """Start the service."""
        if self.client:
            self.client.start()

    def stop(self):
        """Stop the service."""
        if self.client:
            self.client.stop()

    def send_alert(self, title: str, severity: str = "critical", **kwargs) -> bool:
        """Send alert to PagerDuty."""
        if self.client:
            return self.client.send_trigger(title, severity, **kwargs)
        return False

    def send_security_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send security alert."""
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
        }
        severity = severity_map.get(
            alert_data.get("severity", "medium").lower(), "warning"
        )
        return self.send_alert(
            title=alert_data.get("title", "Security Alert"),
            severity=severity,
            **alert_data,
        )

    def send_vulnerability_alert(self, vuln_data: Dict[str, Any]) -> bool:
        """Send vulnerability alert."""
        return self.send_alert(
            title=f"Vulnerability: {vuln_data.get('cve_id', 'Unknown')}",
            severity="warning",
            **vuln_data,
        )

    def send_incident(self, title: str, details: Dict[str, Any]) -> str:
        """Send incident and return incident key."""
        if self.client:
            alert = PagerDutyAlert(
                title=title,
                severity="critical",
                custom_details=details,
            )
            self.client.send(alert)
            return hashlib.md5(
                f"{title}{datetime.now(tz=timezone.utc).replace(tzinfo=None)}".encode(),
                usedforsecurity=False,
            ).hexdigest()
        return ""

    def get_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            "enabled": self.config.get("enabled"),
            "service_id": self.config.get("service_id"),
            "connected": self.client is not None and self.client._running,
        }


import hashlib
