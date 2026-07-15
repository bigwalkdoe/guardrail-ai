"""
Google Chronicle Integration Service.
Provides integration with Google Chronicle for security analytics and log management.
"""

import logging
import threading
import queue
import hashlib
import hmac
import base64
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

import requests

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ChronicleEvent:
    """Chronicle event data."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    event_type: str = "security_event"
    source: str = "guardrail-ai"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    outcome: str = "success"
    severity: str = "medium"
    category: str = "general"
    message: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

    def to_udm_dict(self) -> Dict[str, Any]:
        """Convert to UDM (Unified Data Model) format."""
        return {
            "metadata": {
                "event_timestamp": self.timestamp.isoformat() + "Z",
                "event_type": self.event_type,
                "product_name": "Guardrail AI",
                "product_version": "1.0.0",
                "collector": self.source,
            },
            "network": {
                "application_protocol": "tcp",
            },
            "security": {
                "severity": self.severity.upper(),
            },
            "principal": {
                "user": {"userid": self.user} if self.user else {},
            },
            "target": {
                "ip": self.destination_ip,
            },
            "src": {
                "ip": self.source_ip,
            },
            "intermediary": {
                "ip": self.source_ip,
            },
            "metadata": {
                "description": self.message,
                "product_log_id": hashlib.md5(
                    f"{self.timestamp}{self.event_type}".encode()
                ).hexdigest(),
            },
        }


class ChronicleConfig:
    """Chronicle configuration manager."""

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Get Chronicle configuration."""
        return {
            "enabled": getattr(settings, "CHRONICLE_ENABLED", False),
            "customer_id": getattr(settings, "CHRONICLE_CUSTOMER_ID", ""),
            "api_key": getattr(settings, "CHRONICLE_API_KEY", ""),
            "region": getattr(settings, "CHRONICLE_REGION", "us"),
            "batch_size": getattr(settings, "CHRONICLE_BATCH_SIZE", 50),
        }

    @staticmethod
    def get_api_url() -> str:
        """Get Chronicle API endpoint."""
        region = getattr(settings, "CHRONICLE_REGION", "us")
        region_map = {
            "us": "https://api.chronicle.security",
            "eu": "https://europe-api.chronicle.security",
            "asia": "https://asia-api.chronicle.security",
        }
        base_url = region_map.get(region, region_map["us"])
        customer_id = getattr(settings, "CHRONICLE_CUSTOMER_ID", "")
        return f"{base_url}/v1/customers/{customer_id}/assets"


class ChronicleConnector:
    """Google Chronicle API connector."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"ApiKey {config.get('api_key')}",
                "Content-Type": "application/json",
            }
        )
        self._event_queue: queue.Queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

    def _worker(self):
        """Background worker to batch events."""
        batch: List[Dict[str, Any]] = []
        batch_size = self.config.get("batch_size", 50)

        while self._running:
            try:
                event = self._event_queue.get(timeout=1)
                batch.append(event)

                if len(batch) >= batch_size:
                    self._send_batch(batch)
                    batch = []
            except queue.Empty:
                if batch:
                    self._send_batch(batch)
                    batch = []
            except Exception as e:
                logger.error(f"Chronicle worker error: {e}")

    def _send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send batch of events to Chronicle."""
        try:
            url = ChronicleConfig.get_api_url()
            payload = {"assets": events}

            response = self.session.post(
                url,
                json=payload,
                timeout=30,
            )

            if response.status_code in (200, 201, 202):
                logger.info(f"Sent {len(events)} events to Chronicle")
                return True
            else:
                logger.error(
                    f"Chronicle API error: {response.status_code} - {response.text}"
                )
                return False
        except Exception as e:
            logger.error(f"Failed to send to Chronicle: {e}")
            return False

    def start(self):
        """Start the background worker."""
        if not self._running:
            self._running = True
            self._worker_thread = threading.Thread(target=self._worker, daemon=True)
            self._worker_thread.start()
            logger.info("Chronicle connector started")

    def stop(self):
        """Stop the background worker."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=10)
        logger.info("Chronicle connector stopped")

    def send(self, event: ChronicleEvent) -> bool:
        """Queue event for sending."""
        if self._running:
            self._event_queue.put(event.to_udm_dict())
            return True
        return False


class ChronicleService:
    """Main Chronicle integration service."""

    def __init__(self):
        self.config = ChronicleConfig.get_config()
        self.connector: Optional[ChronicleConnector] = None

        if self.config.get("enabled"):
            if self.config.get("api_key") and self.config.get("customer_id"):
                self.connector = ChronicleConnector(self.config)
            else:
                logger.warning("Chronicle enabled but missing API key or customer ID")

    def start(self):
        """Start the service."""
        if self.connector:
            self.connector.start()

    def stop(self):
        """Stop the service."""
        if self.connector:
            self.connector.stop()

    def send_event(self, event: ChronicleEvent) -> bool:
        """Send event to Chronicle."""
        if self.connector:
            return self.connector.send(event)
        return False

    def send_security_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send security alert."""
        event = ChronicleEvent(
            event_type="security_alert",
            severity=alert_data.get("severity", "medium"),
            category="alert",
            message=alert_data.get("title", "Security Alert"),
            user=alert_data.get("user"),
            action=alert_data.get("action"),
            raw_data=alert_data,
            mitre_technique=alert_data.get("mitre_technique"),
            mitre_tactic=alert_data.get("mitre_tactic"),
        )
        return self.send_event(event)

    def send_auth_event(self, auth_data: Dict[str, Any]) -> bool:
        """Send authentication event."""
        event = ChronicleEvent(
            event_type="authentication",
            severity=auth_data.get("severity", "low"),
            category="authentication",
            message=auth_data.get("message", "Auth event"),
            user=auth_data.get("user"),
            action=auth_data.get("action"),
            outcome=auth_data.get("outcome", "success"),
            source_ip=auth_data.get("source_ip"),
        )
        return self.send_event(event)

    def get_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            "enabled": self.config.get("enabled"),
            "region": self.config.get("region"),
            "customer_id": self.config.get("customer_id"),
            "connected": self.connector is not None and self.connector._running,
        }
