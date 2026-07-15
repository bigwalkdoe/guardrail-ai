"""
Webhook Service.
Provides webhook management for external integrations.
"""

import json
import logging
import queue
import secrets
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import requests
from sqlalchemy.orm import Session

from app.models import Webhook

logger = logging.getLogger(__name__)


class WebhookEvent(str, Enum):
    """Webhook events."""

    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"

    ALERT_CREATED = "alert.created"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_ESCALATED = "alert.escalated"

    VULNERABILITY_FOUND = "vulnerability.found"
    VULNERABILITY_RESOLVED = "vulnerability.resolved"

    POLICY_VIOLATION = "policy.violation"

    SECURITY_SCAN_COMPLETED = "security.scan.completed"

    INTEGRATION_ENABLED = "integration.enabled"
    INTEGRATION_DISABLED = "integration.disabled"


class WebhookStatus(str, Enum):
    """Webhook status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    FAILED = "failed"


class WebhookPayload:
    """Webhook payload structure."""

    def __init__(
        self,
        event: WebhookEvent,
        data: Dict[str, Any],
        timestamp: datetime = None,
        webhook_id: int = None,
    ):
        self.event = event
        self.data = data
        self.timestamp = timestamp or datetime.now(tz=timezone.utc).replace(tzinfo=None)
        self.webhook_id = webhook_id
        self.id = secrets.token_urlsafe(16)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event": self.event.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class WebhookService:
    """Service for webhook management and delivery."""

    def __init__(self, db: Session):
        self.db = db
        self._delivery_queue: queue.Queue = queue.Queue()
        self._worker_thread = None
        self._running = False
        self._subscribers: Dict[WebhookEvent, List[Callable]] = {}

    def _sign_payload(self, payload: str, secret: str) -> str:
        """Sign webhook payload with HMAC."""
        import hashlib
        import hmac

        if not secret:
            return ""

        signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={signature}"

    def _start_worker(self):
        """Start background delivery worker."""
        if not self._running:
            self._running = True
            self._worker_thread = threading.Thread(
                target=self._delivery_worker, daemon=True
            )
            self._worker_thread.start()

    def _delivery_worker(self):
        """Background worker to deliver webhooks."""
        while self._running:
            try:
                payload, webhook, delivery_url = self._delivery_queue.get(timeout=1)
                self._deliver_webhook(payload, webhook, delivery_url)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Webhook delivery error: {e}")

    def _deliver_webhook(
        self, payload: WebhookPayload, webhook: Webhook, delivery_url: str
    ):
        """Deliver webhook to endpoint."""
        payload_str = json.dumps(payload.to_dict())

        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Event": payload.event.value,
            "X-Webhook-ID": str(payload.id),
        }

        if webhook.secret:
            signature = self._sign_payload(payload_str, webhook.secret)
            headers["X-Webhook-Signature"] = signature

        success = False

        for attempt in range(webhook.retry_count + 1):
            try:
                response = requests.post(
                    delivery_url,
                    data=payload_str,
                    headers=headers,
                    timeout=webhook.timeout,
                )

                webhook.last_status_code = response.status_code

                if response.status_code < 400:
                    success = True
                    webhook.failure_count = 0
                    break
            except requests.RequestException:
                pass

            if attempt < webhook.retry_count:
                time.sleep(webhook.retry_delay * (attempt + 1))

        if not success:
            webhook.failure_count += 1
            if webhook.failure_count >= 5:
                webhook.status = WebhookStatus.FAILED.value

        webhook.last_triggered_at = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        self.db.commit()

    def create_webhook(
        self,
        user_id: int,
        name: str,
        url: str,
        events: List[str],
        secret: Optional[str] = None,
        timeout: int = 30,
        retry_count: int = 3,
    ) -> Dict[str, Any]:
        """Create new webhook."""
        if not secret:
            secret = secrets.token_urlsafe(32)

        webhook = Webhook(
            user_id=user_id,
            name=name,
            url=url,
            secret=secret,
            events=events,
            timeout=timeout,
            retry_count=retry_count,
        )

        self.db.add(webhook)
        self.db.commit()
        self.db.refresh(webhook)

        return {
            "id": webhook.id,
            "name": webhook.name,
            "url": webhook.url,
            "events": webhook.events,
            "status": webhook.status,
            "created_at": webhook.created_at.isoformat(),
        }

    def trigger(self, event: WebhookEvent, data: Dict[str, Any]):
        """Trigger webhooks for an event."""
        payload = WebhookPayload(event=event, data=data)

        webhooks = (
            self.db.query(Webhook)
            .filter(
                Webhook.status == WebhookStatus.ACTIVE.value,
            )
            .all()
        )

        for webhook in webhooks:
            if event.value in webhook.events:
                self._delivery_queue.put((payload, webhook, webhook.url))

        if event in self._subscribers:
            for callback in self._subscribers[event]:
                try:
                    callback(payload)
                except Exception as e:
                    logger.error(f"Webhook subscriber error: {e}")

        self._start_worker()

    def subscribe(self, event: WebhookEvent, callback: Callable):
        """Subscribe to webhook events."""
        if event not in self._subscribers:
            self._subscribers[event] = []
        self._subscribers[event].append(callback)

    def list_webhooks(
        self,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List webhooks."""
        query = self.db.query(Webhook)

        if user_id:
            query = query.filter(Webhook.user_id == user_id)
        if status:
            query = query.filter(Webhook.status == status)

        webhooks = query.order_by(Webhook.created_at.desc()).all()

        return [
            {
                "id": w.id,
                "name": w.name,
                "url": w.url,
                "events": w.events,
                "status": w.status,
                "last_triggered_at": (
                    w.last_triggered_at.isoformat() if w.last_triggered_at else None
                ),
                "last_status_code": w.last_status_code,
                "failure_count": w.failure_count,
                "created_at": w.created_at.isoformat(),
            }
            for w in webhooks
        ]

    def delete_webhook(self, webhook_id: int, user_id: int) -> bool:
        """Delete webhook."""
        webhook = (
            self.db.query(Webhook)
            .filter(
                Webhook.id == webhook_id,
                Webhook.user_id == user_id,
            )
            .first()
        )

        if not webhook:
            return False

        self.db.delete(webhook)
        self.db.commit()
        return True

    def test_webhook(self, webhook_id: int) -> Dict[str, Any]:
        """Test webhook with ping event."""
        webhook = self.db.query(Webhook).filter(Webhook.id == webhook_id).first()

        if not webhook:
            raise ValueError("Webhook not found")

        payload = WebhookPayload(
            event=WebhookEvent("test.ping"),
            data={"message": "Webhook test ping"},
            webhook_id=webhook.id,
        )

        self._deliver_webhook(payload, webhook, webhook.url)

        return {
            "status": (
                "success"
                if webhook.last_status_code and webhook.last_status_code < 400
                else "failed"
            ),
            "status_code": webhook.last_status_code,
        }


# =============================================================================
# Incoming webhook verification
# =============================================================================


def verify_incoming_webhook(
    provider: str,
    body: bytes,
    headers: dict,
    secret: str,
) -> bool:
    """Verify an incoming webhook's HMAC signature.

    Supports:
      - slack  :  Slack signing secret (version=v0)
      - github :  X-Hub-Signature-256
      - generic:  X-Webhook-Signature (HMAC-SHA256 of body)
    """
    import hashlib
    import hmac

    if not secret:
        return False

    if provider == "slack":
        timestamp = headers.get("X-Slack-Request-Timestamp", "")
        sig = headers.get("X-Slack-Signature", "")
        if not timestamp or not sig:
            return False
        base = f"v0:{timestamp}:{body.decode()}"
        expected = (
            "v0=" + hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
        )
        return hmac.compare_digest(sig, expected)

    if provider == "github":
        sig = headers.get("X-Hub-Signature-256", "")
        if not sig:
            return False
        expected = (
            "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        )
        return hmac.compare_digest(sig, expected)

    if provider == "generic":
        sig = headers.get("X-Webhook-Signature", "")
        if not sig:
            return False
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)

    return False


def process_incoming_webhook(
    provider: str,
    event: str,
    payload: dict,
) -> dict:
    """Process an incoming webhook and map to internal events."""
    logger.info(f"Incoming webhook from {provider}: event={event}")

    event_map = {
        "slack": {
            "url_verification": "system.webhook.verify",
            "event_callback": "system.webhook.event",
        },
        "github": {
            "push": "code.push",
            "pull_request": "code.pull_request",
            "issues": "code.issue",
        },
    }

    mapped = event_map.get(provider, {}).get(event, f"webhook.{provider}.{event}")
    return {
        "status": "received",
        "event": event,
        "mapped_event": mapped,
        "provider": provider,
    }
