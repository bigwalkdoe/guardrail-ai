"""
Alert Tasks for Celery.
Background task processing for security alerts and notifications.
"""

import logging
from typing import Dict, Any, List, Optional

from celery import Task
from pydantic import BaseModel

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Alert, User

logger = logging.getLogger(__name__)


class AlertNotification(BaseModel):
    """Alert notification model."""

    alert_id: int
    title: str
    severity: str
    message: str
    recipient_email: str
    channel: str = "email"  # email, slack, webhook


@celery_app.task(bind=True, name="app.tasks.alerts.send_alert_notification")
def send_alert_notification(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send alert notification via configured channels.

    Supports: Email, Slack, Webhook
    """
    from app.services.alerts import AlertService

    try:
        alert_service = AlertService()
        result = alert_service.send_notification(alert_data)

        logger.info(f"Alert notification sent: {alert_data.get('title')}")
        return {"status": "success", "alert_id": alert_data.get("alert_id")}

    except Exception as e:
        logger.error(f"Failed to send alert notification: {e}")
        self.retry(exc=e, countdown=60, max_retries=3)


@celery_app.task(bind=True, name="app.tasks.alerts.process_alert_batch")
def process_alert_batch(self, alert_ids: List[int]) -> Dict[str, Any]:
    """Process a batch of alerts."""
    from app.services.alerts import AlertService

    db = SessionLocal()
    try:
        alert_service = AlertService(db)
        processed = 0
        failed = 0

        for alert_id in alert_ids:
            try:
                alert = db.query(Alert).filter(Alert.id == alert_id).first()
                if alert:
                    alert_service.process_alert(alert)
                    processed += 1
            except Exception as e:
                logger.error(f"Failed to process alert {alert_id}: {e}")
                failed += 1

        return {"processed": processed, "failed": failed, "total": len(alert_ids)}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.alerts.escalate_critical_alerts")
def escalate_critical_alerts(self, org_id: Optional[int] = None) -> Dict[str, Any]:
    """Escalate critical alerts that haven't been addressed."""
    from app.services.alerts import AlertService

    db = SessionLocal()
    try:
        alert_service = AlertService(db)
        escalated = alert_service.escalate_unhandled_alerts(org_id)

        logger.info(f"Escalated {escalated} critical alerts")
        return {"escalated": escalated}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.alerts.send_digest")
def send_digest(self, user_id: int, period: str = "daily") -> Dict[str, Any]:
    """Send periodic security digest to user."""
    from app.services.alerts import AlertService

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"status": "error", "message": "User not found"}

        alert_service = AlertService(db)
        result = alert_service.send_digest(user, period)

        return {"status": "success", "recipients": 1}
    finally:
        db.close()
