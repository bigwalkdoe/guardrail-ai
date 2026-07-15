"""
Celery Configuration and Task Queue.
Handles async background tasks for email, SIEM, scanning, and reporting.
"""

import logging
from datetime import timedelta
from typing import Any, Optional

from celery import Celery
from celery.schedules import crontab

from app.config import settings

logger = logging.getLogger(__name__)


def get_celery_app() -> Celery:
    """Create and configure Celery application."""
    celery_app = Celery(
        "guardrail_ai",
        broker=settings.CELERY_BROKER_URL or settings.REDIS_URL,
        backend=settings.CELERY_RESULT_BACKEND or settings.REDIS_URL,
        include=[
            "app.tasks.alerts",
            "app.tasks.scanning",
            "app.tasks.reports",
            "app.tasks.siem",
            "app.tasks.maintenance",
        ],
    )

    # Configure Celery
    celery_app.conf.update(
        # Timezone
        timezone="UTC",
        enable_utc=True,
        # Task settings
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_track_started=True,
        task_time_limit=3600,  # 1 hour max
        task_soft_time_limit=3000,  # 50 minutes soft limit
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=4,
        # Result settings
        result_expires=86400,  # 24 hours
        result_extended=True,
        # Broker settings
        broker_connection_retry_on_startup=True,
        broker_connection_retry=True,
        broker_connection_max_retries=10,
        # Task routes
        task_routes={
            "app.tasks.alerts.*": {"queue": "alerts"},
            "app.tasks.scanning.*": {"queue": "scanning"},
            "app.tasks.reports.*": {"queue": "reports"},
            "app.tasks.siem.*": {"queue": "siem"},
            "app.tasks.maintenance.*": {"queue": "maintenance"},
        },
        # Beat schedule for periodic tasks
        beat_schedule={
            # SIEM event forwarding every minute
            "siem-forward-pending": {
                "task": "app.tasks.siem.forward_pending_events",
                "schedule": 60.0,
                "args": (),
            },
            # Vulnerability scan schedule (daily at 2 AM)
            "daily-vulnerability-scan": {
                "task": "app.tasks.scanning.schedule_vulnerability_scan",
                "schedule": crontab(hour=2, minute=0),
                "args": (),
            },
            # Attack simulation (weekly on Sunday at 3 AM)
            "weekly-attack-simulation": {
                "task": "app.tasks.scanning.schedule_attack_simulation",
                "schedule": crontab(day_of_week=0, hour=3, minute=0),
                "args": (),
            },
            # Alert cleanup (daily at 4 AM)
            "cleanup-resolved-alerts": {
                "task": "app.tasks.maintenance.cleanup_resolved_alerts",
                "schedule": crontab(hour=4, minute=0),
                "args": (),
            },
            # Cache warming (every hour)
            "warm-cache": {
                "task": "app.tasks.maintenance.warm_cache",
                "schedule": 3600.0,
                "args": (),
            },
            # Security metrics aggregation (every 5 minutes)
            "aggregate-metrics": {
                "task": "app.tasks.reports.aggregate_security_metrics",
                "schedule": 300.0,
                "args": (),
            },
            # Threat intel update (every 6 hours)
            "update-threat-intel": {
                "task": "app.tasks.scanning.update_threat_intel",
                "schedule": crontab(hour="*/6"),
                "args": (),
            },
            # Database backups
            "backup-database-daily": {
                "task": "app.tasks.backup.backup_database_daily",
                "schedule": crontab(hour=1, minute=30),
                "args": (),
            },
            "backup-database-weekly": {
                "task": "app.tasks.backup.backup_database_weekly",
                "schedule": crontab(day_of_week=0, hour=2, minute=0),
                "args": (),
            },
            "backup-database-monthly": {
                "task": "app.tasks.backup.backup_database_monthly",
                "schedule": crontab(day_of_month=1, hour=3, minute=0),
                "args": (),
            },
            # Neo4j backup (daily at 4 AM)
            "backup-neo4j": {
                "task": "app.tasks.backup.backup_neo4j",
                "schedule": crontab(hour=4, minute=0),
                "args": (),
            },
            # Redis backup (every 6 hours)
            "backup-redis": {
                "task": "app.tasks.backup.backup_redis",
                "schedule": crontab(hour="*/6", minute=30),
                "args": (),
            },
            # Audit log cleanup (daily at 5 AM)
            "audit-log-cleanup": {
                "task": "app.tasks.backup.audit_log_retention_cleanup",
                "schedule": crontab(hour=5, minute=0),
                "args": (),
            },
        },
    )

    return celery_app


# Global Celery app instance
celery_app = get_celery_app()


# =============================================================================
# Task Definitions
# =============================================================================


@celery_app.task(bind=True, name="health_check")
def health_check(self) -> dict:
    """Health check task for worker monitoring."""
    return {
        "status": "healthy",
        "worker": self.request.hostname,
    }


@celery_app.task(bind=True, name="echo")
def echo_task(self, message: str) -> str:
    """Simple echo task for testing."""
    return f"Echo: {message}"
