import logging
from datetime import datetime, timezone, timedelta

from celery import shared_task
from sqlalchemy import text

from app.database import SessionLocal
from app.config import settings

logger = logging.getLogger(__name__)


@shared_task(name="app.tasks.maintenance.cleanup_resolved_alerts")
def cleanup_resolved_alerts(days=30):
    """Clean up resolved alerts older than specified days."""
    pass


@shared_task(name="app.tasks.maintenance.warm_cache")
def warm_cache():
    """Warm up cache with frequently accessed data."""
    pass


@shared_task(name="app.tasks.maintenance.enforce_audit_retention")
def enforce_audit_retention():
    """Enforce audit log and token retention policies."""
    db = SessionLocal()
    try:
        retention_days = settings.AUDIT_LOG_RETENTION_DAYS
        cutoff = datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)

        # Clean old password reset tokens
        expired_tokens = db.execute(
            text("DELETE FROM password_reset_tokens WHERE expires_at < :cutoff OR used = true"),
            {"cutoff": cutoff},
        )
        token_count = expired_tokens.rowcount

        # Clean old MFA settings for deleted users
        orphaned_mfa = db.execute(
            text(
                "DELETE FROM user_mfa_settings WHERE user_id NOT IN (SELECT id FROM users)"
            )
        )
        mfa_count = orphaned_mfa.rowcount

        db.commit()
        logger.info(
            f"Retention cleanup: removed {token_count} expired reset tokens, "
            f"{mfa_count} orphaned MFA settings"
        )
        return {
            "status": "completed",
            "expired_tokens_removed": token_count,
            "orphaned_mfa_removed": mfa_count,
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Retention cleanup failed: {e}")
        return {"status": "failed", "error": str(e)}
    finally:
        db.close()
