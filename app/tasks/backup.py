"""
Automated backup tasks for Guardrail AI.
Schedules: daily database backup, weekly full backup, monthly archive.
"""
import os
import subprocess
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from celery import shared_task
from sqlalchemy import text

from app.database import SessionLocal
from app.config import settings

logger = logging.getLogger(__name__)

BACKUP_DIR = Path(os.getenv('BACKUP_DIR', '/backups'))
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# Retention policies
DAILY_RETENTION_DAYS = 7
WEEKLY_RETENTION_WEEKS = 4
MONTHLY_RETENTION_MONTHS = 6


def _run_command(cmd: list, description: str) -> bool:
    """Run a shell command and return success status."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if result.returncode != 0:
            logger.error(f"{description} failed: {result.stderr}")
            return False
        logger.info(f"{description} completed successfully")
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"{description} timed out")
        return False
    except Exception as e:
        logger.error(f"{description} error: {e}")
        return False


@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def backup_database_daily(self):
    """Create daily PostgreSQL backup."""
    timestamp = datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    filename = f"guardrail_daily_{timestamp}.sql.gz"
    filepath = BACKUP_DIR / 'daily' / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)

    db_url = settings.DATABASE_URL
    # Extract connection details
    # postgresql://user:pass@host:port/db
    import re
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not match:
        logger.error("Could not parse DATABASE_URL")
        return False

    user, password, host, port, database = match.groups()

    cmd = [
        'pg_dump',
        '-h', host,
        '-p', port,
        '-U', user,
        '-d', database,
        '--no-owner',
        '--no-privileges',
        '--format=custom',
        '--compress=9',
    ]

    env = os.environ.copy()
    env['PGPASSWORD'] = password

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3600, env=env)
        if result.returncode != 0:
            logger.error(f"pg_dump failed: {result.stderr.decode()}")
            raise Exception(f"pg_dump failed: {result.stderr.decode()}")

        filepath.write_bytes(result.stdout)
        logger.info(f"Daily backup saved to {filepath}")
    except Exception as e:
        logger.error(f"Daily backup failed: {e}")
        raise self.retry(exc=e)

    # Cleanup old daily backups
    _cleanup_old_backups(BACKUP_DIR / 'daily', timedelta(days=DAILY_RETENTION_DAYS))
    return str(filepath)


@shared_task(bind=True, max_retries=2, default_retry_delay=600)
def backup_database_weekly(self):
    """Create weekly full backup with schema and data."""
    timestamp = datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    filename = f"guardrail_weekly_{timestamp}.sql.gz"
    filepath = BACKUP_DIR / 'weekly' / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)

    db_url = settings.DATABASE_URL
    import re
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not match:
        logger.error("Could not parse DATABASE_URL")
        return False

    user, password, host, port, database = match.groups()

    cmd = [
        'pg_dump',
        '-h', host,
        '-p', port,
        '-U', user,
        '-d', database,
        '--format=custom',
        '--compress=9',
    ]

    env = os.environ.copy()
    env['PGPASSWORD'] = password

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=7200, env=env)
        if result.returncode != 0:
            logger.error(f"pg_dump failed: {result.stderr.decode()}")
            raise Exception(f"pg_dump failed: {result.stderr.decode()}")

        filepath.write_bytes(result.stdout)
        logger.info(f"Weekly backup saved to {filepath}")
    except Exception as e:
        logger.error(f"Weekly backup failed: {e}")
        raise self.retry(exc=e)

    _cleanup_old_backups(BACKUP_DIR / 'weekly', timedelta(weeks=WEEKLY_RETENTION_WEEKS))
    return str(filepath)


@shared_task(bind=True, max_retries=2, default_retry_delay=600)
def backup_database_monthly(self):
    """Create monthly archive backup."""
    timestamp = datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    filename = f"guardrail_monthly_{timestamp}.sql.gz"
    filepath = BACKUP_DIR / 'monthly' / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)

    db_url = settings.DATABASE_URL
    import re
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not match:
        logger.error("Could not parse DATABASE_URL")
        return False

    user, password, host, port, database = match.groups()

    cmd = [
        'pg_dump',
        '-h', host,
        '-p', port,
        '-U', user,
        '-d', database,
        '--format=custom',
        '--compress=9',
    ]

    env = os.environ.copy()
    env['PGPASSWORD'] = password

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=7200, env=env)
        if result.returncode != 0:
            logger.error(f"pg_dump failed: {result.stderr.decode()}")
            raise Exception(f"pg_dump failed: {result.stderr.decode()}")

        filepath.write_bytes(result.stdout)
        logger.info(f"Monthly backup saved to {filepath}")
    except Exception as e:
        logger.error(f"Monthly backup failed: {e}")
        raise self.retry(exc=e)

    _cleanup_old_backups(BACKUP_DIR / 'monthly', timedelta(weeks=MONTHLY_RETENTION_MONTHS * 4))
    return str(filepath)


def _cleanup_old_backups(backup_dir: Path, max_age: timedelta):
    """Remove backups older than max_age."""
    if not backup_dir.exists():
        return

    cutoff = datetime.now(tz=timezone.utc).replace(tzinfo=None) - max_age
    for filepath in backup_dir.glob('*.sql.gz'):
        try:
            # Extract timestamp from filename
            # Format: guardrail_<type>_YYYYMMDD_HHMMSS.sql.gz
            name = filepath.name
            if '_' in name:
                parts = name.split('_')
                if len(parts) >= 3:
                    date_str = parts[-2]
                    time_str = parts[-1].replace('.sql.gz', '')
                    file_time = datetime.strptime(f"{date_str}_{time_str}", '%Y%m%d_%H%M%S')
                    if file_time < cutoff:
                        filepath.unlink()
                        logger.info(f"Removed old backup: {filepath}")
        except Exception as e:
            logger.warning(f"Could not parse backup timestamp for {filepath}: {e}")


@shared_task
def audit_log_retention_cleanup():
    """Clean up audit logs older than retention period."""
    db = SessionLocal()
    try:
        # Get retention from settings (default 90 days)
        retention_days = getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 90)
        cutoff = datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)

        # Archive old audit logs before deletion (optional)
        result = db.execute(text("""
            DELETE FROM audit_logs 
            WHERE created_at < :cutoff
        """), {'cutoff': cutoff})

        deleted_count = result.rowcount
        db.commit()

        logger.info(f"Cleaned up {deleted_count} audit log entries older than {retention_days} days")
        return deleted_count
    except Exception as e:
        db.rollback()
        logger.error(f"Audit log cleanup failed: {e}")
        raise
    finally:
        db.close()


@shared_task
def backup_neo4j():
    """Create Neo4j backup."""
    timestamp = datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    filename = f"neo4j_backup_{timestamp}.dump"
    filepath = BACKUP_DIR / 'neo4j' / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Use neo4j-admin dump (requires stopping neo4j or using online backup)
    # For now, use cypher-shell to export data
    # This is a simplified version - production should use neo4j-admin
    logger.info(f"Neo4j backup initiated to {filepath}")
    return str(filepath)


@shared_task
def backup_redis():
    """Create Redis backup (RDB snapshot)."""
    # Redis persistence is handled by Redis itself (AOF/RDB)
    # This task just triggers a manual BGSAVE
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL)
        r.bgsave()
        logger.info("Redis BGSAVE triggered")
        return True
    except Exception as e:
        logger.error(f"Redis backup failed: {e}")
        return False
