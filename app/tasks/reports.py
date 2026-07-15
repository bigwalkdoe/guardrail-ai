"""
Report Tasks for Celery.
Background task processing for report generation and metrics aggregation.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from app.celery_app import celery_app
from app.database import SessionLocal

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.tasks.reports.generate_compliance_report")
def generate_compliance_report(
    self, org_id: int, report_type: str = "monthly"
) -> Dict[str, Any]:
    """Generate compliance report for organization."""
    db = SessionLocal()
    try:
        from app.services.reporting import ReportingService

        service = ReportingService(db)

        result = service.generate_compliance_report(org_id, report_type)

        return {
            "status": "success",
            "org_id": org_id,
            "report_type": report_type,
            "file_path": result.get("file_path"),
        }
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.reports.export_audit_logs")
def export_audit_logs(
    self, org_id: int, start_date: str, end_date: str, format: str = "csv"
) -> Dict[str, Any]:
    """Export audit logs to file."""
    from app.services.reporting import ReportingService

    db = SessionLocal()
    try:
        service = ReportingService(db)

        result = service.export_audit_logs(
            org_id=org_id, start_date=start_date, end_date=end_date, format=format
        )

        return {
            "status": "success",
            "file_path": result.get("file_path"),
            "record_count": result.get("record_count"),
        }
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.reports.aggregate_security_metrics")
def aggregate_security_metrics(self, org_id: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate security metrics for reporting."""
    from app.services.cache import cache

    db = SessionLocal()
    try:
        from app.models import Asset, Vulnerability, Alert

        # Get counts
        asset_count = db.query(Asset).count()
        vuln_count = db.query(Vulnerability).count()
        critical_vulns = (
            db.query(Vulnerability).filter(Vulnerability.severity == "critical").count()
        )
        open_alerts = db.query(Alert).filter(Alert.status == "open").count()

        metrics = {
            "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            "assets": asset_count,
            "vulnerabilities": vuln_count,
            "critical_vulnerabilities": critical_vulns,
            "open_alerts": open_alerts,
        }

        # Cache for dashboard
        cache.set("metrics:security", metrics, ttl=300)

        return {"status": "success", "metrics": metrics}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.reports.generate_vulnerability_report")
def generate_vulnerability_report(self, org_id: int) -> Dict[str, Any]:
    """Generate vulnerability report."""
    from app.services.reporting import ReportingService

    db = SessionLocal()
    try:
        service = ReportingService(db)
        result = service.generate_vulnerability_report(org_id)

        return {
            "status": "success",
            "org_id": org_id,
            "file_path": result.get("file_path"),
        }
    finally:
        db.close()
