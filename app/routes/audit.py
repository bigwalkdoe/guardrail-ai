"""
Audit Logs API Routes.
Endpoints for querying and exporting audit logs.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel

from app.database import get_db
from app.security import get_current_user, require_admin
from app.models import User
from app.services.audit import AuditService, AuditLog, AuditEventType, AuditSeverity

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    severity: str
    actor_id: Optional[int]
    actor_email: Optional[str]
    org_id: Optional[int]
    target_type: Optional[str]
    target_id: Optional[str]
    description: Optional[str]
    ip_address: Optional[str]
    result: str
    timestamp: datetime

    class Config:
        from_attributes = True


class AuditSummaryResponse(BaseModel):
    period_days: int
    total_events: int
    event_types: dict
    severity_distribution: dict
    failed_events: int


@router.get("/logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    org_id: Optional[int] = None,
    actor_id: Optional[int] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get audit logs with filters."""
    audit_service = AuditService(db)

    event_type_enum = None
    if event_type:
        try:
            event_type_enum = AuditEventType(event_type)
        except:
            pass

    severity_enum = None
    if severity:
        try:
            severity_enum = AuditSeverity(severity)
        except:
            pass

    logs = audit_service.get_audit_logs(
        org_id=org_id,
        actor_id=actor_id,
        event_type=event_type_enum,
        start_date=start_date,
        end_date=end_date,
        severity=severity_enum,
        limit=limit,
        offset=offset,
    )

    return logs


@router.get("/summary", response_model=AuditSummaryResponse)
def get_audit_summary(
    org_id: int,
    days: int = Query(30, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Get audit summary for reporting."""
    audit_service = AuditService(db)
    summary = audit_service.get_audit_summary(org_id=org_id, days=days)
    return summary


@router.post("/export")
def export_audit_logs(
    org_id: int,
    start_date: datetime,
    end_date: datetime,
    format: str = Query("json", regex="^(json|csv)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Export audit logs for compliance reporting."""
    audit_service = AuditService(db)
    export_data = audit_service.export_audit_logs(
        org_id=org_id,
        start_date=start_date,
        end_date=end_date,
        format=format,
    )

    if format == "csv":
        import io
        import csv

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "timestamp",
                "event_type",
                "severity",
                "actor_email",
                "target_type",
                "target_id",
                "description",
                "ip_address",
                "result",
            ],
        )
        writer.writeheader()

        for record in export_data["data"]:
            writer.writerow(record)

        return {
            "format": "csv",
            "data": output.getvalue(),
            "record_count": export_data["record_count"],
        }

    return export_data


@router.get("/event-types")
def get_event_types():
    """Get list of available event types."""
    return {"event_types": [e.value for e in AuditEventType]}


@router.get("/severities")
def get_severities():
    """Get list of severity levels."""
    return {"severities": [s.value for s in AuditSeverity]}
