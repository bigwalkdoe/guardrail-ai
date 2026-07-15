"""
Comprehensive Audit Logging Service.
Enterprise-grade audit trail for compliance (SOC 2, ISO 27001, HIPAA, GDPR).
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, Text, Index

from app.database import Base
from app.config import settings

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""

    # Authentication events
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    LOGIN_SAML = "login_saml"
    TOKEN_REFRESH = "token_refresh"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"

    # User management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_DISABLED = "user_disabled"
    USER_ENABLED = "user_enabled"

    # Organization
    ORG_CREATED = "org_created"
    ORG_UPDATED = "org_updated"
    ORG_DELETED = "org_deleted"

    # Asset management
    ASSET_CREATED = "asset_created"
    ASSET_UPDATED = "asset_updated"
    ASSET_DELETED = "asset_deleted"
    ASSET_SCANNED = "asset_scanned"

    # Vulnerability
    VULN_DISCOVERED = "vuln_discovered"
    VULN_UPDATED = "vuln_updated"
    VULN_RESOLVED = "vuln_resolved"
    VULN_DELETED = "vuln_deleted"
    VULN_SCAN_COMPLETED = "vuln_scan_completed"

    # Alert management
    ALERT_CREATED = "alert_created"
    ALERT_ACKNOWLEDGED = "alert_acknowledged"
    ALERT_ESCALATED = "alert_escalated"
    ALERT_RESOLVED = "alert_resolved"
    ALERT_DELETED = "alert_deleted"

    # Attack simulation
    ATTACK_SIMULATED = "attack_simulated"
    ATTACK_PATH_DISCOVERED = "attack_path_discovered"

    # Reconnaissance
    RECON_STARTED = "recon_started"
    RECON_COMPLETED = "recon_completed"

    # Threat intelligence
    THREAT_ADDED = "threat_added"
    THREAT_UPDATED = "threat_updated"
    THREAT_DELETED = "threat_deleted"

    # Reports
    REPORT_GENERATED = "report_generated"
    REPORT_EXPORTED = "report_exported"
    REPORT_DELETED = "report_deleted"

    # Integrations
    SIEM_CONFIG_UPDATED = "siem_config_updated"
    SIEM_EVENT_SENT = "siem_event_sent"
    SAML_CONFIG_UPDATED = "saml_config_updated"
    WEBHOOK_CONFIG_UPDATED = "webhook_config_updated"

    # Policy
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_DELETED = "policy_changed"
    POLICY_ENFORCED = "policy_enforced"

    # System
    CONFIG_CHANGED = "config_changed"
    BACKUP_CREATED = "backup_created"
    MAINTENANCE_STARTED = "maintenance_started"
    MAINTENANCE_COMPLETED = "maintenance_completed"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuditEvent:
    """Audit event data structure."""

    event_type: AuditEventType
    severity: AuditSeverity = AuditSeverity.INFO
    actor_id: Optional[int] = None
    actor_email: Optional[str] = None
    org_id: Optional[int] = None
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    description: str = ""
    changes: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    result: str = "success"


class AuditLog(Base):
    """Audit log model for database storage."""

    __tablename__ = "audit_logs"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default=AuditSeverity.INFO.value)

    actor_id = Column(Integer, nullable=True, index=True)
    actor_email = Column(String(255), nullable=True, index=True)
    org_id = Column(Integer, nullable=True, index=True)

    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True, index=True)

    description = Column(Text, nullable=True)
    changes = Column(JSON, nullable=True)
    extra_data = Column(JSON, nullable=True)

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    resource = Column(String(500), nullable=True)

    result = Column(String(20), default="success")

    timestamp = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None), index=True)

    __table_args__ = (
        Index("idx_audit_org_timestamp", "org_id", "timestamp"),
        Index("idx_audit_actor_timestamp", "actor_id", "timestamp"),
        Index("idx_audit_target_timestamp", "target_type", "target_id", "timestamp"),
        Index("idx_audit_event_timestamp", "event_type", "timestamp"),
    )


class AuditService:
    """
    Enterprise audit logging service.
    Provides comprehensive audit trail for compliance and security.
    """

    def __init__(self, db: Session):
        self.db = db

    def log(self, event: AuditEvent) -> AuditLog:
        """Log an audit event to the database."""
        audit_log = AuditLog(
            event_type=event.event_type.value,
            severity=event.severity.value,
            actor_id=event.actor_id,
            actor_email=event.actor_email,
            org_id=event.org_id,
            target_type=event.target_type,
            target_id=event.target_id,
            description=event.description,
            changes=event.changes,
            extra_data=event.metadata,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            resource=event.resource,
            result=event.result,
        )

        self.db.add(audit_log)
        self.db.commit()

        # Also send to SIEM if configured
        self._send_to_siem(event)

        logger.info(f"Audit log: {event.event_type.value} by {event.actor_email}")
        return audit_log

    def _send_to_siem(self, event: AuditEvent):
        """Forward audit event to SIEM."""
        try:
            from app.services.siem_service import SIEMService, SIEMEvent

            siem_service = SIEMService(self.db)
            siem_event = SIEMEvent(
                event_type="audit_event",
                severity=event.severity.value.lower(),
                category="audit",
                message=event.description or event.event_type.value,
                user=event.actor_email,
                action=event.event_type.value,
                outcome=event.result,
                raw_data={
                    "event_type": event.event_type.value,
                    "actor_id": event.actor_id,
                    "target_type": event.target_type,
                    "target_id": event.target_id,
                    "changes": event.changes,
                },
            )
            siem_service.send_event(siem_event)
        except Exception as e:
            logger.warning(f"Failed to send audit to SIEM: {e}")

    def log_authentication(
        self,
        event_type: AuditEventType,
        user_id: int,
        email: str,
        org_id: Optional[int],
        result: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """Log authentication event."""
        severity = AuditSeverity.HIGH if result == "failed" else AuditSeverity.INFO

        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            actor_id=user_id,
            actor_email=email,
            org_id=org_id,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Authentication {event_type.value}: {email}",
        )
        return self.log(event)

    def log_user_action(
        self,
        action: AuditEventType,
        actor_id: int,
        actor_email: str,
        target_user_id: int,
        org_id: Optional[int],
        changes: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ):
        """Log user management action."""
        event = AuditEvent(
            event_type=action,
            severity=AuditSeverity.HIGH
            if action
            in [
                AuditEventType.USER_DELETED,
                AuditEventType.USER_DISABLED,
            ]
            else AuditSeverity.MEDIUM,
            actor_id=actor_id,
            actor_email=actor_email,
            org_id=org_id,
            target_type="user",
            target_id=str(target_user_id),
            changes=changes,
            ip_address=ip_address,
            description=f"User {action.value}: {target_user_id}",
        )
        return self.log(event)

    def log_security_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        actor_id: Optional[int],
        actor_email: Optional[str],
        org_id: Optional[int],
        target_type: str,
        target_id: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Log security-related event."""
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            actor_id=actor_id,
            actor_email=actor_email,
            org_id=org_id,
            target_type=target_type,
            target_id=target_id,
            description=description,
            extra_data=metadata,
        )
        return self.log(event)

    def log_config_change(
        self,
        actor_id: int,
        actor_email: str,
        config_key: str,
        old_value: Any,
        new_value: Any,
        ip_address: Optional[str] = None,
    ):
        """Log configuration change."""
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGED,
            severity=AuditSeverity.HIGH,
            actor_id=actor_id,
            actor_email=actor_email,
            target_type="config",
            target_id=config_key,
            changes={
                "old": str(old_value)[:500],  # Truncate for storage
                "new": str(new_value)[:500],
            },
            ip_address=ip_address,
            description=f"Configuration changed: {config_key}",
        )
        return self.log(event)

    def get_audit_logs(
        self,
        org_id: Optional[int] = None,
        actor_id: Optional[int] = None,
        event_type: Optional[AuditEventType] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """Query audit logs with filters."""
        query = self.db.query(AuditLog)

        if org_id:
            query = query.filter(AuditLog.org_id == org_id)
        if actor_id:
            query = query.filter(AuditLog.actor_id == actor_id)
        if event_type:
            query = query.filter(AuditLog.event_type == event_type.value)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        if severity:
            query = query.filter(AuditLog.severity == severity.value)

        return (
            query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
        )

    def get_audit_summary(
        self,
        org_id: int,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get audit summary for reporting."""
        start_date = datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(days=days)

        # Event counts by type
        event_counts = (
            self.db.query(AuditLog.event_type, self.db.func.count(AuditLog.id))
            .filter(AuditLog.org_id == org_id, AuditLog.timestamp >= start_date)
            .group_by(AuditLog.event_type)
            .all()
        )

        # Severity counts
        severity_counts = (
            self.db.query(AuditLog.severity, self.db.func.count(AuditLog.id))
            .filter(AuditLog.org_id == org_id, AuditLog.timestamp >= start_date)
            .group_by(AuditLog.severity)
            .all()
        )

        # Failed events
        failed_count = (
            self.db.query(AuditLog)
            .filter(
                AuditLog.org_id == org_id,
                AuditLog.timestamp >= start_date,
                AuditLog.result == "failed",
            )
            .count()
        )

        return {
            "period_days": days,
            "total_events": sum(count for _, count in event_counts),
            "event_types": {event: count for event, count in event_counts},
            "severity_distribution": {sev: count for sev, count in severity_counts},
            "failed_events": failed_count,
        }

    def export_audit_logs(
        self,
        org_id: int,
        start_date: datetime,
        end_date: datetime,
        format: str = "json",
    ) -> Dict[str, Any]:
        """Export audit logs for compliance reporting."""
        logs = self.get_audit_logs(
            org_id=org_id,
            start_date=start_date,
            end_date=end_date,
            limit=10000,
        )

        export_data = []
        for log in logs:
            export_data.append(
                {
                    "timestamp": log.timestamp.isoformat(),
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "actor_email": log.actor_email,
                    "target_type": log.target_type,
                    "target_id": log.target_id,
                    "description": log.description,
                    "changes": log.changes,
                    "ip_address": log.ip_address,
                    "result": log.result,
                }
            )

        return {
            "format": format,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "record_count": len(export_data),
            "data": export_data,
        }


def audit_log(event_type: AuditEventType, **kwargs):
    """
    Decorator to automatically log audit events for functions.

    Usage:
        @audit_log(AuditEventType.USER_CREATED)
        def create_user(user_data):
            ...
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **func_kwargs):
            from app.database import get_db

            # Extract relevant info from function call
            result = func(*args, **func_kwargs)

            # Log the event
            db = next(get_db())
            audit_service = AuditService(db)

            event = AuditEvent(
                event_type=event_type,
                actor_email=kwargs.get("actor_email"),
                actor_id=kwargs.get("actor_id"),
                org_id=kwargs.get("org_id"),
                description=f"Executed {event_type.value}",
            )

            audit_service.log(event)
            return result

        return wrapper

    return decorator
