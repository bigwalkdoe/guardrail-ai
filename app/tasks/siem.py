"""
SIEM Tasks for Celery.
Background task processing for SIEM event forwarding.
"""

import logging
from typing import Dict, Any, List, Optional

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Alert, Vulnerability

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.tasks.siem.forward_pending_events")
def forward_pending_events(self) -> Dict[str, Any]:
    """Forward pending security events to SIEM."""
    from app.services.siem_service import SIEMService, SIEMEvent
    from app.services.cache import cache

    # Check if SIEM is enabled
    siem_status = cache.get("siem:status")
    if not siem_status:
        return {"status": "disabled", "forwarded": 0}

    db = SessionLocal()
    try:
        siem_service = SIEMService(db)
        forward_count = 0

        # Forward recent alerts
        recent_alerts = (
            db.query(Alert)
            .filter(Alert.created_at >= siem_status.get("last_forward", None))
            .limit(100)
            .all()
        )

        for alert in recent_alerts:
            siem_service.send_security_alert(
                {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "description": alert.description,
                    "source": alert.source,
                    "mitre_tactic": alert.mitre_tactic,
                    "mitre_technique": alert.mitre_technique,
                }
            )
            forward_count += 1

        # Update last forward timestamp
        from datetime import datetime, timezone

        cache.set("siem:last_forward", datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat())

        return {"status": "success", "forwarded": forward_count}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.siem.forward_vulnerability")
def forward_vulnerability(self, vuln_id: int) -> Dict[str, Any]:
    """Forward vulnerability to SIEM."""
    from app.services.siem_service import SIEMService

    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            return {"status": "error", "message": "Vulnerability not found"}

        siem_service = SIEMService(db)
        siem_service.send_vulnerability(
            {
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "description": vuln.description,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "exploit_probability": vuln.exploit_probability,
                "risk_score": vuln.risk_score,
            }
        )

        return {"status": "success", "vuln_id": vuln_id}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.siem.test_connection")
def test_siem_connection(self, provider: str) -> Dict[str, Any]:
    """Test SIEM connection."""
    from app.services.siem_service import SIEMService, SIEMProvider, SIEMEvent

    db = SessionLocal()
    try:
        siem_service = SIEMService(db)

        test_event = SIEMEvent(
            event_type="test",
            severity="low",
            category="test",
            message="Test event from Guardrail AI",
        )

        provider_enum = SIEMProvider(provider)
        if provider_enum not in siem_service._connectors:
            return {"status": "error", "message": f"Provider {provider} not enabled"}

        success = siem_service._connectors[provider_enum].send(test_event)

        return {"status": "success" if success else "error", "provider": provider}
    finally:
        db.close()
