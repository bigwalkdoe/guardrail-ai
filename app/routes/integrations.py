"""
Integration Routes.
SIEM and external integration configuration endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List

from app.database import get_db
from app.models import User
from app.security import get_current_user, require_admin
from app.services.siem_service import SIEMService, SIEMConfig, SIEMEvent
from app.services.saml_service import SAMLConfig

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/siem/status")
def siem_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get SIEM integration status."""
    siem_service = SIEMService(db)
    return siem_service.get_status()


@router.get("/siem/config")
def siem_config(current_user: User = Depends(require_admin)):
    """Get SIEM configuration (without secrets)."""
    config = SIEMConfig()

    return {
        "splunk": {
            "enabled": config.get_splunk_config().get("enabled"),
            "hec_url": config.get_splunk_config().get("hec_url"),
            "index": config.get_splunk_config().get("index"),
            "source": config.get_splunk_config().get("source"),
        },
        "qradar": {
            "enabled": config.get_qradar_config().get("enabled"),
            "host": config.get_qradar_config().get("host"),
            "port": config.get_qradar_config().get("port"),
            "protocol": config.get_qradar_config().get("protocol"),
        },
        "syslog": {
            "enabled": config.get_syslog_config().get("enabled"),
            "host": config.get_syslog_config().get("host"),
            "port": config.get_syslog_config().get("port"),
            "protocol": config.get_syslog_config().get("protocol"),
            "facility": config.get_syslog_config().get("facility"),
        },
        "elastic": {
            "enabled": config.get_elastic_config().get("enabled"),
            "url": config.get_elastic_config().get("url"),
            "index_prefix": config.get_elastic_config().get("index_prefix"),
        },
        "azure_sentinel": {
            "enabled": config.get_azure_sentinel_config().get("enabled"),
            "workspace_id": config.get_azure_sentinel_config().get("workspace_id"),
            "log_type": config.get_azure_sentinel_config().get("log_type"),
        },
    }


@router.post("/siem/test/{provider}")
def test_siem_connection(
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Test SIEM connection for a specific provider."""
    from app.services.siem_service import SIEMProvider

    siem_service = SIEMService(db)

    test_event = SIEMEvent(
        event_type="test",
        severity="low",
        category="test",
        message="Test event from Guardrail AI SIEM integration",
    )

    try:
        provider_enum = SIEMProvider(provider)
        if provider_enum not in siem_service._connectors:
            raise HTTPException(
                status_code=400, detail=f"Provider {provider} is not enabled"
            )

        success = siem_service._connectors[provider_enum].send(test_event)

        return {
            "provider": provider,
            "success": success,
            "message": "Test event sent successfully"
            if success
            else "Failed to send test event",
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")


@router.post("/siem/test-all")
def test_all_siem(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Test all enabled SIEM connections."""
    siem_service = SIEMService(db)

    test_event = SIEMEvent(
        event_type="test",
        severity="low",
        category="test",
        message="Test event from Guardrail AI SIEM integration",
    )

    results = {}
    for provider, connector in siem_service._connectors.items():
        try:
            success = connector.send(test_event)
            results[provider.value] = {
                "success": success,
                "message": "OK" if success else "Failed",
            }
        except Exception as e:
            results[provider.value] = {"success": False, "message": str(e)}

    return results


@router.post("/siem/send-alert")
def send_siem_alert(
    alert_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Manually send alert to SIEM."""
    siem_service = SIEMService(db)

    success = siem_service.send_security_alert(alert_data)

    return {
        "success": success,
        "message": "Alert queued for SIEM forwarding"
        if success
        else "No SIEM providers enabled",
    }


@router.get("/saml/status")
def saml_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get SAML/SSO configuration status."""
    config = SAMLConfig(db)
    validation = config.validate_config()

    from app.config import settings

    return {
        "saml_enabled": settings.SAML_ENABLED,
        "configured": validation.get("configured", False),
        "valid": validation.get("valid", False),
        "errors": validation.get("errors", []),
        "idp": {
            "entity_id": settings.SAML_IDP_ENTITY_ID,
            "sso_url": settings.SAML_IDP_SSO_URL,
        },
        "sp": {
            "entity_id": settings.SAML_SP_ENTITY_ID,
            "acs_url": settings.SAML_SP_ACS_URL,
        },
    }


@router.get("/cloudwatch/status")
def cloudwatch_status(current_user: User = Depends(get_current_user)):
    """Get AWS CloudWatch integration status."""
    from app.services.cloudwatch_service import CloudWatchService

    service = CloudWatchService()
    return service.get_status()


@router.post("/cloudwatch/test")
def test_cloudwatch(current_user: User = Depends(require_admin)):
    """Test AWS CloudWatch connection."""
    from app.services.cloudwatch_service import CloudWatchService

    service = CloudWatchService()
    success = service.send_log("Test log from Guardrail AI", "INFO")

    return {"success": success, "message": "Test log sent" if success else "Failed"}


@router.get("/chronicle/status")
def chronicle_status(current_user: User = Depends(get_current_user)):
    """Get Google Chronicle integration status."""
    from app.services.chronicle_service import ChronicleService

    service = ChronicleService()
    return service.get_status()


@router.post("/chronicle/test")
def test_chronicle(current_user: User = Depends(require_admin)):
    """Test Google Chronicle connection."""
    from app.services.chronicle_service import ChronicleService, ChronicleEvent

    service = ChronicleService()
    event = ChronicleEvent(
        event_type="test",
        severity="low",
        category="test",
        message="Test event from Guardrail AI",
    )
    success = service.send_event(event)

    return {"success": success, "message": "Test event sent" if success else "Failed"}


@router.get("/pagerduty/status")
def pagerduty_status(current_user: User = Depends(get_current_user)):
    """Get PagerDuty integration status."""
    from app.services.pagerduty_service import PagerDutyService

    service = PagerDutyService()
    return service.get_status()


@router.post("/pagerduty/test")
def test_pagerduty(current_user: User = Depends(require_admin)):
    """Test PagerDuty connection."""
    from app.services.pagerduty_service import PagerDutyService

    service = PagerDutyService()
    success = service.send_alert(
        title="Test Alert from Guardrail AI",
        severity="info",
        test_mode=True,
    )

    return {"success": success, "message": "Test alert sent" if success else "Failed"}


@router.get("/ldap/status")
def ldap_status(current_user: User = Depends(get_current_user)):
    """Get LDAP/AD integration status."""
    from app.services.ldap_service import LDAPService

    service = LDAPService()
    return service.get_status()


@router.post("/ldap/test")
def test_ldap(current_user: User = Depends(require_admin)):
    """Test LDAP connection."""
    from app.services.ldap_service import LDAPService

    service = LDAPService()
    status = service.get_status()

    return {
        "success": status.get("connected", False),
        "message": "Connected to LDAP" if status.get("connected") else "Not connected",
    }


@router.get("/ldap/users")
def ldap_search_users(
    filter: str = "", limit: int = 100, current_user: User = Depends(require_admin)
):
    """Search LDAP users."""
    from app.services.ldap_service import LDAPService

    service = LDAPService()
    users = service.search_users(filter, limit)

    return [
        {
            "username": u.username,
            "email": u.email,
            "display_name": u.display_name,
            "groups": u.groups,
            "enabled": u.enabled,
        }
        for u in users
    ]


@router.get("/vault/status")
def vault_status(current_user: User = Depends(get_current_user)):
    """Get Vault integration status."""
    from app.services.vault_service import VaultService

    service = VaultService()
    return service.get_status()


@router.post("/vault/test")
def test_vault(current_user: User = Depends(require_admin)):
    """Test Vault connection."""
    from app.services.vault_service import VaultService

    service = VaultService()
    status = service.get_status()

    return {
        "success": status.get("connected", False),
        "message": "Connected to Vault" if status.get("connected") else "Not connected",
    }
