"""
SIEM Integration Service.
Provides integration with Security Information and Event Management platforms.
Supports Splunk, QRadar, ArcSight, and generic syslog/CEF formats.
"""

import json
import logging
import queue
import socket
import ssl
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import requests

from sqlalchemy.orm import Session

from app.config import settings

logger = logging.getLogger(__name__)


class SIEMProvider(Enum):
    """Supported SIEM platforms."""

    SPLUNK = "splunk"
    QRADAR = "qradar"
    ARCSIGHT = "arcSight"
    SYSLOG = "syslog"
    CEF = "cef"
    JSON = "json"
    ELASTIC = "elastic"
    Azure_SENTINEL = "azure_sentinel"


@dataclass
class SIEMEvent:
    """Standardized security event for SIEM integration."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    event_type: str = "security_event"
    source: str = "guardrail-ai"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    outcome: str = "success"
    severity: str = "medium"
    category: str = "general"
    message: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    MitreTechnique: Optional[str] = None
    MitreTactic: Optional[str] = None
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "action": self.action,
            "outcome": self.outcome,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "mitre_technique": self.MitreTechnique,
            "mitre_tactic": self.MitreTactic,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "raw_data": self.raw_data,
        }


class SIEMConfig:
    """SIEM configuration manager."""

    @staticmethod
    def get_splunk_config() -> Dict[str, Any]:
        """Get Splunk configuration."""
        return {
            "enabled": getattr(settings, "SIEM_SPLUNK_ENABLED", False),
            "hec_url": getattr(settings, "SIEM_SPLUNK_HEC_URL", ""),
            "hec_token": getattr(settings, "SIEM_SPLUNK_HEC_TOKEN", ""),
            "index": getattr(settings, "SIEM_SPLUNK_INDEX", "main"),
            "source": getattr(settings, "SIEM_SPLUNK_SOURCE", "guardrail-ai"),
            "sourcetype": getattr(
                settings, "SIEM_SPLUNK_SOURCETYPE", "guardrail:security"
            ),
            "verify_ssl": getattr(settings, "SIEM_SPLUNK_VERIFY_SSL", True),
        }

    @staticmethod
    def get_qradar_config() -> Dict[str, Any]:
        """Get QRadar configuration."""
        return {
            "enabled": getattr(settings, "SIEM_QRADAR_ENABLED", False),
            "host": getattr(settings, "SIEM_QRADAR_HOST", ""),
            "port": getattr(settings, "SIEM_QRADAR_PORT", 514),
            "protocol": getattr(settings, "SIEM_QRADAR_PROTOCOL", "tcp"),
            "log_source_id": getattr(settings, "SIEM_QRADAR_LOG_SOURCE_ID", ""),
        }

    @staticmethod
    def get_arcsight_config() -> Dict[str, Any]:
        """Get ArcSight configuration."""
        return {
            "enabled": getattr(settings, "SIEM_ARCSIGHT_ENABLED", False),
            "host": getattr(settings, "SIEM_ARCSIGHT_HOST", ""),
            "port": getattr(settings, "SIEM_ARCSIGHT_PORT", 514),
            "cert_path": getattr(settings, "SIEM_ARCSIGHT_CERT", ""),
            "key_path": getattr(settings, "SIEM_ARCSIGHT_KEY", ""),
        }

    @staticmethod
    def get_syslog_config() -> Dict[str, Any]:
        """Get syslog configuration."""
        return {
            "enabled": getattr(settings, "SIEM_SYSLOG_ENABLED", False),
            "host": getattr(settings, "SIEM_SYSLOG_HOST", ""),
            "port": getattr(settings, "SIEM_SYSLOG_PORT", 514),
            "protocol": getattr(settings, "SIEM_SYSLOG_PROTOCOL", "udp"),
            "facility": getattr(settings, "SIEM_SYSLOG_FACILITY", "local0"),
            "format": getattr(settings, "SIEM_SYSLOG_FORMAT", "rfc5424"),
        }

    @staticmethod
    def get_elastic_config() -> Dict[str, Any]:
        """Get Elasticsearch configuration."""
        return {
            "enabled": getattr(settings, "SIEM_ELASTIC_ENABLED", False),
            "url": getattr(settings, "SIEM_ELASTIC_URL", ""),
            "api_key": getattr(settings, "SIEM_ELASTIC_API_KEY", ""),
            "index_prefix": getattr(
                settings, "SIEM_ELASTIC_INDEX_PREFIX", "guardrail-"
            ),
            "index_suffix": getattr(settings, "SIEM_ELASTIC_INDEX_SUFFIX", "events"),
            "verify_ssl": getattr(settings, "SIEM_ELASTIC_VERIFY_SSL", True),
        }

    @staticmethod
    def get_azure_sentinel_config() -> Dict[str, Any]:
        """Get Azure Sentinel configuration."""
        return {
            "enabled": getattr(settings, "SIEM_AZURE_SENTINEL_ENABLED", False),
            "workspace_id": getattr(settings, "SIEM_AZURE_WORKSPACE_ID", ""),
            "shared_key": getattr(settings, "SIEM_AZURE_SHARED_KEY", ""),
            "log_type": getattr(settings, "SIEM_AZURE_LOG_TYPE", "GuardrailAI"),
        }

    def get_enabled_providers(self) -> List[str]:
        """Get list of enabled SIEM providers."""
        providers = []

        if self.get_splunk_config().get("enabled"):
            providers.append(SIEMProvider.SPLUNK.value)
        if self.get_qradar_config().get("enabled"):
            providers.append(SIEMProvider.QRADAR.value)
        if self.get_arcsight_config().get("enabled"):
            providers.append(SIEMProvider.ARCSIGHT.value)
        if self.get_syslog_config().get("enabled"):
            providers.append(SIEMProvider.SYSLOG.value)
        if self.get_elastic_config().get("enabled"):
            providers.append(SIEMProvider.ELASTIC.value)
        if self.get_azure_sentinel_config().get("enabled"):
            providers.append(SIEMProvider.Azure_SENTINEL.value)

        return providers


class SplunkConnector:
    """Splunk HEC (HTTP Event Collector) connector."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Splunk {config.get('hec_token')}",
                "Content-Type": "application/json",
            }
        )

    def send(self, event: SIEMEvent) -> bool:
        """Send event to Splunk via HEC."""
        payload = {
            "time": event.timestamp.timestamp(),
            "host": event.source,
            "source": self.config.get("source"),
            "sourcetype": self.config.get("sourcetype"),
            "index": self.config.get("index"),
            "event": event.to_dict(),
        }

        try:
            response = self.session.post(
                self.config.get("hec_url"),
                json=payload,
                verify=self.config.get("verify_ssl", True),
                timeout=10,
            )
            return response.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Failed to send to Splunk: {e}")
            return False

    def send_batch(self, events: List[SIEMEvent]) -> int:
        """Send batch of events to Splunk."""
        success_count = 0
        for event in events:
            if self.send(event):
                success_count += 1
        return success_count


class QRadarConnector:
    """QRadar syslog connector."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def _format_cef(self, event: SIEMEvent) -> str:
        """Format event as CEF for QRadar."""
        device_product = "Guardrail AI"
        device_version = "1.0.0"
        device_event_class_id = event.event_type
        name = event.message or event.event_type
        severity = (
            str(min(int(event.severity) * 2, 10)) if event.severity.isdigit() else "5"
        )

        extensions = []
        if event.source_ip:
            extensions.append(f"src={event.source_ip}")
        if event.destination_ip:
            extensions.append(f"dst={event.destination_ip}")
        if event.user:
            extensions.append(f"suser={event.user}")
        if event.action:
            extensions.append(f"act={event.action}")
        if event.MitreTechnique:
            extensions.append(f"cn1={event.MitreTechnique}")

        ext_str = " ".join(extensions)

        return f"CEF:0|{device_product}|{device_version}|{device_event_class_id}|{name}|{severity}|{ext_str}"

    def send(self, event: SIEMEvent) -> bool:
        """Send event to QRadar via syslog."""
        cef_message = self._format_cef(event)

        try:
            if self.config.get("protocol") == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.connect((self.config.get("host"), self.config.get("port", 514)))
            sock.send(cef_message.encode("utf-8"))
            sock.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send to QRadar: {e}")
            return False


class SyslogConnector:
    """Generic syslog connector."""

    FACILITY_MAP = {
        "local0": 16,
        "local1": 17,
        "local2": 18,
        "local3": 19,
        "local4": 20,
        "local5": 21,
        "local6": 22,
        "local7": 23,
    }

    SEVERITY_MAP = {
        "emergency": 0,
        "alert": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "notice": 5,
        "info": 6,
        "debug": 7,
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.facility = self.FACILITY_MAP.get(config.get("facility", "local0"), 16)

    def _format_rfc5424(self, event: SIEMEvent) -> str:
        """Format as RFC 5424 syslog message."""
        severity = self.SEVERITY_MAP.get(event.severity.lower(), 6)
        priority = (self.facility * 8) + severity

        timestamp = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
        hostname = event.source
        app_name = "guardrail-ai"
        proc_id = "1"
        msg_id = event.event_type[:32]
        structured_data = "-"

        message = json.dumps(event.to_dict())

        return f"<{priority}>{timestamp} {hostname} {app_name} {proc_id} {msg_id} {structured_data} {message}"

    def _format_rfc3164(self, event: SIEMEvent) -> str:
        """Format as RFC 3164 syslog message."""
        timestamp = event.timestamp.strftime("%b %d %H:%M:%S")
        hostname = event.source
        message = f"guardrail-ai: {event.message or event.event_type}"

        return f"<{self.facility * 8 + 6}>{timestamp} {hostname} {message}"

    def send(self, event: SIEMEvent) -> bool:
        """Send event via syslog."""
        fmt = self.config.get("format", "rfc5424")
        message = (
            self._format_rfc5424(event)
            if fmt == "rfc5424"
            else self._format_rfc3164(event)
        )

        try:
            if self.config.get("protocol") == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.connect((self.config.get("host"), self.config.get("port", 514)))
            sock.send(message.encode("utf-8"))
            sock.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send syslog: {e}")
            return False


class ElasticConnector:
    """Elasticsearch connector."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        if config.get("api_key"):
            self.session.headers.update(
                {
                    "Authorization": f"ApiKey {config.get('api_key')}",
                    "Content-Type": "application/json",
                }
            )

    def _get_index(self) -> str:
        date_suffix = datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime("%Y.%m.%d")
        return f"{self.config.get('index_prefix')}guardrail-{self.config.get('index_suffix')}-{date_suffix}"

    def send(self, event: SIEMEvent) -> bool:
        """Send event to Elasticsearch."""
        try:
            index = self._get_index()
            response = self.session.post(
                f"{self.config.get('url')}/{index}/_doc",
                json=event.to_dict(),
                verify=self.config.get("verify_ssl", True),
                timeout=10,
            )
            return response.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Failed to send to Elasticsearch: {e}")
            return False


class AzureSentinelConnector:
    """Azure Sentinel (Log Analytics) connector."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.workspace_id = config.get("workspace_id")
        self.shared_key = config.get("shared_key")
        self.log_type = config.get("log_type", "GuardrailAI")

    def _build_signature(self, date: str, content_length: int) -> str:
        """Build Azure API signature."""
        import hmac
        import base64

        string_to_sign = (
            f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
        )

        key_bytes = base64.b64decode(self.shared_key)
        encoded_string = string_to_sign.encode("utf-8")

        signature = hmac.new(key_bytes, encoded_string, digestmod="sha256").digest()
        return base64.b64encode(signature).decode("utf-8")

    def send(self, event: SIEMEvent) -> bool:
        """Send event to Azure Sentinel."""
        try:
            import json

            date = datetime.now(tz=timezone.utc).replace(tzinfo=None).strftime("%a, %d %b %Y %H:%M:%S GMT")
            content = json.dumps([event.to_dict()])
            content_length = len(content)

            signature = self._build_signature(date, content_length)

            url = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

            headers = {
                "Content-Type": "application/json",
                "Log-Type": self.log_type,
                "x-ms-date": date,
                "x-ms-signature": signature,
            }

            response = requests.post(url, data=content, headers=headers, timeout=10)

            return response.status_code in (200, 201, 202)
        except Exception as e:
            logger.error(f"Failed to send to Azure Sentinel: {e}")
            return False


class SIEMService:
    """
    Main SIEM integration service.
    Handles event forwarding to multiple SIEM platforms.
    """

    def __init__(self, db: Session):
        self.db = db
        self.config = SIEMConfig()
        self._connectors = {}
        self._init_connectors()
        self._event_queue: queue.Queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False

    def _init_connectors(self):
        """Initialize enabled SIEM connectors."""
        splunk_cfg = self.config.get_splunk_config()
        if splunk_cfg.get("enabled"):
            self._connectors[SIEMProvider.SPLUNK] = SplunkConnector(splunk_cfg)

        qradar_cfg = self.config.get_qradar_config()
        if qradar_cfg.get("enabled"):
            self._connectors[SIEMProvider.QRADAR] = QRadarConnector(qradar_cfg)

        syslog_cfg = self.config.get_syslog_config()
        if syslog_cfg.get("enabled"):
            self._connectors[SIEMProvider.SYSLOG] = SyslogConnector(syslog_cfg)

        elastic_cfg = self.config.get_elastic_config()
        if elastic_cfg.get("enabled"):
            self._connectors[SIEMProvider.ELASTIC] = ElasticConnector(elastic_cfg)

        azure_cfg = self.config.get_azure_sentinel_config()
        if azure_cfg.get("enabled"):
            self._connectors[SIEMProvider.Azure_SENTINEL] = AzureSentinelConnector(
                azure_cfg
            )

        if self._connectors:
            logger.info(
                f"Initialized SIEM connectors: {[c.__class__.__name__ for c in self._connectors.values()]}"
            )

    def _worker(self):
        """Background worker to process event queue."""
        while self._running:
            try:
                event = self._event_queue.get(timeout=1)
                self._dispatch_event(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"SIEM worker error: {e}")

    def _dispatch_event(self, event: SIEMEvent):
        """Dispatch event to all enabled connectors."""
        for provider, connector in self._connectors.items():
            try:
                connector.send(event)
            except Exception as e:
                logger.error(f"Failed to send to {provider}: {e}")

    def start(self):
        """Start SIEM background worker."""
        if not self._running and self._connectors:
            self._running = True
            self._worker_thread = threading.Thread(target=self._worker, daemon=True)
            self._worker_thread.start()
            logger.info("SIEM service started")

    def stop(self):
        """Stop SIEM background worker."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info("SIEM service stopped")

    def send_event(self, event: SIEMEvent):
        """Queue event for SIEM forwarding."""
        if self._connectors:
            self._event_queue.put(event)

    def send_security_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send security alert to SIEM."""
        event = SIEMEvent(
            event_type="security_alert",
            severity=alert_data.get("severity", "medium"),
            category="alert",
            message=alert_data.get("title", "Security Alert"),
            user=alert_data.get("user"),
            action=alert_data.get("action"),
            raw_data=alert_data,
            MitreTechnique=alert_data.get("mitre_technique"),
            MitreTactic=alert_data.get("mitre_tactic"),
        )

        self.send_event(event)
        return True

    def send_vulnerability(self, vuln_data: Dict[str, Any]) -> bool:
        """Send vulnerability finding to SIEM."""
        event = SIEMEvent(
            event_type="vulnerability_found",
            severity=vuln_data.get("severity", "medium"),
            category="vulnerability",
            message=f"{vuln_data.get('cve_id', 'N/A')} - {vuln_data.get('description', '')[:100]}",
            raw_data=vuln_data,
            MitreTechnique=vuln_data.get("mitre_technique"),
        )

        self.send_event(event)
        return True

    def send_auth_event(self, auth_data: Dict[str, Any]) -> bool:
        """Send authentication event to SIEM."""
        event = SIEMEvent(
            event_type="authentication",
            severity=auth_data.get("severity", "low"),
            category="authentication",
            message=auth_data.get("message", "Auth event"),
            user=auth_data.get("user"),
            action=auth_data.get("action"),
            outcome=auth_data.get("outcome", "success"),
            source_ip=auth_data.get("source_ip"),
        )

        self.send_event(event)
        return True

    def send_asset_event(self, asset_data: Dict[str, Any]) -> bool:
        """Send asset event to SIEM."""
        event = SIEMEvent(
            event_type="asset_change",
            severity="low",
            category="asset",
            message=asset_data.get("message", "Asset event"),
            asset_id=asset_data.get("asset_id"),
            asset_name=asset_data.get("hostname"),
            action=asset_data.get("action"),
        )

        self.send_event(event)
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get SIEM integration status."""
        return {
            "enabled_providers": self.config.get_enabled_providers(),
            "connectors_initialized": len(self._connectors),
            "queue_size": self._event_queue.qsize()
            if hasattr(self, "_event_queue")
            else 0,
            "running": self._running,
        }
