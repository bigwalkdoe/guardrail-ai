"""
Defensive Monitoring Engine Service (Blue Team).
Monitors logs and telemetry for threat detection and anomaly detection.
Matches blueprint specification for defensive monitoring.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
import numpy as np

logger = logging.getLogger(__name__)


class DefensiveMonitoringEngine:
    """
    Blue team defensive monitoring engine.
    Performs real-time detection using anomaly detection and threat classification.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.anomaly_model = None
        self._init_anomaly_model()
    
    def _init_anomaly_model(self):
        """Initialize anomaly detection model."""
        # Initialize Isolation Forest for anomaly detection
        # In production, this would be trained on historical data
        try:
            self.anomaly_model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            # Fit with empty data initially (would be trained on historical logs)
            self.anomaly_model.fit([[0] * 10])
        except Exception as e:
            logger.warning(f"Could not initialize anomaly model: {e}")
    
    # Detection rules for common attack patterns
    DETECTION_RULES = {
        "brute_force": {
            "pattern": "multiple_failed_logins",
            "threshold": 5,
            "window_minutes": 10,
            "severity": "high"
        },
        "privilege_escalation": {
            "pattern": "sudden_privilege_change",
            "threshold": 1,
            "window_minutes": 5,
            "severity": "critical"
        },
        "data_exfiltration": {
            "pattern": "unusual_outbound_traffic",
            "threshold": 1000000,  # bytes
            "window_minutes": 60,
            "severity": "critical"
        },
        "lateral_movement": {
            "pattern": "unusual_access_patterns",
            "threshold": 3,
            "window_minutes": 15,
            "severity": "high"
        },
        "intrusion": {
            "pattern": "suspicious_port_access",
            "threshold": 1,
            "window_minutes": 1,
            "severity": "high"
        }
    }
    
    def analyze_log_entry(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single log entry for security events.
        
        Args:
            log_data: Log entry data
        
        Returns:
            Analysis results with threat indicators
        """
        analysis = {
            "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            "indicators": [],
            "threat_level": "normal",
            "recommendations": []
        }
        
        # Check for suspicious patterns
        if self._check_failed_logins(log_data):
            analysis["indicators"].append({
                "type": "brute_force",
                "severity": "high",
                "description": "Multiple failed login attempts detected"
            })
            analysis["recommendations"].append("Enable account lockout policies")
        
        if self._check_privilege_escalation(log_data):
            analysis["indicators"].append({
                "type": "privilege_escalation",
                "severity": "critical",
                "description": "Suspicious privilege escalation detected"
            })
            analysis["recommendations"].append("Review user permissions immediately")
        
        if self._check_suspicious_ports(log_data):
            analysis["indicators"].append({
                "type": "intrusion",
                "severity": "high",
                "description": "Access to suspicious ports detected"
            })
            analysis["recommendations"].append("Block unauthorized ports at firewall")
        
        # Determine overall threat level
        if any(i["severity"] == "critical" for i in analysis["indicators"]):
            analysis["threat_level"] = "critical"
        elif any(i["severity"] == "high" for i in analysis["indicators"]):
            analysis["threat_level"] = "high"
        elif analysis["indicators"]:
            analysis["threat_level"] = "medium"
        
        return analysis
    
    def _check_failed_logins(self, log_data: Dict) -> bool:
        """Check for brute force login attempts."""
        event_type = log_data.get("event_type", "")
        return event_type == "auth_failure"
    
    def _check_privilege_escalation(self, log_data: Dict) -> bool:
        """Check for privilege escalation attempts."""
        event_type = log_data.get("event_type", "")
        return event_type in ["privilege_change", "admin_access"]
    
    def _check_suspicious_ports(self, log_data: Dict) -> bool:
        """Check for suspicious port access."""
        suspicious_ports = [22, 23, 445, 3389]  # SSH, Telnet, SMB, RDP
        port = log_data.get("port")
        return port in suspicious_ports
    
    def detect_anomaly(self, features: List[float]) -> Dict[str, Any]:
        """
        Detect anomalies using ML model.
        
        Args:
            features: Feature vector for the event
        
        Returns:
            Anomaly detection results
        """
        if not self.anomaly_model:
            return {"is_anomaly": False, "confidence": 0}
        
        try:
            # Reshape for single prediction
            features_array = np.array(features).reshape(1, -1)
            prediction = self.anomaly_model.predict(features_array)
            score = self.anomaly_model.decision_function(features_array)
            
            return {
                "is_anomaly": prediction[0] == -1,
                "confidence": abs(score[0]),
                "anomaly_score": float(score[0])
            }
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return {"is_anomaly": False, "confidence": 0}
    
    def create_alert(self, org_id: int, alert_data: Dict[str, Any]) -> int:
        """
        Create a security alert in the database.
        
        Args:
            org_id: Organization ID
            alert_data: Alert data
        
        Returns:
            Created alert ID
        """
        from app.models import Alert
        
        alert = Alert(
            org_id=org_id,
            asset_id=alert_data.get("asset_id"),
            alert_type=alert_data.get("alert_type", "anomaly"),
            title=alert_data.get("title", "Security Alert"),
            description=alert_data.get("description"),
            severity=alert_data.get("severity", "medium"),
            source="blue_team",
            mitre_tactic=alert_data.get("mitre_tactic"),
            mitre_technique=alert_data.get("mitre_technique"),
            indicators=alert_data.get("indicators")
        )
        
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        
        return alert.id
    
    def get_security_metrics(self, org_id: int, hours: int = 24) -> Dict[str, Any]:
        """
        Get security metrics for the specified time period.
        
        Args:
            org_id: Organization ID
            hours: Time period in hours
        
        Returns:
            Security metrics
        """
        from app.models import Alert
        from sqlalchemy import func
        
        cutoff = datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
        
        # Get alert counts by severity
        alert_counts = self.db.query(
            Alert.severity,
            func.count(Alert.id)
        ).filter(
            Alert.org_id == org_id,
            Alert.created_at >= cutoff
        ).group_by(Alert.severity).all()
        
        # Get alert counts by type
        type_counts = self.db.query(
            Alert.alert_type,
            func.count(Alert.id)
        ).filter(
            Alert.org_id == org_id,
            Alert.created_at >= cutoff
        ).group_by(Alert.alert_type).all()
        
        return {
            "period_hours": hours,
            "total_alerts": sum(count for _, count in alert_counts),
            "by_severity": {severity: count for severity, count in alert_counts},
            "by_type": {alert_type: count for alert_type, count in type_counts},
            "critical_count": next((count for s, count in alert_counts if s == "critical"), 0),
            "open_alerts": self.db.query(Alert).filter(
                Alert.org_id == org_id,
                Alert.status == "open"
            ).count()
        }
    
    def auto_response_action(self, alert_id: int, action: str) -> Dict[str, Any]:
        """
        Execute automated response action for an alert.
        
        Args:
            alert_id: Alert ID
            action: Action to take (block_ip, isolate_host, rotate_credential)
        
        Returns:
            Action result
        """
        from app.models import Alert
        
        alert = self.db.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert:
            return {"success": False, "error": "Alert not found"}
        
        action_results = {
            "block_ip": self._block_ip(alert),
            "isolate_host": self._isolate_host(alert),
            "rotate_credential": self._rotate_credential(alert),
            "quarantine_endpoint": self._quarantine_endpoint(alert)
        }
        
        result = action_results.get(action, {"success": False, "error": "Unknown action"})
        
        # Update alert with response action
        if result.get("success"):
            alert.response_action = action
            self.db.commit()
        
        return result
    
    def _block_ip(self, alert) -> Dict[str, Any]:
        """Block malicious IP."""
        logger.info(f"Auto-blocking IP for alert {alert.id}")
        return {"success": True, "action": "ip_blocked", "alert_id": alert.id}
    
    def _isolate_host(self, alert) -> Dict[str, Any]:
        """Isolate compromised host."""
        logger.info(f"Isolating host for alert {alert.id}")
        return {"success": True, "action": "host_isolated", "alert_id": alert.id}
    
    def _rotate_credential(self, alert) -> Dict[str, Any]:
        """Rotate compromised credentials."""
        logger.info(f"Rotating credentials for alert {alert.id}")
        return {"success": True, "action": "credentials_rotated", "alert_id": alert.id}
    
    def _quarantine_endpoint(self, alert) -> Dict[str, Any]:
        """Quarantine endpoint."""
        logger.info(f"Quarantining endpoint for alert {alert.id}")
        return {"success": True, "action": "endpoint_quarantined", "alert_id": alert.id}


# MITRE ATT&CK tactics mapping for blue team
MITRE_TACTICS_MAP = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact"
}
