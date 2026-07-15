"""
AI Decision Layer Service.
Central orchestration layer that connects all security components.
Provides risk prioritization, attack path prediction, and remediation recommendations.
Matches blueprint specification for AI decision layer.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class AIDecisionEngine:
    """
    AI Decision Engine - the central brain of the security platform.
    Coordinates all security services and provides intelligent recommendations.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def analyze_threat(self, asset_id: int, vulnerability_id: int = None) -> Dict[str, Any]:
        """
        Analyze a specific threat scenario.
        
        Args:
            asset_id: Asset to analyze
            vulnerability_id: Optional specific vulnerability
        
        Returns:
            Threat analysis with recommendations
        """
        from app.models import Asset, Vulnerability
        
        asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
        
        if not asset:
            return {"error": "Asset not found"}
        
        # Get vulnerabilities for this asset
        query = self.db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id)
        if vulnerability_id:
            query = query.filter(Vulnerability.id == vulnerability_id)
        
        vulnerabilities = query.all()
        
        # Calculate overall risk
        total_risk = sum(v.risk_score for v in vulnerabilities)
        max_severity = max((v.severity for v in vulnerabilities), default="none")
        
        # Build attack path analysis
        analysis = {
            "asset": {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "exposure_level": asset.exposure_level
            },
            "vulnerabilities": [
                {
                    "cve": v.cve_id,
                    "severity": v.severity,
                    "risk_score": v.risk_score,
                    "exploitable": v.is_exploitable
                }
                for v in vulnerabilities
            ],
            "risk_assessment": {
                "total_risk_score": total_risk,
                "max_severity": max_severity,
                "exploitable_vulnerabilities": sum(1 for v in vulnerabilities if v.is_exploitable)
            },
            "attack_vector": self._identify_attack_vector(asset, vulnerabilities),
            "recommendations": self._generate_recommendations(asset, vulnerabilities),
            "mitre_techniques": self._map_mitre_techniques(vulnerabilities)
        }
        
        return analysis
    
    def _identify_attack_vector(self, asset, vulnerabilities) -> str:
        """Identify the most likely attack vector."""
        if not vulnerabilities:
            return "unknown"
        
        # Check for web-based vulnerabilities
        if asset.service in ["http", "https", "api", "web"]:
            return "web_attack"
        
        # Check for remote code execution
        for v in vulnerabilities:
            if v.cve_id and any(cve in str(v.cve_id) for cve in ["RCE", "RCE"]):
                return "remote_code_execution"
        
        # Default to network-based attack
        return "network_attack"
    
    def _generate_recommendations(self, asset, vulnerabilities) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Based on severity
        critical_vulns = [v for v in vulnerabilities if v.severity == "critical"]
        if critical_vulns:
            recommendations.append(f"URGENT: Patch {len(critical_vulns)} critical vulnerabilities immediately")
            recommendations.append("Consider isolating this asset until patches are applied")
        
        # Based on exposure
        if asset.exposure_level == "public":
            recommendations.append("This asset is publicly exposed - implement WAF protection")
            recommendations.append("Review and restrict access controls")
        
        # Based on exploitability
        exploitable = [v for v in vulnerabilities if v.is_exploitable]
        if exploitable:
            recommendations.append(f"Enable enhanced monitoring for {len(exploitable)} exploitable vulnerabilities")
            recommendations.append("Implement virtual patching at the network level")
        
        # General recommendations
        if not recommendations:
            recommendations.append("Continue regular security monitoring")
            recommendations.append("Schedule routine vulnerability scans")
        
        return recommendations
    
    def _map_mitre_techniques(self, vulnerabilities) -> List[Dict]:
        """Map vulnerabilities to MITRE ATT&CK techniques."""
        # Simplified mapping - in production would be more comprehensive
        technique_map = {
            "sql_injection": "T1190",  # Exploit Public-Facing Application
            "xss": "T1183",  # Exploit Public-Facing Application
            "command_injection": "T1059",  # Command and Scripting Interpreter
            "privilege_escalation": "T1068",  # Exploitation for Privilege Escalation
            "credential_dump": "T1003",  # OS Credential Dumping
        }
        
        techniques = []
        for v in vulnerabilities:
            if v.vulnerability_type in technique_map:
                techniques.append({
                    "technique_id": technique_map[v.vulnerability_type],
                    "tactic": self._get_tactic_for_technique(technique_map[v.vulnerability_type])
                })
        
        return techniques
    
    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """Get MITRE ATT&CK tactic for a technique."""
        tactics_map = {
            "T1190": "Initial Access",
            "T1183": "Initial Access",
            "T1059": "Execution",
            "T1068": "Privilege Escalation",
            "T1003": "Credential Access"
        }
        return tactics_map.get(technique_id, "Unknown")
    
    def prioritize_vulnerabilities(self, org_id: int = None) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities for remediation.
        
        Args:
            org_id: Optional organization filter
        
        Returns:
            Prioritized list of vulnerabilities
        """
        from app.models import Vulnerability
        
        query = self.db.query(Vulnerability)
        if org_id:
            query = query.filter(Vulnerability.org_id == org_id)
        
        vulnerabilities = query.order_by(Vulnerability.risk_score.desc()).all()
        
        prioritized = []
        for v in vulnerabilities:
            prioritized.append({
                "id": v.id,
                "asset_id": v.asset_id,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "risk_score": v.risk_score,
                "is_exploitable": v.is_exploitable,
                "remediation_priority": self._calculate_priority(v)
            })
        
        return prioritized
    
    def _calculate_priority(self, vulnerability) -> str:
        """Calculate remediation priority."""
        if vulnerability.severity == "critical" and vulnerability.is_exploitable:
            return "P1 - Immediate Action"
        elif vulnerability.severity == "critical":
            return "P2 - Within 24 Hours"
        elif vulnerability.severity == "high" and vulnerability.is_exploitable:
            return "P2 - Within 24 Hours"
        elif vulnerability.severity == "high":
            return "P3 - Within 1 Week"
        else:
            return "P4 - Schedule for Next Cycle"
    
    def predict_attack_paths(self, org_id: int) -> List[Dict[str, Any]]:
        """
        Predict potential attack paths.
        
        Args:
            org_id: Organization ID
        
        Returns:
            Predicted attack paths
        """
        from app.models import AttackPath
        
        # Get all attack paths for the organization
        paths = self.db.query(AttackPath).filter(
            AttackPath.org_id == org_id
        ).order_by(AttackPath.impact_score.desc()).limit(10).all()
        
        return [
            {
                "id": p.id,
                "name": p.name,
                "attack_vector": p.attack_vector,
                "likelihood": p.likelihood,
                "impact": p.impact_score,
                "critical_asset_id": p.critical_asset_id
            }
            for p in paths
        ]
    
    def generate_incident_summary(self, alert_ids: List[int]) -> Dict[str, Any]:
        """
        Generate an AI summary of security incidents.
        
        Args:
            alert_ids: List of alert IDs to summarize
        
        Returns:
            Incident summary
        """
        from app.models import Alert
        
        alerts = self.db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
        
        if not alerts:
            return {"error": "No alerts found"}
        
        # Group by severity
        by_severity = {}
        for alert in alerts:
            severity = alert.severity
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append({
                "id": alert.id,
                "title": alert.title,
                "type": alert.alert_type,
                "created_at": alert.created_at.isoformat()
            })
        
        # Generate summary
        summary = {
            "total_alerts": len(alerts),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "timeline": "Recent",
            "recommended_actions": self._recommend_actions(by_severity)
        }
        
        return summary
    
    def _recommend_actions(self, by_severity: Dict) -> List[str]:
        """Generate recommended actions based on alerts."""
        actions = []
        
        critical = by_severity.get("critical", [])
        if critical:
            actions.append(f"CRITICAL: {len(critical)} critical alerts require immediate investigation")
        
        high = by_severity.get("high", [])
        if high:
            actions.append(f"HIGH: {len(high)} high severity alerts need attention within 1 hour")
        
        return actions
    
    def get_security_posture(self, org_id: int) -> Dict[str, Any]:
        """
        Get overall security posture for an organization.
        
        Args:
            org_id: Organization ID
        
        Returns:
            Security posture assessment
        """
        from app.models import Asset, Vulnerability, Alert
        
        # Get counts
        total_assets = self.db.query(Asset).filter(Asset.org_id == org_id).count()
        total_vulns = self.db.query(Vulnerability).filter(Vulnerability.org_id == org_id).count()
        open_alerts = self.db.query(Alert).filter(
            Alert.org_id == org_id,
            Alert.status == "open"
        ).count()
        
        # Get severity breakdown
        critical_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.org_id == org_id,
            Vulnerability.severity == "critical"
        ).count()
        
        # Calculate overall score (simplified)
        score = 100
        score -= min(critical_vulns * 5, 30)
        score -= min(open_alerts * 2, 20)
        score = max(0, score)
        
        return {
            "score": score,
            "grade": self._get_grade(score),
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "open_alerts": open_alerts,
            "risk_level": "critical" if score < 40 else "high" if score < 70 else "medium" if score < 85 else "low"
        }
    
    def _get_grade(self, score: int) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
