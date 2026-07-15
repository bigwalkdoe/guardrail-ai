"""
Attack Simulation Engine Service (Red Team).
Simulates exploit chains and attack paths to test infrastructure security.
Matches blueprint specification for attack path simulation.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.neo4j_client import get_neo4j_client

logger = logging.getLogger(__name__)


class AttackSimulationEngine:
    """
    Red team attack simulation engine.
    Models how attackers chain vulnerabilities to compromise systems.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.neo4j = get_neo4j_client()
    
    # Common attack techniques mapped to MITRE ATT&CK
    ATTACK_TECHNIQUES = {
        "sql_injection": {
            "mitre_id": "T1190",
            "tactic": "Initial Access",
            "risk": 9.5
        },
        "xss": {
            "mitre_id": "T1183",
            "tactic": "Initial Access",
            "risk": 7.0
        },
        "csrf": {
            "mitre_id": "T1190",
            "tactic": "Initial Access",
            "risk": 5.0
        },
        "credential_dump": {
            "mitre_id": "T1003",
            "tactic": "Credential Access",
            "risk": 9.0
        },
        "privilege_escalation": {
            "mitre_id": "T1068",
            "tactic": "Privilege Escalation",
            "risk": 8.5
        },
        "lateral_movement": {
            "mitre_id": "T1021",
            "tactic": "Lateral Movement",
            "risk": 8.0
        },
        "data_exfiltration": {
            "mitre_id": "T1041",
            "tactic": "Exfiltration",
            "risk": 9.0
        },
        "command_injection": {
            "mitre_id": "T1059",
            "tactic": "Execution",
            "risk": 8.5
        },
        "path_traversal": {
            "mitre_id": "T1006",
            "tactic": "Defense Evasion",
            "risk": 6.5
        },
        "ssrf": {
            "mitre_id": "T1190",
            "tactic": "Initial Access",
            "risk": 7.5
        }
    }
    
    # Attack chain templates
    ATTACK_CHAIN_TEMPLATES = {
        "web_to_db": [
            {"step": "Initial Access", "technique": "sql_injection"},
            {"step": "Execution", "technique": "command_injection"},
            {"step": "Privilege Escalation", "technique": "privilege_escalation"},
            {"step": "Impact", "technique": "data_exfiltration"}
        ],
        "phishing_to_domain": [
            {"step": "Initial Access", "technique": "phishing"},
            {"step": "Execution", "technique": "command_injection"},
            {"step": "Credential Access", "technique": "credential_dump"},
            {"step": "Lateral Movement", "technique": "lateral_movement"},
            {"step": "Impact", "technique": "privilege_escalation"}
        ],
        "cloud_compromise": [
            {"step": "Initial Access", "technique": "ssrf"},
            {"step": "Credential Access", "technique": "credential_dump"},
            {"step": "Lateral Movement", "technique": "lateral_movement"},
            {"step": "Impact", "technique": "data_exfiltration"}
        ]
    }
    
    def calculate_likelihood(self, vulnerabilities: List[Dict]) -> float:
        """
        Calculate likelihood of attack success based on vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities in the attack path
        
        Returns:
            Likelihood score (0-100)
        """
        if not vulnerabilities:
            return 0.0
        
        # Average exploit probability of all vulnerabilities
        avg_prob = sum(v.get("exploit_probability", 0) for v in vulnerabilities) / len(vulnerabilities)
        
        # Adjust based on number of steps (more steps = harder)
        chain_penalty = min(len(vulnerabilities) * 5, 30)
        
        likelihood = avg_prob - chain_penalty
        return max(0.0, min(100.0, likelihood))
    
    def calculate_impact(self, target_asset_type: str) -> float:
        """
        Calculate impact score based on target asset type.
        
        Args:
            target_asset_type: Type of target asset
        
        Returns:
            Impact score (0-10)
        """
        impact_map = {
            "database": 9.5,
            "domain_controller": 10.0,
            "api": 8.0,
            "web_server": 7.0,
            "container": 8.5,
            "cloud": 9.0,
            "file_server": 6.5,
            "workstation": 5.0
        }
        return impact_map.get(target_asset_type.lower(), 5.0)
    
    def simulate_attack_chain(self, entry_asset_id: int, target_asset_id: int,
                            attack_scenario: str = None) -> Dict[str, Any]:
        """
        Simulate an attack chain from entry point to target.
        
        Args:
            entry_asset_id: Starting asset ID
            target_asset_id: Target/critical asset ID
            attack_scenario: Specific attack scenario to simulate
        
        Returns:
            Attack simulation results
        """
        from app.models import Asset, Vulnerability
        
        # Get entry and target assets
        entry_asset = self.db.query(Asset).filter(Asset.id == entry_asset_id).first()
        target_asset = self.db.query(Asset).filter(Asset.id == target_asset_id).first()
        
        if not entry_asset or not target_asset:
            return {"error": "Assets not found"}
        
        # Get vulnerabilities for both assets
        entry_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.asset_id == entry_asset_id
        ).all()
        
        target_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.asset_id == target_asset_id
        ).all()
        
        # Build attack path
        attack_path = {
            "entry": {
                "asset_id": entry_asset_id,
                "hostname": entry_asset.hostname,
                "ip_address": entry_asset.ip_address,
                "service": entry_asset.service,
                "vulnerabilities": [
                    {"cve": v.cve_id, "risk_score": v.risk_score} 
                    for v in entry_vulns
                ]
            },
            "target": {
                "asset_id": target_asset_id,
                "hostname": target_asset.hostname,
                "ip_address": target_asset.ip_address,
                "asset_type": target_asset.asset_type,
                "vulnerabilities": [
                    {"cve": v.cve_id, "risk_score": v.risk_score} 
                    for v in target_vulns
                ]
            },
            "steps": []
        }
        
        # Determine attack chain based on scenario or infer
        if attack_scenario and attack_scenario in self.ATTACK_CHAIN_TEMPLATES:
            chain = self.ATTACK_CHAIN_TEMPLATES[attack_scenario]
        else:
            # Use web_to_db as default for web targets
            chain = self.ATTACK_CHAIN_TEMPLATES["web_to_db"]
        
        # Build attack steps
        all_vulnerabilities = list(entry_vulns) + list(target_vulns)
        likelihood = self.calculate_likelihood([
            {"exploit_probability": v.exploit_probability for v in all_vulnerabilities}
        ])
        
        for step in chain:
            technique = step["technique"]
            tech_info = self.ATTACK_TECHNIQUES.get(technique, {})
            
            attack_path["steps"].append({
                "step": step["step"],
                "technique": technique,
                "mitre_id": tech_info.get("mitre_id"),
                "tactic": tech_info.get("tactic"),
                "risk": tech_info.get("risk", 5.0)
            })
        
        impact = self.calculate_impact(target_asset.asset_type or "unknown")
        
        # Calculate overall risk
        overall_risk = (likelihood * 0.4) + (impact * 10 * 0.6)
        
        attack_path["summary"] = {
            "likelihood": round(likelihood, 2),
            "impact": round(impact, 2),
            "overall_risk": round(overall_risk, 2),
            "chain_length": len(chain),
            "is_simulated": True,
            "recommendations": self._generate_recommendations(attack_path)
        }
        
        return attack_path
    
    def _generate_recommendations(self, attack_path: Dict) -> List[str]:
        """Generate security recommendations based on attack path."""
        recommendations = []
        
        # Check for SQL injection
        for step in attack_path.get("steps", []):
            if step.get("technique") == "sql_injection":
                recommendations.append("Implement parameterized queries and input validation")
                recommendations.append("Use Web Application Firewall (WAF)")
            
            if step.get("technique") == "privilege_escalation":
                recommendations.append("Implement principle of least privilege")
                recommendations.append("Enable privileged access management")
            
            if step.get("technique") == "credential_dump":
                recommendations.append("Enable credential protection mechanisms")
                recommendations.append("Implement multi-factor authentication")
            
            if step.get("technique") == "lateral_movement":
                recommendations.append("Implement network segmentation")
                recommendations.append("Enable advanced threat protection")
        
        return recommendations
    
    def get_critical_attack_paths(self, org_id: int = None, 
                                 min_risk: float = 5.0) -> List[Dict[str, Any]]:
        """
        Get the most critical attack paths for an organization.
        
        Args:
            org_id: Organization ID
            min_risk: Minimum risk threshold
        
        Returns:
            List of critical attack paths
        """
        from app.models import AttackPath
        
        query = self.db.query(AttackPath)
        if org_id:
            query = query.filter(AttackPath.org_id == org_id)
        
        # Filter by risk score (simplified - would use computed risk)
        critical_paths = query.filter(
            AttackPath.impact_score >= min_risk
        ).order_by(AttackPath.impact_score.desc()).limit(10).all()
        
        return [
            {
                "id": path.id,
                "name": path.name,
                "entry_asset_id": path.entry_asset_id,
                "critical_asset_id": path.critical_asset_id,
                "attack_vector": path.attack_vector,
                "likelihood": path.likelihood,
                "impact_score": path.impact_score,
                "created_at": path.created_at.isoformat() if path.created_at else None
            }
            for path in critical_paths
        ]
    
    def run_continuous_pentest(self, org_id: int, target_scope: List[str]) -> Dict[str, Any]:
        """
        Run continuous penetration testing simulation.
        
        Args:
            org_id: Organization ID
            target_scope: List of target domains/IPs
        
        Returns:
            Pentest results
        """
        results = {
            "org_id": org_id,
            "scope": target_scope,
            "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            "findings": []
        }
        
        # For each target, simulate attack
        for target in target_scope:
            # This would integrate with actual scanning in production
            finding = {
                "target": target,
                "vulnerabilities_found": 0,
                "attack_paths_possible": 0,
                "risk_level": "medium"
            }
            results["findings"].append(finding)
        
        return results
    
    def get_attack_surface_score(self, org_id: int) -> Dict[str, Any]:
        """
        Calculate overall attack surface score.
        
        Args:
            org_id: Organization ID
        
        Returns:
            Attack surface metrics
        """
        from app.models import Asset, Vulnerability
        
        total_assets = self.db.query(Asset).filter(
            Asset.org_id == org_id
        ).count()
        
        total_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.org_id == org_id
        ).count()
        
        critical_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.org_id == org_id,
            Vulnerability.severity == "critical"
        ).count()
        
        exploitable = self.db.query(Vulnerability).filter(
            Vulnerability.org_id == org_id,
            Vulnerability.is_exploitable == True
        ).count()
        
        # Simple attack surface score (0-100, lower is better)
        score = min(100, (critical_vulns * 10) + (exploitable * 5) + (total_vulns * 1))
        
        return {
            "score": score,
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "exploitable_vulnerabilities": exploitable,
            "risk_level": "critical" if score > 70 else "high" if score > 50 else "medium" if score > 30 else "low"
        }
