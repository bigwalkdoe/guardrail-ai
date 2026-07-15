"""
Threat Intelligence Service.
Integrates with threat feeds and provides IOC (Indicator of Compromise) matching.
Matches blueprint specification for threat intelligence integration.
"""

import logging
import requests
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Common threat intelligence feeds
THREAT_FEEDS = {
    "alienvault": "https://otx.alienvault.com/api/v1/pulses/subscribed",
    "abuse_ch": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox": "https://threatfox.abuse.ch/api/v1/",
}


class ThreatIntelligenceService:
    """
    Threat intelligence service for correlating events with known threats.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def check_indicator(self, indicator_type: str, indicator_value: str) -> Optional[Dict[str, Any]]:
        """
        Check if an indicator matches known threats.
        
        Args:
            indicator_type: Type of indicator (ip, domain, hash, url)
            indicator_value: The indicator value
        
        Returns:
            Threat intelligence results or None
        """
        from app.models import ThreatIntel
        
        # Check local database first
        threat = self.db.query(ThreatIntel).filter(
            ThreatIntel.indicator_type == indicator_type,
            ThreatIntel.indicator_value == indicator_value,
            ThreatIntel.is_active == True
        ).first()
        
        if threat:
            return {
                "found": True,
                "source": threat.source,
                "threat_type": threat.threat_type,
                "confidence": threat.confidence,
                "last_seen": threat.last_seen.isoformat() if threat.last_seen else None
            }
        
        # Would check external feeds here in production
        return {"found": False}
    
    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Look up IP reputation.
        
        Args:
            ip_address: IP address to check
        
        Returns:
            IP reputation data
        """
        # Check local database
        result = self.check_indicator("ip", ip_address)
        
        if result and result.get("found"):
            return result
        
        # In production, would query external threat feeds
        # For now, return mock data
        return {
            "found": False,
            "reputation": "unknown",
            "country": None,
            "isp": None,
            "is_malicious": False
        }
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up domain reputation.
        
        Args:
            domain: Domain to check
        
        Returns:
            Domain reputation data
        """
        result = self.check_indicator("domain", domain)
        
        if result and result.get("found"):
            return result
        
        return {
            "found": False,
            "reputation": "unknown",
            "registrar": None,
            "creation_date": None,
            "is_malicious": False
        }
    
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up file hash in threat databases.
        
        Args:
            file_hash: File hash (MD5, SHA1, SHA256)
        
        Returns:
            Threat intelligence for the hash
        """
        result = self.check_indicator("hash", file_hash)
        
        if result and result.get("found"):
            return result
        
        return {
            "found": False,
            "malware_family": None,
            "detection_ratio": None,
            "is_malicious": False
        }
    
    def add_threat_indicator(self, indicator_data: Dict[str, Any]) -> int:
        """
        Add a new threat indicator to the database.
        
        Args:
            indicator_data: Indicator data
        
        Returns:
            Created indicator ID
        """
        from app.models import ThreatIntel
        
        indicator = ThreatIntel(
            indicator_type=indicator_data["indicator_type"],
            indicator_value=indicator_data["indicator_value"],
            threat_type=indicator_data["threat_type"],
            source=indicator_data.get("source", "manual"),
            confidence=indicator_data.get("confidence", 50.0),
            first_seen=indicator_data.get("first_seen"),
            last_seen=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            metadata=indicator_data.get("metadata")
        )
        
        self.db.add(indicator)
        self.db.commit()
        self.db.refresh(indicator)
        
        return indicator.id
    
    def get_threat_summary(self, org_id: int = None) -> Dict[str, Any]:
        """
        Get summary of threat intelligence data.
        
        Args:
            org_id: Optional organization filter
        
        Returns:
            Threat intelligence summary
        """
        from app.models import ThreatIntel
        from sqlalchemy import func
        
        query = self.db.query(ThreatIntel)
        
        total = query.count()
        
        by_type = query.with_entities(
            ThreatIntel.indicator_type,
            func.count(ThreatIntel.id)
        ).group_by(ThreatIntel.indicator_type).all()
        
        by_threat = query.with_entities(
            ThreatIntel.threat_type,
            func.count(ThreatIntel.id)
        ).group_by(ThreatIntel.threat_type).all()
        
        return {
            "total_indicators": total,
            "by_type": {itype: count for itype, count in by_type},
            "by_threat_type": {threat: count for threat, count in by_threat},
            "active_count": query.filter(ThreatIntel.is_active == True).count()
        }
    
    def correlate_threat(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate an event with threat intelligence.
        
        Args:
            event_data: Event data to correlate
        
        Returns:
            Correlation results
        """
        correlations = []
        
        # Check IP if present
        if "ip" in event_data:
            ip_result = self.lookup_ip(event_data["ip"])
            if ip_result.get("found"):
                correlations.append({
                    "type": "ip",
                    "indicator": event_data["ip"],
                    "threat": ip_result
                })
        
        # Check domain if present
        if "domain" in event_data:
            domain_result = self.lookup_domain(event_data["domain"])
            if domain_result.get("found"):
                correlations.append({
                    "type": "domain",
                    "indicator": event_data["domain"],
                    "threat": domain_result
                })
        
        # Check URL if present
        if "url" in event_data:
            url_result = self.check_indicator("url", event_data["url"])
            if url_result and url_result.get("found"):
                correlations.append({
                    "type": "url",
                    "indicator": event_data["url"],
                    "threat": url_result
                })
        
        # Check file hash if present
        if "hash" in event_data:
            hash_result = self.lookup_hash(event_data["hash"])
            if hash_result.get("found"):
                correlations.append({
                    "type": "hash",
                    "indicator": event_data["hash"],
                    "threat": hash_result
                })
        
        return {
            "correlations": correlations,
            "is_malicious": len(correlations) > 0,
            "threat_level": "critical" if correlations else "none"
        }
    
    def fetch_external_feeds(self) -> Dict[str, Any]:
        """
        Fetch and integrate external threat feeds.
        
        Returns:
            Feed fetch results
        """
        results = {
            "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            "feeds": {}
        }
        
        # In production, would fetch from actual threat feeds
        # For now, return placeholder
        for feed_name in THREAT_FEEDS.keys():
            results["feeds"][feed_name] = {
                "status": "not_implemented",
                "indicators_added": 0
            }
        
        return results


# Common threat types
THREAT_TYPES = {
    "malware": "Malware",
    "ransomware": "Ransomware",
    "trojan": "Trojan",
    "backdoor": "Backdoor",
    "worm": "Worm",
    "adware": "Adware",
    "spyware": "Spyware",
    "c2": "Command and Control",
    "phishing": "Phishing",
    "spam": "Spam",
    "botnet": "Botnet"
}

# Indicator types
INDICATOR_TYPES = ["ip", "domain", "url", "hash", "email", "file_name"]
