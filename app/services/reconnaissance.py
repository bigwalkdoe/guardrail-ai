"""
Asset Discovery / Reconnaissance Engine Service.
Discovers attack surface through domain enumeration, port scanning, and technology fingerprinting.
Matches blueprint specification for reconnaissance engine.
"""

import logging
import socket
import requests
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Common ports and their services
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}


class ReconnaissanceEngine:
    """
    Reconnaissance engine for asset discovery.
    Performs domain enumeration, port scanning, and technology fingerprinting.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def discover_subdomains(self, domain: str) -> List[str]:
        """
        Discover subdomains for a given domain.
        
        Args:
            domain: Target domain
        
        Returns:
            List of discovered subdomains
        """
        subdomains = []
        
        # Common subdomain prefixes to check
        prefixes = ["api", "www", "admin", "dev", "staging", "test", 
                   "mail", "ftp", "localhost", "webmail", "smtp",
                   "pop", "ns1", "webdisk", "ns2", "cpanel", "whm"]
        
        # In production, would use DNS enumeration and certificate transparency logs
        # For now, return common subdomains that might exist
        for prefix in prefixes:
            subdomain = f"{prefix}.{domain}"
            subdomains.append(subdomain)
        
        return subdomains
    
    def scan_ports(self, host: str, ports: List[int] = None) -> Dict[int, Dict[str, Any]]:
        """
        Scan ports on a target host.
        
        Args:
            host: Target IP or hostname
            ports: List of ports to scan (default: common ports)
        
        Returns:
            Dictionary of open ports and their services
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        open_ports = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    service = COMMON_PORTS.get(port, "unknown")
                    open_ports[port] = {
                        "service": service,
                        "state": "open"
                    }
            except Exception as e:
                logger.debug(f"Port {port} scan failed: {e}")
        
        return open_ports
    
    def fingerprint_technology(self, url: str) -> Dict[str, Any]:
        """
        Fingerprint technologies used by a web service.
        
        Args:
            url: Target URL
        
        Returns:
            Technology fingerprint data
        """
        try:
            response = requests.get(url, timeout=5, headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
            })
            
            headers = response.headers
            fingerprint = {
                "server": headers.get("Server", "Unknown"),
                "content_type": headers.get("Content-Type", ""),
                "powered_by": headers.get("X-Powered-By", ""),
                "frameworks": []
            }
            
            # Detect common frameworks from headers
            server = headers.get("Server", "").lower()
            if "nginx" in server:
                fingerprint["frameworks"].append("nginx")
            if "apache" in server:
                fingerprint["frameworks"].append("apache")
            if "iis" in server:
                fingerprint["frameworks"].append("iis")
            
            powered_by = headers.get("X-Powered-By", "").lower()
            if "php" in powered_by:
                fingerprint["frameworks"].append("php")
            if "asp.net" in powered_by:
                fingerprint["frameworks"].append("asp.net")
            if "express" in powered_by:
                fingerprint["frameworks"].append("express")
            
            return fingerprint
        except Exception as e:
            logger.error(f"Technology fingerprinting failed: {e}")
            return {"error": str(e)}
    
    def create_asset(self, asset_data: Dict[str, Any]) -> int:
        """
        Create a new asset in the database.
        
        Args:
            asset_data: Asset data
        
        Returns:
            Created asset ID
        """
        from app.models import Asset
        
        asset = Asset(
            org_id=asset_data.get("org_id"),
            hostname=asset_data.get("hostname"),
            ip_address=asset_data.get("ip_address"),
            service=asset_data.get("service"),
            version=asset_data.get("version"),
            exposure_level=asset_data.get("exposure_level", "external"),
            asset_type=asset_data.get("asset_type", "web_server"),
            cloud_provider=asset_data.get("cloud_provider"),
            cloud_resource_id=asset_data.get("cloud_resource_id"),
            metadata=asset_data.get("metadata")
        )
        
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        
        return asset.id
    
    def run_reconnaissance(self, target: str, org_id: int = None) -> Dict[str, Any]:
        """
        Run complete reconnaissance scan on a target.
        
        Args:
            target: Target domain or IP
            org_id: Organization ID
        
        Returns:
            Reconnaissance results
        """
        results = {
            "target": target,
            "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            "subdomains": [],
            "open_ports": {},
            "technologies": {},
            "assets_created": []
        }
        
        # Check if target is a domain or IP
        is_domain = not target.replace(".", "").isdigit()
        
        if is_domain:
            # Domain reconnaissance
            results["subdomains"] = self.discover_subdomains(target)
            
            # Try to resolve main domain
            try:
                ip = socket.gethostbyname(target)
                results["resolved_ip"] = ip
                results["open_ports"] = self.scan_ports(ip)
            except Exception as e:
                results["resolution_error"] = str(e)
        else:
            # IP reconnaissance
            results["open_ports"] = self.scan_ports(target)
        
        # Fingerprint HTTP services
        if results["open_ports"].get(80) or results["open_ports"].get(443):
            protocol = "https" if 443 in results["open_ports"] else "http"
            url = f"{protocol}://{target}"
            results["technologies"] = self.fingerprint_technology(url)
        
        # Create assets in database
        ip_address = results.get("resolved_ip", target)
        
        # Create main asset
        asset_id = self.create_asset({
            "org_id": org_id,
            "hostname": target if is_domain else None,
            "ip_address": ip_address,
            "service": "web" if results["technologies"] else None,
            "exposure_level": "external",
            "asset_type": "web_server",
            "metadata": {
                "scan_results": results
            }
        })
        results["assets_created"].append(asset_id)
        
        # Create port-based assets
        for port, info in results["open_ports"].items():
            asset_id = self.create_asset({
                "org_id": org_id,
                "ip_address": ip_address,
                "service": info["service"],
                "port": port,
                "exposure_level": "external",
                "asset_type": "service"
            })
            results["assets_created"].append(asset_id)
        
        return results
    
    def get_asset_inventory(self, org_id: int = None) -> Dict[str, Any]:
        """
        Get asset inventory summary.
        
        Args:
            org_id: Optional organization filter
        
        Returns:
            Asset inventory summary
        """
        from app.models import Asset
        from sqlalchemy import func
        
        query = self.db.query(Asset)
        if org_id:
            query = query.filter(Asset.org_id == org_id)
        
        total = query.count()
        
        # Count by exposure level
        by_exposure = query.with_entities(
            Asset.exposure_level,
            func.count(Asset.id)
        ).group_by(Asset.exposure_level).all()
        
        # Count by type
        by_type = query.with_entities(
            Asset.asset_type,
            func.count(Asset.id)
        ).group_by(Asset.asset_type).all()
        
        # Count by service
        by_service = query.with_entities(
            Asset.service,
            func.count(Asset.id)
        ).filter(Asset.service != None).group_by(Asset.service).all()
        
        return {
            "total_assets": total,
            "by_exposure": {level: count for level, count in by_exposure},
            "by_type": {atype: count for atype, count in by_type},
            "by_service": {service: count for service, count in by_service},
            "external_assets": next((count for level, count in by_exposure if level == "external"), 0),
            "public_assets": next((count for level, count in by_exposure if level == "public"), 0)
        }
    
    def discover_cloud_assets(self, org_id: int) -> Dict[str, Any]:
        """
        Discover cloud assets (AWS, GCP, Azure).
        
        Args:
            org_id: Organization ID
        
        Returns:
            Discovered cloud assets
        """
        # In production, would integrate with cloud provider APIs
        # For now, return placeholder
        return {
            "aws": [],
            "gcp": [],
            "azure": [],
            "total": 0
        }
