"""
Scanning Tasks for Celery.
Background task processing for vulnerability scanning and reconnaissance.
"""

import logging
from typing import Dict, Any, List, Optional

from app.celery_app import celery_app
from app.database import SessionLocal

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.tasks.scanning.schedule_vulnerability_scan")
def schedule_vulnerability_scan(self, org_id: Optional[int] = None) -> Dict[str, Any]:
    """Schedule vulnerability scan for organization."""
    from app.services.vulnerability_engine import VulnerabilityIntelligenceEngine

    db = SessionLocal()
    try:
        engine = VulnerabilityIntelligenceEngine(db)

        from app.models import Asset

        assets = db.query(Asset)
        if org_id:
            assets = assets.filter(Asset.org_id == org_id)
        assets = assets.limit(100).all()

        scanned = 0
        for asset in assets:
            try:
                vulns = engine.scan_asset_vulnerabilities(
                    asset_id=asset.id,
                    service=asset.service or "unknown",
                    version=asset.version or "unknown",
                    exposure_level=asset.exposure_level or "internal",
                )
                scanned += 1
            except Exception as e:
                logger.error(f"Failed to scan asset {asset.id}: {e}")

        return {"status": "success", "scanned": scanned}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.scanning.scan_asset")
def scan_asset(self, asset_id: int) -> Dict[str, Any]:
    """Scan individual asset for vulnerabilities."""
    from app.services.vulnerability_engine import VulnerabilityIntelligenceEngine

    db = SessionLocal()
    try:
        engine = VulnerabilityIntelligenceEngine(db)

        from app.models import Asset

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return {"status": "error", "message": "Asset not found"}

        vulns = engine.scan_asset_vulnerabilities(
            asset_id=asset.id,
            service=asset.service or "unknown",
            version=asset.version or "unknown",
            exposure_level=asset.exposure_level or "internal",
        )

        return {
            "status": "success",
            "asset_id": asset_id,
            "vulnerabilities_found": len(vulns),
        }
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.scanning.schedule_attack_simulation")
def schedule_attack_simulation(self, org_id: Optional[int] = None) -> Dict[str, Any]:
    """Schedule attack simulation for organization."""
    from app.services.attack_simulation import AttackSimulationEngine

    db = SessionLocal()
    try:
        engine = AttackSimulationEngine(db)

        # Get critical assets for simulation
        from app.models import Asset, Vulnerability

        query = (
            db.query(Asset)
            .join(Vulnerability)
            .filter(Vulnerability.severity.in_(["critical", "high"]))
        )

        if org_id:
            query = query.filter(Asset.org_id == org_id)

        assets = query.limit(10).all()

        simulated = 0
        for asset in assets:
            try:
                paths = engine.simulate_attack_chain(
                    entry_asset_id=asset.id,
                    target_asset_id=asset.id,
                    attack_scenario="automated_scan",
                )
                simulated += 1
            except Exception as e:
                logger.error(f"Failed to simulate attack for asset {asset.id}: {e}")

        return {"status": "success", "simulated": simulated}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.scanning.run_reconnaissance")
def run_reconnaissance(self, target: str, org_id: int) -> Dict[str, Any]:
    """Run reconnaissance scan on target."""
    from app.services.reconnaissance import ReconnaissanceEngine

    db = SessionLocal()
    try:
        engine = ReconnaissanceEngine(db)

        results = engine.run_reconnaissance(target=target, org_id=org_id)

        return {"status": "success", "target": target, "results": results}
    finally:
        db.close()


@celery_app.task(bind=True, name="app.tasks.scanning.update_threat_intel")
def update_threat_intel(self) -> Dict[str, Any]:
    """Update threat intelligence database."""
    from app.services.threat_intel import ThreatIntelligenceService

    db = SessionLocal()
    try:
        service = ThreatIntelligenceService(db)

        # Fetch and update from threat feeds
        updated = service.update_threat_feeds()

        return {"status": "success", "indicators_updated": updated}
    finally:
        db.close()
