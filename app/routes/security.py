"""
Security Platform API Routes.
Endpoints for the cybersecurity platform (red team + blue team operations).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone

from app.database import get_db
from app.security import get_current_user, require_admin
from app.models import User
from app.schemas import (
    Asset,
    AssetCreate,
    Vulnerability,
    VulnerabilityCreate,
    AttackPath,
    AttackPathCreate,
    Alert,
    AlertCreate,
    AlertUpdate,
    ThreatIntel,
    ThreatIntelCreate,
    ScanJobCreate,
    ReconRequest,
    VulnScanRequest,
    AttackSimRequest,
    AIDecisionRequest,
    AIDecisionResponse,
)
from app.services.vulnerability_engine import VulnerabilityIntelligenceEngine
from app.services.attack_simulation import AttackSimulationEngine
from app.services.defensive_monitor import DefensiveMonitoringEngine
from app.services.threat_intel import ThreatIntelligenceService
from app.services.reconnaissance import ReconnaissanceEngine
from app.services.ai_decision import AIDecisionEngine

router = APIRouter(prefix="/security", tags=["security"])


# =============================================================================
# Asset Management Routes
# =============================================================================


@router.post("/assets", response_model=Asset)
def create_asset(
    asset: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new asset."""
    from app.models import Asset

    db_asset = Asset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.get("/assets", response_model=List[Asset])
def list_assets(
    org_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all assets."""
    from app.models import Asset

    query = db.query(Asset)
    if org_id:
        query = query.filter(Asset.org_id == org_id)

    return query.offset(skip).limit(limit).all()


@router.get("/assets/{asset_id}", response_model=Asset)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific asset."""
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


# =============================================================================
# Reconnaissance / Asset Discovery Routes
# =============================================================================


@router.post("/recon/scan")
def run_reconnaissance(
    request: ReconRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run reconnaissance scan on a target."""
    recon = ReconnaissanceEngine(db)
    results = recon.run_reconnaissance(
        target=request.target, org_id=current_user.org_id
    )
    return results


@router.get("/recon/inventory")
def get_asset_inventory(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get asset inventory summary."""
    recon = ReconnaissanceEngine(db)
    return recon.get_asset_inventory(org_id=current_user.org_id)


# =============================================================================
# Vulnerability Intelligence Routes
# =============================================================================


@router.post("/vulnerabilities/scan")
async def scan_vulnerabilities(
    request: VulnScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan assets for vulnerabilities."""
    vuln_engine = VulnerabilityIntelligenceEngine(db)

    # Get assets to scan
    from app.models import Asset

    if request.asset_ids:
        assets = db.query(Asset).filter(Asset.id.in_(request.asset_ids)).all()
    else:
        assets = db.query(Asset).filter(Asset.org_id == current_user.org_id).all()

    from app.models import Vulnerability as DBVulnerability

    results = []
    for asset in assets:
        vulns = await vuln_engine.scan_asset_vulnerabilities(
            asset_id=asset.id,
            service=asset.service or "unknown",
            version=asset.version or "unknown",
            exposure_level=asset.exposure_level or "internal",
        )

        # Save vulnerabilities to database
        for v in vulns:
            vuln = DBVulnerability(org_id=current_user.org_id, **v)
            db.add(vuln)
            results.append(v)

    db.commit()
    return {"vulnerabilities_found": len(results)}


@router.get("/vulnerabilities", response_model=List[Vulnerability])
def list_vulnerabilities(
    org_id: Optional[int] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List vulnerabilities."""
    from app.models import Vulnerability

    query = db.query(Vulnerability)
    if org_id:
        query = query.filter(Vulnerability.org_id == org_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)

    return (
        query.order_by(Vulnerability.risk_score.desc()).offset(skip).limit(limit).all()
    )


@router.get("/vulnerabilities/summary")
def get_vulnerability_summary(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get vulnerability summary."""
    vuln_engine = VulnerabilityIntelligenceEngine(db)
    return vuln_engine.get_vulnerability_summary(org_id=current_user.org_id)


# =============================================================================
# Attack Simulation (Red Team) Routes
# =============================================================================


@router.post("/attack-simulate")
def simulate_attack(
    request: AttackSimRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Simulate an attack path."""
    attack_engine = AttackSimulationEngine(db)
    return attack_engine.simulate_attack_chain(
        entry_asset_id=request.entry_asset_id,
        target_asset_id=request.target_asset_id,
        attack_scenario=request.attack_scenario,
    )


@router.get("/attack-paths")
def get_attack_paths(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get critical attack paths."""
    attack_engine = AttackSimulationEngine(db)
    return attack_engine.get_critical_attack_paths(org_id=org_id)


@router.get("/attack-surface")
def get_attack_surface(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get attack surface score."""
    attack_engine = AttackSimulationEngine(db)
    return attack_engine.get_attack_surface_score(org_id=current_user.org_id)


# =============================================================================
# Defensive Monitoring (Blue Team) Routes
# =============================================================================


@router.post("/defense/analyze-log")
def analyze_log(
    log_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Analyze a log entry for security events."""
    defense = DefensiveMonitoringEngine(db)
    return defense.analyze_log_entry(log_data)


@router.get("/defense/metrics")
def get_security_metrics(
    hours: int = 24,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get security metrics."""
    defense = DefensiveMonitoringEngine(db)
    return defense.get_security_metrics(org_id=current_user.org_id, hours=hours)


@router.post("/defense/auto-response")
def execute_auto_response(
    alert_id: int,
    action: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute automated response action."""
    defense = DefensiveMonitoringEngine(db)
    return defense.auto_response_action(alert_id=alert_id, action=action)


@router.post("/alerts", response_model=Alert)
def create_alert(
    alert: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new alert."""
    db_alert = Alert(**alert.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


@router.get("/alerts", response_model=List[Alert])
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List alerts."""
    from app.models import Alert

    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update an alert."""
    from app.models import Alert

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(alert, key, value)

    if payload.status == "resolved":
        alert.resolved_at = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        alert.resolved_by = current_user.id

    db.commit()
    db.refresh(alert)
    return alert


# =============================================================================
# Threat Intelligence Routes
# =============================================================================


@router.post("/threat-intel/lookup")
def lookup_indicator(
    indicator_type: str,
    indicator_value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Look up an indicator in threat intelligence."""
    threat_intel = ThreatIntelligenceService(db)
    return threat_intel.check_indicator(indicator_type, indicator_value)


@router.post("/threat-intel/indicators", response_model=ThreatIntel)
def add_indicator(
    indicator: ThreatIntelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Add a new threat indicator."""
    threat_intel = ThreatIntelligenceService(db)
    indicator_id = threat_intel.add_threat_indicator(indicator.model_dump())

    from app.models import ThreatIntel

    return db.query(ThreatIntel).filter(ThreatIntel.id == indicator_id).first()


@router.get("/threat-intel/summary")
def get_threat_summary(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get threat intelligence summary."""
    threat_intel = ThreatIntelligenceService(db)
    return threat_intel.get_threat_summary()


@router.post("/threat-intel/correlate")
def correlate_event(
    event_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Correlate an event with threat intelligence."""
    threat_intel = ThreatIntelligenceService(db)
    return threat_intel.correlate_threat(event_data)


# =============================================================================
# AI Decision Engine Routes
# =============================================================================


@router.post("/ai/analyze")
def analyze_threat(
    asset_id: int,
    vulnerability_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Analyze a threat using AI."""
    ai_engine = AIDecisionEngine(db)
    return ai_engine.analyze_threat(
        asset_id=asset_id, vulnerability_id=vulnerability_id
    )


@router.get("/ai/prioritize")
def prioritize_vulnerabilities(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get prioritized vulnerability list."""
    ai_engine = AIDecisionEngine(db)
    return ai_engine.prioritize_vulnerabilities(org_id=current_user.org_id)


@router.get("/ai/attack-prediction")
def predict_attack_paths(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Predict potential attack paths."""
    ai_engine = AIDecisionEngine(db)
    return ai_engine.predict_attack_paths(org_id=current_user.org_id)


@router.get("/ai/posture")
def get_security_posture(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get overall security posture."""
    ai_engine = AIDecisionEngine(db)
    return ai_engine.get_security_posture(org_id=current_user.org_id)


# =============================================================================
# Dashboard Summary Route
# =============================================================================


@router.get("/dashboard/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get overall dashboard summary for security platform."""
    from app.models import Asset, Vulnerability, Alert

    org_id = current_user.org_id

    # Asset counts
    total_assets = (
        db.query(Asset).filter(Asset.org_id == org_id).count()
        if org_id
        else db.query(Asset).count()
    )

    # Vulnerability counts
    vuln_query = db.query(Vulnerability)
    if org_id:
        vuln_query = vuln_query.filter(Vulnerability.org_id == org_id)
    total_vulns = vuln_query.count()
    critical_vulns = vuln_query.filter(Vulnerability.severity == "critical").count()

    # Alert counts
    alert_query = db.query(Alert)
    if org_id:
        alert_query = alert_query.filter(Alert.org_id == org_id)
    open_alerts = alert_query.filter(Alert.status == "open").count()
    critical_alerts = alert_query.filter(
        Alert.severity == "critical", Alert.status == "open"
    ).count()

    # Get attack surface score
    attack_engine = AttackSimulationEngine(db)
    attack_surface = attack_engine.get_attack_surface_score(org_id=org_id or 0)

    # Get security posture
    ai_engine = AIDecisionEngine(db)
    posture = ai_engine.get_security_posture(org_id=org_id or 0)

    return {
        "assets": {
            "total": total_assets,
        },
        "vulnerabilities": {"total": total_vulns, "critical": critical_vulns},
        "alerts": {"open": open_alerts, "critical": critical_alerts},
        "attack_surface": attack_surface,
        "security_posture": posture,
    }
