"""
Incidents API - Track and manage security incidents
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from app.security import get_current_user
from app.models import User

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    category: str
    source: str
    affected_assets: List[str]
    assigned_to: Optional[str]
    timeline: List[dict]
    created_at: str
    updated_at: str
    resolved_at: Optional[str]
    root_cause: Optional[str]
    remediation: Optional[str]


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str
    category: str
    source: str
    affected_assets: List[str] = []


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    root_cause: Optional[str] = None
    remediation: Optional[str] = None


incidents_db = [
    {
        "id": 1,
        "title": "Suspicious login activity from unknown location",
        "description": "Multiple failed login attempts followed by successful login from IP 192.168.1.100 in unexpected location",
        "severity": "high",
        "status": "investigating",
        "category": "Unauthorized Access",
        "source": "SIEM",
        "affected_assets": ["user@acme.com", "VPN Gateway"],
        "assigned_to": "SOC Analyst",
        "timeline": [
            {
                "timestamp": "2024-03-15T10:00:00Z",
                "action": "Alert triggered",
                "user": "system",
            },
            {
                "timestamp": "2024-03-15T10:05:00Z",
                "action": "Incident created",
                "user": "analyst1",
            },
            {
                "timestamp": "2024-03-15T10:15:00Z",
                "action": "Assigned to SOC",
                "user": "manager",
            },
        ],
        "created_at": "2024-03-15T10:00:00Z",
        "updated_at": "2024-03-15T10:15:00Z",
        "resolved_at": None,
        "root_cause": None,
        "remediation": None,
    },
    {
        "id": 2,
        "title": "Malware detected on endpoint HR-WS-042",
        "description": "Trojan detected and quarantined on HR workstation. Initial vector appears to be email attachment",
        "severity": "critical",
        "status": "contained",
        "category": "Malware",
        "source": "EDR",
        "affected_assets": ["HR-WS-042", "File Server Share"],
        "assigned_to": "Endpoint Team",
        "timeline": [
            {
                "timestamp": "2024-03-14T14:30:00Z",
                "action": "Malware detected",
                "user": "EDR",
            },
            {
                "timestamp": "2024-03-14T14:35:00Z",
                "action": "Host isolated",
                "user": "endpoint_team",
            },
            {
                "timestamp": "2024-03-14T15:00:00Z",
                "action": "Forensic image taken",
                "user": "forensics",
            },
            {
                "timestamp": "2024-03-14T16:00:00Z",
                "action": "Malware cleaned",
                "user": "endpoint_team",
            },
        ],
        "created_at": "2024-03-14T14:30:00Z",
        "updated_at": "2024-03-14T16:00:00Z",
        "resolved_at": None,
        "root_cause": "User opened malicious email attachment",
        "remediation": "Endpoint cleaned and restored. User retrained on phishing awareness",
    },
    {
        "id": 3,
        "title": "DDoS attack on public API",
        "description": "Large volume of HTTP flood detected against api.guardrail.ai, peaking at 50K req/s",
        "severity": "high",
        "status": "resolved",
        "category": "DDoS",
        "source": "WAF",
        "affected_assets": ["api.guardrail.ai"],
        "assigned_to": "Network Team",
        "timeline": [
            {
                "timestamp": "2024-03-10T09:00:00Z",
                "action": "Attack detected",
                "user": "WAF",
            },
            {
                "timestamp": "2024-03-10T09:05:00Z",
                "action": "Scrubbing enabled",
                "user": "network_team",
            },
            {
                "timestamp": "2024-03-10T09:30:00Z",
                "action": "Attack mitigated",
                "user": "network_team",
            },
        ],
        "created_at": "2024-03-10T09:00:00Z",
        "updated_at": "2024-03-10T09:30:00Z",
        "resolved_at": "2024-03-10T09:30:00Z",
        "root_cause": "Botnet from compromised IoT devices",
        "remediation": "Rate limiting and geo-blocking rules added to WAF",
    },
    {
        "id": 4,
        "title": "Phishing campaign targeting finance department",
        "description": "10 employees received convincing fake invoice emails. 2 users clicked but credentials not compromised",
        "severity": "medium",
        "status": "resolved",
        "category": "Phishing",
        "source": "Email Gateway",
        "affected_assets": ["Finance Team Email"],
        "assigned_to": "Email Security Team",
        "timeline": [
            {
                "timestamp": "2024-03-12T11:00:00Z",
                "action": "Emails detected and quarantined",
                "user": "email_gateway",
            },
            {
                "timestamp": "2024-03-12T11:30:00Z",
                "action": "Users notified",
                "user": "email_team",
            },
            {
                "timestamp": "2024-03-12T12:00:00Z",
                "action": "Phishing simulation run",
                "user": "security_awareness",
            },
        ],
        "created_at": "2024-03-12T11:00:00Z",
        "updated_at": "2024-03-12T12:00:00Z",
        "resolved_at": "2024-03-12T12:00:00Z",
        "root_cause": "External attacker using compromised vendor email",
        "remediation": "Additional email filtering rules implemented",
    },
    {
        "id": 5,
        "title": "Unauthorized AWS resource creation",
        "description": "New EC2 instances and S3 buckets created using compromised IAM credentials",
        "severity": "critical",
        "status": "investigating",
        "category": "Cloud Security",
        "source": "CloudTrail",
        "affected_assets": ["AWS Production Account"],
        "assigned_to": "Cloud Security Team",
        "timeline": [
            {
                "timestamp": "2024-03-16T08:00:00Z",
                "action": "CloudTrail alert",
                "user": "aws_guardduty",
            },
            {
                "timestamp": "2024-03-16T08:15:00Z",
                "action": "Credentials rotated",
                "user": "cloud_team",
            },
            {
                "timestamp": "2024-03-16T08:30:00Z",
                "action": "Resources terminated",
                "user": "cloud_team",
            },
        ],
        "created_at": "2024-03-16T08:00:00Z",
        "updated_at": "2024-03-16T08:30:00Z",
        "resolved_at": None,
        "root_cause": None,
        "remediation": None,
    },
]


@router.get("/", response_model=List[dict])
def list_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List incidents with filtering."""
    results = incidents_db

    if severity:
        results = [i for i in results if i["severity"] == severity]
    if status:
        results = [i for i in results if i["status"] == status]
    if category:
        results = [i for i in results if i["category"] == category]

    return sorted(results, key=lambda x: x["created_at"], reverse=True)


@router.get("/{incident_id}", response_model=dict)
def get_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get incident details."""
    for incident in incidents_db:
        if incident["id"] == incident_id:
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")


@router.post("/", response_model=dict)
def create_incident(
    incident: IncidentCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new incident."""
    new_id = max(i["id"] for i in incidents_db) + 1
    new_incident = {
        "id": new_id,
        **incident.model_dump(),
        "status": "open",
        "assigned_to": None,
        "timeline": [
            {
                "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                "action": "Incident created",
                "user": current_user.email,
            }
        ],
        "created_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "updated_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "resolved_at": None,
        "root_cause": None,
        "remediation": None,
    }
    incidents_db.append(new_incident)
    return new_incident


@router.put("/{incident_id}", response_model=dict)
def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update incident."""
    for incident in incidents_db:
        if incident["id"] == incident_id:
            if update.status:
                old_status = incident["status"]
                incident["status"] = update.status
                incident["timeline"].append(
                    {
                        "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                        "action": f"Status changed from {old_status} to {update.status}",
                        "user": current_user.email,
                    }
                )
                if update.status == "resolved":
                    incident["resolved_at"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"

            if update.assigned_to:
                incident["assigned_to"] = update.assigned_to
                incident["timeline"].append(
                    {
                        "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                        "action": f"Assigned to {update.assigned_to}",
                        "user": current_user.email,
                    }
                )

            if update.root_cause:
                incident["root_cause"] = update.root_cause

            if update.remediation:
                incident["remediation"] = update.remediation

            incident["updated_at"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            return incident

    raise HTTPException(status_code=404, detail="Incident not found")


@router.post("/{incident_id}/timeline")
def add_timeline_entry(
    incident_id: int,
    action: str,
    current_user: User = Depends(get_current_user),
):
    """Add entry to incident timeline."""
    for incident in incidents_db:
        if incident["id"] == incident_id:
            incident["timeline"].append(
                {
                    "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                    "action": action,
                    "user": current_user.email,
                }
            )
            incident["updated_at"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")


@router.get("/summary/stats")
def get_incident_stats(current_user: User = Depends(get_current_user)):
    """Get incident statistics."""
    stats = {
        "total": len(incidents_db),
        "open": 0,
        "investigating": 0,
        "contained": 0,
        "resolved": 0,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": {},
    }

    for incident in incidents_db:
        status = incident["status"]
        if status in stats:
            stats[status] += 1

        severity = incident["severity"]
        if severity in stats["by_severity"]:
            stats["by_severity"][severity] += 1

        cat = incident["category"]
        if cat not in stats["by_category"]:
            stats["by_category"][cat] = 0
        stats["by_category"][cat] += 1

    return stats
