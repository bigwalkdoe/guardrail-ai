"""
Configuration Scanner API - Scan for security misconfigurations
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from app.security import get_current_user
from app.models import User

router = APIRouter(prefix="/config-scan", tags=["config-scanner"])


class ScanResult(BaseModel):
    id: int
    resource_type: str
    resource_name: str
    check_name: str
    status: str
    severity: str
    description: str
    recommendation: str
    detected_at: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    started_at: str
    completed_at: Optional[str]
    resources_scanned: int
    findings: List[dict]
    summary: dict


class ScanConfig(BaseModel):
    target: str
    resource_types: List[str] = ["cloud", "network", "application", "database"]


scan_results_db = [
    {
        "id": 1,
        "resource_type": "cloud",
        "resource_name": "AWS Production Account",
        "check_name": "MFA Not Enabled on Root",
        "status": "fail",
        "severity": "critical",
        "description": "Root account does not have MFA enabled",
        "recommendation": "Enable MFA on root account immediately",
        "detected_at": "2024-03-15T10:00:00Z",
    },
    {
        "id": 2,
        "resource_type": "cloud",
        "resource_name": "AWS Production Account",
        "check_name": "S3 Bucket Public Access",
        "status": "warning",
        "severity": "high",
        "description": "Bucket 'logs-archive' has public access enabled",
        "recommendation": "Disable public access or restrict to specific IPs",
        "detected_at": "2024-03-15T10:00:00Z",
    },
    {
        "id": 3,
        "resource_type": "network",
        "resource_name": "Firewall Policy Default",
        "check_name": "Allow All Outbound",
        "status": "warning",
        "severity": "medium",
        "description": "Default outbound rule allows all traffic",
        "recommendation": "Implement least-privilege outbound rules",
        "detected_at": "2024-03-14T14:00:00Z",
    },
    {
        "id": 4,
        "resource_type": "database",
        "resource_name": "PostgreSQL prod-db-01",
        "check_name": "SSL Not Enforced",
        "status": "fail",
        "severity": "high",
        "description": "Database connections can use unencrypted channels",
        "recommendation": "Enforce SSL/TLS in database configuration",
        "detected_at": "2024-03-14T09:00:00Z",
    },
    {
        "id": 5,
        "resource_type": "application",
        "resource_name": "API Gateway",
        "check_name": "Rate Limiting Disabled",
        "status": "warning",
        "severity": "medium",
        "description": "No rate limiting configured on public endpoints",
        "recommendation": "Configure rate limits to prevent abuse",
        "detected_at": "2024-03-13T16:00:00Z",
    },
    {
        "id": 6,
        "resource_type": "cloud",
        "resource_name": "AWS Production Account",
        "check_name": "Unused IAM Users",
        "status": "info",
        "severity": "low",
        "description": "3 IAM users have not logged in for 90+ days",
        "recommendation": "Review and disable inactive IAM users",
        "detected_at": "2024-03-12T11:00:00Z",
    },
    {
        "id": 7,
        "resource_type": "network",
        "resource_name": "VPN Gateway",
        "check_name": "Split Tunneling Enabled",
        "status": "fail",
        "severity": "high",
        "description": "VPN allows split tunneling which may leak traffic",
        "recommendation": "Disable split tunneling for corporate VPN",
        "detected_at": "2024-03-11T08:00:00Z",
    },
    {
        "id": 8,
        "resource_type": "application",
        "resource_name": "Web App Firewall",
        "check_name": "OWASP Top 10 Disabled",
        "status": "fail",
        "severity": "critical",
        "description": "WAF is not blocking OWASP Top 10 threats",
        "recommendation": "Enable OWASP Top 10 protection rules",
        "detected_at": "2024-03-10T15:00:00Z",
    },
    {
        "id": 9,
        "resource_type": "database",
        "resource_name": "Redis Cache Cluster",
        "check_name": "Password Not Set",
        "status": "fail",
        "severity": "critical",
        "description": "Redis cluster accessible without authentication",
        "recommendation": "Enable password authentication immediately",
        "detected_at": "2024-03-09T12:00:00Z",
    },
    {
        "id": 10,
        "resource_type": "cloud",
        "resource_name": "Kubernetes Cluster",
        "check_name": "Anonymous API Access",
        "status": "fail",
        "severity": "high",
        "description": "Anonymous access to Kubernetes API server is enabled",
        "recommendation": "Disable anonymous access and use RBAC",
        "detected_at": "2024-03-08T10:00:00Z",
    },
]


scan_counter = 1


@router.get("/results", response_model=List[dict])
def list_scan_results(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    resource_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List configuration scan results."""
    results = scan_results_db

    if severity:
        results = [r for r in results if r["severity"] == severity]
    if status:
        results = [r for r in results if r["status"] == status]
    if resource_type:
        results = [r for r in results if r["resource_type"] == resource_type]

    return results


@router.get("/results/{result_id}", response_model=dict)
def get_scan_result(
    result_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get specific scan result."""
    for result in scan_results_db:
        if result["id"] == result_id:
            return result
    raise HTTPException(status_code=404, detail="Result not found")


@router.post("/scan", response_model=dict)
def start_scan(
    config: ScanConfig,
    current_user: User = Depends(get_current_user),
):
    """Start a new configuration scan."""
    global scan_counter

    scan_id = f"scan_{scan_counter}"
    scan_counter += 1

    # Simulate scanning different resource types
    relevant_results = []
    if "cloud" in config.resource_types:
        relevant_results.extend(
            [r for r in scan_results_db if r["resource_type"] == "cloud"]
        )
    if "network" in config.resource_types:
        relevant_results.extend(
            [r for r in scan_results_db if r["resource_type"] == "network"]
        )
    if "application" in config.resource_types:
        relevant_results.extend(
            [r for r in scan_results_db if r["resource_type"] == "application"]
        )
    if "database" in config.resource_types:
        relevant_results.extend(
            [r for r in scan_results_db if r["resource_type"] == "database"]
        )

    summary = {
        "total": len(relevant_results),
        "critical": len([r for r in relevant_results if r["severity"] == "critical"]),
        "high": len([r for r in relevant_results if r["severity"] == "high"]),
        "medium": len([r for r in relevant_results if r["severity"] == "medium"]),
        "low": len([r for r in relevant_results if r["severity"] == "low"]),
        "fail": len([r for r in relevant_results if r["status"] == "fail"]),
        "warning": len([r for r in relevant_results if r["status"] == "warning"]),
        "info": len([r for r in relevant_results if r["status"] == "info"]),
    }

    return {
        "scan_id": scan_id,
        "status": "completed",
        "target": config.target,
        "started_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "completed_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "resources_scanned": len(set(r["resource_name"] for r in relevant_results)),
        "findings": relevant_results,
        "summary": summary,
    }


@router.get("/summary", response_model=dict)
def get_scan_summary(current_user: User = Depends(get_current_user)):
    """Get overall scan summary."""
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_type = {"cloud": 0, "network": 0, "application": 0, "database": 0}
    by_status = {"fail": 0, "warning": 0, "info": 0}

    for result in scan_results_db:
        by_severity[result["severity"]] += 1
        by_type[result["resource_type"]] += 1
        by_status[result["status"]] += 1

    return {
        "total_findings": len(scan_results_db),
        "by_severity": by_severity,
        "by_type": by_type,
        "by_status": by_status,
        "compliance_score": max(
            0, 100 - (by_status["fail"] * 10) - (by_status["warning"] * 5)
        ),
    }


@router.get("/remediation/{result_id}")
def get_remediation(
    result_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get remediation steps for a finding."""
    for result in scan_results_db:
        if result["id"] == result_id:
            return {
                "finding": result["check_name"],
                "severity": result["severity"],
                "recommendation": result["recommendation"],
                "auto_remediable": result["severity"] in ["high", "critical"],
                "steps": [
                    f"1. Review {result['resource_name']} configuration",
                    f"2. Apply security control: {result['recommendation']}",
                    f"3. Verify change with re-scan",
                    "4. Document in compliance system",
                ],
            }
    raise HTTPException(status_code=404, detail="Result not found")
