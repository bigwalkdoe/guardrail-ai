"""
Policies API - Security policies and compliance
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from app.security import get_current_user
from app.models import User

router = APIRouter(prefix="/policies", tags=["policies"])


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: str
    category: str
    status: str
    severity: str
    version: str
    owner: str
    approvers: List[str]
    created_at: str
    updated_at: str
    effective_date: Optional[str]
    last_reviewed: Optional[str]


class PolicyCreate(BaseModel):
    name: str
    description: str
    category: str
    severity: str = "medium"
    owner: str
    approvers: List[str]
    effective_date: Optional[str] = None


policies_db = [
    {
        "id": 1,
        "name": "Password Policy",
        "description": "Minimum requirements for password complexity and rotation",
        "category": "Access Control",
        "status": "active",
        "severity": "high",
        "version": "2.3",
        "owner": "IT Security",
        "approvers": ["CISO", "IT Director"],
        "created_at": "2024-01-10T10:00:00Z",
        "updated_at": "2024-03-01T14:00:00Z",
        "effective_date": "2024-01-15",
        "last_reviewed": "2024-03-01",
    },
    {
        "id": 2,
        "name": "Data Classification Policy",
        "description": "Guidelines for classifying and handling sensitive data",
        "category": "Data Protection",
        "status": "active",
        "severity": "high",
        "version": "1.8",
        "owner": "Data Governance",
        "approvers": ["CISO", "DPO", "Legal"],
        "created_at": "2024-01-15T09:00:00Z",
        "updated_at": "2024-02-20T11:00:00Z",
        "effective_date": "2024-02-01",
        "last_reviewed": "2024-02-20",
    },
    {
        "id": 3,
        "name": "Acceptable Use Policy",
        "description": "Rules for acceptable use of company IT resources",
        "category": "Compliance",
        "status": "active",
        "severity": "medium",
        "version": "3.1",
        "owner": "IT Operations",
        "approvers": ["HR Director", "CISO"],
        "created_at": "2023-11-01T08:00:00Z",
        "updated_at": "2024-01-15T10:00:00Z",
        "effective_date": "2023-11-15",
        "last_reviewed": "2024-01-15",
    },
    {
        "id": 4,
        "name": "Incident Response Policy",
        "description": "Procedures for handling security incidents",
        "category": "Security Operations",
        "status": "active",
        "severity": "critical",
        "version": "2.1",
        "owner": "SOC Team",
        "approvers": ["CISO", "CTO", "CEO"],
        "created_at": "2024-01-05T11:00:00Z",
        "updated_at": "2024-03-10T09:00:00Z",
        "effective_date": "2024-01-10",
        "last_reviewed": "2024-03-10",
    },
    {
        "id": 5,
        "name": "Remote Work Policy",
        "description": "Security requirements for remote access",
        "category": "Access Control",
        "status": "draft",
        "severity": "medium",
        "version": "0.9",
        "owner": "HR + IT Security",
        "approvers": ["CISO", "HR Director"],
        "created_at": "2024-03-15T14:00:00Z",
        "updated_at": "2024-03-15T14:00:00Z",
        "effective_date": None,
        "last_reviewed": None,
    },
    {
        "id": 6,
        "name": "API Security Policy",
        "description": "Standards for API development and consumption",
        "category": "Application Security",
        "status": "active",
        "severity": "high",
        "version": "1.2",
        "owner": "API Team",
        "approvers": ["CISO", "Engineering Lead"],
        "created_at": "2024-02-01T10:00:00Z",
        "updated_at": "2024-02-28T16:00:00Z",
        "effective_date": "2024-02-15",
        "last_reviewed": "2024-02-28",
    },
]


@router.get("/", response_model=List[dict])
def list_policies(
    category: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List policies with optional filtering."""
    results = policies_db

    if category:
        results = [p for p in results if p["category"] == category]
    if status:
        results = [p for p in results if p["status"] == status]
    if search:
        search_lower = search.lower()
        results = [p for p in results if search_lower in p["name"].lower()]

    return results


@router.get("/{policy_id}", response_model=dict)
def get_policy(
    policy_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get policy details."""
    for policy in policies_db:
        if policy["id"] == policy_id:
            return policy
    raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/", response_model=dict)
def create_policy(
    policy: PolicyCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new policy."""
    new_id = max(p["id"] for p in policies_db) + 1
    new_policy = {
        "id": new_id,
        **policy.model_dump(),
        "status": "draft",
        "version": "0.1",
        "created_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "updated_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "last_reviewed": None,
    }
    policies_db.append(new_policy)
    return new_policy


@router.put("/{policy_id}/approve")
def approve_policy(
    policy_id: int,
    current_user: User = Depends(get_current_user),
):
    """Approve a policy."""
    for policy in policies_db:
        if policy["id"] == policy_id:
            policy["status"] = "active"
            policy["updated_at"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            if not policy.get("effective_date"):
                policy["effective_date"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat()[:10]
            return policy
    raise HTTPException(status_code=404, detail="Policy not found")


@router.put("/{policy_id}/review")
def review_policy(
    policy_id: int,
    current_user: User = Depends(get_current_user),
):
    """Mark policy as reviewed."""
    for policy in policies_db:
        if policy["id"] == policy_id:
            policy["last_reviewed"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat()[:10]
            policy["updated_at"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            return policy
    raise HTTPException(status_code=404, detail="Policy not found")


@router.get("/summary/categories")
def get_category_summary(current_user: User = Depends(get_current_user)):
    """Get policy count by category."""
    categories = {}
    for policy in policies_db:
        cat = policy["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "active": 0, "draft": 0}
        categories[cat]["total"] += 1
        if policy["status"] == "active":
            categories[cat]["active"] += 1
        else:
            categories[cat]["draft"] += 1
    return categories
