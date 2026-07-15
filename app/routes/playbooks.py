"""
Playbooks API - Security incident response playbooks
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from app.security import get_current_user
from app.models import User

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


class PlaybookStep(BaseModel):
    order: int
    title: str
    description: str
    automatable: bool = False


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: str
    category: str
    severity: str
    steps: List[dict]
    created_at: datetime
    updated_at: datetime
    is_active: bool = True


class PlaybookCreate(BaseModel):
    name: str
    description: str
    category: str
    severity: str = "medium"
    steps: List[dict]


class PlaybookExecution(BaseModel):
    playbook_id: int
    triggered_by: str
    notes: Optional[str] = None


class ExecutionResponse(BaseModel):
    id: str
    playbook_id: int
    playbook_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    triggered_by: str
    steps_completed: List[int]
    notes: Optional[str]


playbooks_db = [
    {
        "id": 1,
        "name": "Phishing Incident Response",
        "description": "Standard response procedure for reported phishing attempts",
        "category": "Email Security",
        "severity": "high",
        "steps": [
            {
                "order": 1,
                "title": "Isolate Email",
                "description": "Extract and quarantine the suspicious email",
                "automatable": True,
            },
            {
                "order": 2,
                "title": "Analyze Headers",
                "description": "Review email headers for indicators of compromise",
                "automatable": False,
            },
            {
                "order": 3,
                "title": "Check Links",
                "description": "Analyze URLs in the email (do not click)",
                "automatable": True,
            },
            {
                "order": 4,
                "title": "Notify Users",
                "description": "Send alert to organization about the threat",
                "automatable": True,
            },
            {
                "order": 5,
                "title": "Block Sender",
                "description": "Add sender domain/IP to blocklist",
                "automatable": True,
            },
            {
                "order": 6,
                "title": "Document Incident",
                "description": "Record findings in incident log",
                "automatable": False,
            },
        ],
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-02-20T14:30:00Z",
        "is_active": True,
    },
    {
        "id": 2,
        "name": "Malware Outbreak Response",
        "description": "Handle detection of malware on multiple endpoints",
        "category": "Endpoint Security",
        "severity": "critical",
        "steps": [
            {
                "order": 1,
                "title": "Identify Scope",
                "description": "Determine number of affected systems",
                "automatable": True,
            },
            {
                "order": 2,
                "title": "Isolate Network",
                "description": "Segment affected systems from network",
                "automatable": True,
            },
            {
                "order": 3,
                "title": "Collect Samples",
                "description": "Gather malware samples for analysis",
                "automatable": False,
            },
            {
                "order": 4,
                "title": "Update Signatures",
                "description": "Push latest AV definitions",
                "automatable": True,
            },
            {
                "order": 5,
                "title": "Scan All Systems",
                "description": "Run full scan on all endpoints",
                "automatable": True,
            },
            {
                "order": 6,
                "title": "Restore Systems",
                "description": "Reimage or restore from backup",
                "automatable": False,
            },
        ],
        "created_at": "2024-01-20T09:00:00Z",
        "updated_at": "2024-03-01T11:00:00Z",
        "is_active": True,
    },
    {
        "id": 3,
        "name": "Data Breach Response",
        "description": "Procedure for suspected or confirmed data breach",
        "category": "Data Protection",
        "severity": "critical",
        "steps": [
            {
                "order": 1,
                "title": "Confirm Breach",
                "description": "Verify data exfiltration occurred",
                "automatable": False,
            },
            {
                "order": 2,
                "title": "Contain Access",
                "description": "Revoke compromised credentials",
                "automatable": True,
            },
            {
                "order": 3,
                "title": "Preserve Evidence",
                "description": "Collect logs and forensic data",
                "automatable": False,
            },
            {
                "order": 4,
                "title": "Assess Impact",
                "description": "Determine data types and volume exposed",
                "automatable": False,
            },
            {
                "order": 5,
                "title": "Legal Notification",
                "description": "Engage legal counsel",
                "automatable": False,
            },
            {
                "order": 6,
                "title": "Regulatory Reporting",
                "description": "File required reports (72hr GDPR deadline)",
                "automatable": False,
            },
            {
                "order": 7,
                "title": "Customer Notification",
                "description": "Notify affected individuals",
                "automatable": False,
            },
        ],
        "created_at": "2024-02-01T08:00:00Z",
        "updated_at": "2024-02-15T16:00:00Z",
        "is_active": True,
    },
    {
        "id": 4,
        "name": "DDoS Attack Mitigation",
        "description": "Response to denial-of-service attack",
        "category": "Network Security",
        "severity": "high",
        "steps": [
            {
                "order": 1,
                "title": "Verify Attack",
                "description": "Confirm attack is occurring vs normal traffic",
                "automatable": True,
            },
            {
                "order": 2,
                "title": "Enable Scrubbing",
                "description": "Route traffic through DDoS protection",
                "automatable": True,
            },
            {
                "order": 3,
                "title": "Rate Limiting",
                "description": "Apply rate limiting rules",
                "automatable": True,
            },
            {
                "order": 4,
                "title": "Block Bad Actors",
                "description": "IP reputation filtering",
                "automatable": True,
            },
            {
                "order": 5,
                "title": "Scale Infrastructure",
                "description": "Auto-scale resources if possible",
                "automatable": True,
            },
        ],
        "created_at": "2024-02-10T12:00:00Z",
        "updated_at": "2024-02-10T12:00:00Z",
        "is_active": True,
    },
    {
        "id": 5,
        "name": "Insider Threat Investigation",
        "description": "Handle suspected malicious insider activity",
        "category": "Insider Threat",
        "severity": "high",
        "steps": [
            {
                "order": 1,
                "title": "Gather Evidence",
                "description": "Collect logs without alerting user",
                "automatable": False,
            },
            {
                "order": 2,
                "title": "Review Access",
                "description": "Check what data was accessed",
                "automatable": True,
            },
            {
                "order": 3,
                "title": "Consult HR",
                "description": "Coordinate with HR on employment status",
                "automatable": False,
            },
            {
                "order": 4,
                "title": "Preserve Data",
                "description": "Backup relevant data stores",
                "automatable": False,
            },
            {
                "order": 5,
                "title": "Revoke Access",
                "description": "Disable accounts and credentials",
                "automatable": True,
            },
        ],
        "created_at": "2024-03-01T10:00:00Z",
        "updated_at": "2024-03-01T10:00:00Z",
        "is_active": True,
    },
]

executions_db = []
execution_counter = 1


@router.get("/", response_model=List[dict])
def list_playbooks(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List all available playbooks with optional filtering."""
    results = playbooks_db
    if category:
        results = [p for p in results if p["category"].lower() == category.lower()]
    if severity:
        results = [p for p in results if p["severity"].lower() == severity.lower()]
    return results


@router.post("/execute", response_model=dict)
def execute_playbook(
    execution: PlaybookExecution,
    current_user: User = Depends(get_current_user),
):
    """Execute a playbook and track the execution."""
    global execution_counter

    playbook = None
    for p in playbooks_db:
        if p["id"] == execution.playbook_id:
            playbook = p
            break

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    exec_id = f"exec_{execution_counter}"
    execution_counter += 1

    new_execution = {
        "id": exec_id,
        "playbook_id": playbook["id"],
        "playbook_name": playbook["name"],
        "status": "in_progress",
        "started_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "completed_at": None,
        "triggered_by": execution.triggered_by,
        "steps_completed": [],
        "notes": execution.notes,
    }
    executions_db.append(new_execution)
    return new_execution


@router.get("/executions", response_model=List[dict])
def list_executions(
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List playbook executions."""
    results = executions_db
    if status:
        results = [e for e in results if e["status"] == status]
    return sorted(results, key=lambda x: x["started_at"], reverse=True)


@router.get("/executions/{execution_id}", response_model=dict)
def get_execution(
    execution_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get execution details."""
    for execution in executions_db:
        if execution["id"] == execution_id:
            return execution
    raise HTTPException(status_code=404, detail="Execution not found")


@router.put("/executions/{execution_id}")
def update_execution(
    execution_id: str,
    step_completed: int,
    current_user: User = Depends(get_current_user),
):
    """Mark a step as completed in an execution."""
    for execution in executions_db:
        if execution["id"] == execution_id:
            if step_completed not in execution["steps_completed"]:
                execution["steps_completed"].append(step_completed)
            if execution["status"] == "in_progress":
                execution["status"] = "completed"
                execution["completed_at"] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            return execution
    raise HTTPException(status_code=404, detail="Execution not found")


@router.get("/{playbook_id}", response_model=dict)
def get_playbook(
    playbook_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get detailed playbook information."""
    for playbook in playbooks_db:
        if playbook["id"] == playbook_id:
            return playbook
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.post("/", response_model=dict)
def create_playbook(
    playbook: PlaybookCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new playbook (admin only)."""
    global execution_counter
    new_id = len(playbooks_db) + 1
    new_playbook = {
        "id": new_id,
        **playbook.model_dump(),
        "steps": [dict(step, order=i + 1) for i, step in enumerate(playbook.steps)],
        "created_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "updated_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "is_active": True,
    }
    playbooks_db.append(new_playbook)
    return new_playbook
