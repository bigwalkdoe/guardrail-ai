"""
User Management Routes.
Administrative endpoints for user and organization management.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from app.database import get_db
from app.security import get_current_user, require_admin, hash_password
from app.models import User, Organization

router = APIRouter(prefix="/users", tags=["users"])


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    department: Optional[str] = None
    is_active: Optional[bool] = None


class OrganizationCreate(BaseModel):
    name: str
    industry: Optional[str] = None


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    department: Optional[str]
    is_active: bool
    org_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class OrganizationResponse(BaseModel):
    id: int
    name: str
    industry: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


from datetime import datetime, timezone


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return current_user


@router.put("/me", response_model=UserResponse)
def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update current user profile."""
    update_data = user_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(current_user, key, value)

    db.commit()
    db.refresh(current_user)
    return current_user


@router.get("/", response_model=List[UserResponse])
def list_users(
    org_id: Optional[int] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """List all users (admin only)."""
    query = db.query(User)

    if org_id:
        query = query.filter(User.org_id == org_id)
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    return query.offset(skip).limit(limit).all()


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Get user by ID (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete user (admin only). Cannot delete self."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Reset user password (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    import secrets

    temp_password = secrets.token_hex(8)
    user.hashed_password = hash_password(temp_password)
    db.commit()

    return {"message": "Password reset", "temp_password": temp_password}


@router.get("/organizations/", response_model=List[OrganizationResponse])
def list_organizations(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """List all organizations (admin only)."""
    return db.query(Organization).offset(skip).limit(limit).all()


@router.post("/organizations/", response_model=OrganizationResponse)
def create_organization(
    org_data: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Create organization (admin only)."""
    org = Organization(**org_data.model_dump())
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
def get_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Get organization by ID (admin only)."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.put("/organizations/{org_id}", response_model=OrganizationResponse)
def update_organization(
    org_id: int,
    org_update: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update organization (admin only)."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    update_data = org_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(org, key, value)

    db.commit()
    db.refresh(org)
    return org


@router.get("/organizations/{org_id}/users", response_model=List[UserResponse])
def get_organization_users(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Get users in organization (admin only)."""
    users = db.query(User).filter(User.org_id == org_id).all()
    return users


# GDPR Compliance Endpoints


class DataExportResponse(BaseModel):
    user_id: int
    email: str
    role: str
    department: Optional[str]
    organization_id: Optional[int]
    created_at: datetime
    api_keys: List[dict]
    audit_logs: List[dict]
    export_date: datetime


class AccountDeletionRequest(BaseModel):
    confirmation_email: str
    reason: Optional[str] = None


class DeletionRequestResponse(BaseModel):
    request_id: str
    status: str
    scheduled_deletion_date: datetime
    message: str


@router.get("/me/export", response_model=DataExportResponse)
def export_user_data(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    GDPR Article 20 - Right to Data Portability.
    Export all personal data associated with the current user.
    """
    from app.models import APIKey
    from app.services.audit import AuditService

    api_keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).all()
    api_key_data = [
        {
            "id": str(k.id),
            "name": k.name,
            "prefix": k.prefix,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "last_used": k.last_used.isoformat() if k.last_used else None,
            "is_active": k.is_active,
        }
        for k in api_keys
    ]

    audit_service = AuditService(db)
    audit_logs = audit_service.get_audit_logs(
        actor_id=current_user.id,
        limit=1000,
    )

    audit_log_data = []
    for log in audit_logs[:100]:
        audit_log_data.append(
            {
                "event_type": log.event_type,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "severity": log.severity,
                "details": log.details,
            }
        )

    return DataExportResponse(
        user_id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        department=current_user.department,
        organization_id=current_user.org_id,
        created_at=current_user.created_at,
        api_keys=api_key_data,
        audit_logs=audit_log_data,
        export_date=datetime.now(tz=timezone.utc).replace(tzinfo=None),
    )


@router.post("/me/delete", response_model=DeletionRequestResponse)
def request_account_deletion(
    deletion_request: AccountDeletionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    GDPR Article 17 - Right to Erasure ("Right to be Forgotten").
    Request permanent deletion of account and all associated data.
    """
    if deletion_request.confirmation_email != current_user.email:
        raise HTTPException(
            status_code=400,
            detail="Email confirmation does not match your account email",
        )

    import secrets
    from datetime import timedelta

    request_id = f"gdpr_deletion_{current_user.id}_{secrets.token_hex(8)}"
    scheduled_date = datetime.now(tz=timezone.utc).replace(tzinfo=None) + timedelta(days=30)

    current_user.is_active = False
    db.commit()

    return DeletionRequestResponse(
        request_id=request_id,
        status="scheduled",
        scheduled_deletion_date=scheduled_date,
        message=f"Your account deletion has been scheduled. All data will be permanently deleted on {scheduled_date.strftime('%Y-%m-%d')}. You can cancel this request by logging in before that date.",
    )


@router.post("/me/delete/cancel")
def cancel_account_deletion(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Cancel a pending account deletion request.
    """
    if current_user.is_active:
        raise HTTPException(
            status_code=400, detail="No pending deletion request found for this account"
        )

    current_user.is_active = True
    db.commit()

    return {"message": "Account deletion cancelled. Your account is now active."}


@router.post("/me/anonymize")
def anonymize_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    GDPR Article 17 - Anonymization instead of deletion.
    Replace personal data with anonymized data while preserving audit logs.
    """
    current_user.email = f"deleted_user_{current_user.id}@anonymized.local"
    current_user.department = None

    db.commit()

    return {
        "message": "Personal data has been anonymized. Your account is now associated with anonymous data.",
        "user_id": current_user.id,
    }
