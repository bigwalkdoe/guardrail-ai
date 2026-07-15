"""
API Keys Management Routes.
Endpoints for creating and managing API keys for programmatic access.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel

from app.database import get_db
from app.security import get_current_user, require_admin
from app.models import User
from app.services.api_key_service import APIKeyService, APIKeyType

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class APIKeyCreate(BaseModel):
    name: str
    key_type: str = "standard"
    expires_days: Optional[int] = None
    rate_limit: int = 1000
    allowed_ips: Optional[List[str]] = None
    allowed_origins: Optional[List[str]] = None


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key: str
    prefix: str
    key_type: str
    expires_at: Optional[str]
    rate_limit: int
    created_at: str


class APIKeyListItem(BaseModel):
    id: int
    name: str
    key_type: str
    prefix: str
    status: str
    expires_at: Optional[str]
    last_used_at: Optional[str]
    created_at: str
    rate_limit: int


@router.post("/", response_model=APIKeyResponse)
def create_api_key(
    key_data: APIKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create new API key."""
    service = APIKeyService(db)

    try:
        key_type = APIKeyType(key_data.key_type)
    except:
        key_type = APIKeyType.STANDARD

    result = service.create_key(
        user_id=current_user.id,
        name=key_data.name,
        key_type=key_type,
        expires_days=key_data.expires_days,
        rate_limit=key_data.rate_limit,
        allowed_ips=key_data.allowed_ips,
        allowed_origins=key_data.allowed_origins,
    )

    return result


@router.get("/", response_model=List[APIKeyListItem])
def list_api_keys(
    user_id: Optional[int] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List API keys. Users see their own keys, admins see all."""
    if current_user.role != "admin" and user_id and user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Cannot view other users' keys")

    if current_user.role != "admin":
        user_id = current_user.id

    service = APIKeyService(db)
    return service.list_keys(user_id=user_id, status=status)


@router.delete("/{key_id}")
def delete_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete API key."""
    service = APIKeyService(db)

    keys = service.list_keys(
        user_id=current_user.id if current_user.role != "admin" else None
    )
    key_ids = [k["id"] for k in keys]

    if key_id not in key_ids and current_user.role != "admin":
        raise HTTPException(status_code=404, detail="API key not found")

    success = service.delete_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")

    return {"message": "API key deleted successfully"}


@router.post("/{key_id}/rotate")
def rotate_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Rotate API key: generate new key value while preserving metadata."""
    service = APIKeyService(db)

    keys = service.list_keys(
        user_id=current_user.id if current_user.role != "admin" else None
    )
    key_ids = [k["id"] for k in keys]

    if key_id not in key_ids and current_user.role != "admin":
        raise HTTPException(status_code=404, detail="API key not found")

    result = service.rotate_key(key_id, current_user.id)
    if not result:
        raise HTTPException(status_code=404, detail="API key not found")

    return result


@router.post("/{key_id}/revoke")
def revoke_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Revoke API key."""
    service = APIKeyService(db)

    success = service.revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")

    return {"message": "API key revoked successfully"}


def verify_api_key(db: Session, api_key: str, ip_address: Optional[str] = None):
    """Verify API key for programmatic access."""
    service = APIKeyService(db)

    key = service.validate_key(api_key, ip_address)
    if not key:
        return None

    if not service.check_rate_limit(key):
        return None

    return key


@router.get("/{key_id}/rate-limit")
def get_key_rate_limit(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current rate limit status for an API key."""
    service = APIKeyService(db)

    keys = service.list_keys(
        user_id=current_user.id if current_user.role != "admin" else None
    )
    key_ids = [k["id"] for k in keys]

    if key_id not in key_ids and current_user.role != "admin":
        raise HTTPException(status_code=404, detail="API key not found")

    return service.get_rate_limit_info(key_id)
