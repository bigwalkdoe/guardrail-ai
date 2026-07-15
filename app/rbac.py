"""
Enhanced Role-Based Access Control (RBAC) with granular permissions.
Designed for enterprise multi-tenant environments.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set
from functools import wraps

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Organization, UserRole


class Permission(str, Enum):
    """Granular permissions for the platform."""

    # Asset permissions
    ASSET_READ = "asset:read"
    ASSET_CREATE = "asset:create"
    ASSET_UPDATE = "asset:update"
    ASSET_DELETE = "asset:delete"

    # Vulnerability permissions
    VULN_READ = "vuln:read"
    VULN_CREATE = "vuln:create"
    VULN_UPDATE = "vuln:update"
    VULN_DELETE = "vuln:delete"
    VULN_SCAN = "vuln:scan"

    # Alert permissions
    ALERT_READ = "alert:read"
    ALERT_CREATE = "alert:create"
    ALERT_UPDATE = "alert:update"
    ALERT_DELETE = "alert:delete"
    ALERT_ACKNOWLEDGE = "alert:acknowledge"

    # Attack simulation permissions
    ATTACK_READ = "attack:read"
    ATTACK_CREATE = "attack:create"
    ATTACK_EXECUTE = "attack:execute"

    # Reconnaissance permissions
    RECON_READ = "recon:read"
    RECON_CREATE = "recon:create"
    RECON_EXECUTE = "recon:execute"

    # Threat intelligence permissions
    THREAT_READ = "threat:read"
    THREAT_CREATE = "threat:create"
    THREAT_UPDATE = "threat:update"

    # User management permissions
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

    # Organization permissions
    ORG_READ = "org:read"
    ORG_CREATE = "org:create"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"

    # Policy permissions
    POLICY_READ = "policy:read"
    POLICY_CREATE = "policy:create"
    POLICY_UPDATE = "policy:update"
    POLICY_DELETE = "policy:delete"

    # Report permissions
    REPORT_READ = "report:read"
    REPORT_CREATE = "report:create"
    REPORT_EXPORT = "report:export"

    # Integration permissions
    INTEGRATION_READ = "integration:read"
    INTEGRATION_CREATE = "integration:create"
    INTEGRATION_UPDATE = "integration:update"
    INTEGRATION_DELETE = "integration:delete"

    # Audit log permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Admin permissions
    ADMIN = "admin"
    SYSTEM_CONFIG = "system:config"


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[str, Set[Permission]] = {
    "admin": {
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.ASSET_DELETE,
        Permission.VULN_READ,
        Permission.VULN_CREATE,
        Permission.VULN_UPDATE,
        Permission.VULN_DELETE,
        Permission.VULN_SCAN,
        Permission.ALERT_READ,
        Permission.ALERT_CREATE,
        Permission.ALERT_UPDATE,
        Permission.ALERT_DELETE,
        Permission.ALERT_ACKNOWLEDGE,
        Permission.ATTACK_READ,
        Permission.ATTACK_CREATE,
        Permission.ATTACK_EXECUTE,
        Permission.RECON_READ,
        Permission.RECON_CREATE,
        Permission.RECON_EXECUTE,
        Permission.THREAT_READ,
        Permission.THREAT_CREATE,
        Permission.THREAT_UPDATE,
        Permission.USER_READ,
        Permission.USER_CREATE,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.ORG_READ,
        Permission.ORG_CREATE,
        Permission.ORG_UPDATE,
        Permission.ORG_DELETE,
        Permission.POLICY_READ,
        Permission.POLICY_CREATE,
        Permission.POLICY_UPDATE,
        Permission.POLICY_DELETE,
        Permission.REPORT_READ,
        Permission.REPORT_CREATE,
        Permission.REPORT_EXPORT,
        Permission.INTEGRATION_READ,
        Permission.INTEGRATION_CREATE,
        Permission.INTEGRATION_UPDATE,
        Permission.INTEGRATION_DELETE,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.ADMIN,
        Permission.SYSTEM_CONFIG,
    },
    "security_analyst": {
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.VULN_READ,
        Permission.VULN_CREATE,
        Permission.VULN_UPDATE,
        Permission.VULN_SCAN,
        Permission.ALERT_READ,
        Permission.ALERT_CREATE,
        Permission.ALERT_UPDATE,
        Permission.ALERT_ACKNOWLEDGE,
        Permission.ATTACK_READ,
        Permission.ATTACK_CREATE,
        Permission.ATTACK_EXECUTE,
        Permission.RECON_READ,
        Permission.RECON_CREATE,
        Permission.RECON_EXECUTE,
        Permission.THREAT_READ,
        Permission.THREAT_CREATE,
        Permission.THREAT_UPDATE,
        Permission.USER_READ,
        Permission.USER_CREATE,
        Permission.ORG_READ,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.REPORT_CREATE,
        Permission.REPORT_EXPORT,
        Permission.INTEGRATION_READ,
        Permission.AUDIT_READ,
    },
    "auditor": {
        Permission.ASSET_READ,
        Permission.VULN_READ,
        Permission.ALERT_READ,
        Permission.ATTACK_READ,
        Permission.RECON_READ,
        Permission.THREAT_READ,
        Permission.USER_READ,
        Permission.ORG_READ,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.REPORT_EXPORT,
        Permission.INTEGRATION_READ,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
    },
    "employee": {
        Permission.ASSET_READ,
        Permission.VULN_READ,
        Permission.ALERT_READ,
        Permission.REPORT_READ,
    },
    "viewer": {
        Permission.ASSET_READ,
        Permission.REPORT_READ,
    },
}


class RBACService:
    """Service for checking and managing permissions."""

    @staticmethod
    def get_user_permissions(user: User) -> Set[Permission]:
        """Get all permissions for a user based on their role."""
        role = user.role or "employee"
        return ROLE_PERMISSIONS.get(role, set())

    @staticmethod
    def has_permission(user: User, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        permissions = RBACService.get_user_permissions(user)

        # Admin has all permissions
        if Permission.ADMIN in permissions:
            return True

        return permission in permissions

    @staticmethod
    def has_any_permission(user: User, permissions: List[Permission]) -> bool:
        """Check if user has any of the specified permissions."""
        user_perms = RBACService.get_user_permissions(user)

        # Admin has all permissions
        if Permission.ADMIN in user_perms:
            return True

        return any(p in user_perms for p in permissions)

    @staticmethod
    def has_all_permissions(user: User, permissions: List[Permission]) -> bool:
        """Check if user has all of the specified permissions."""
        user_perms = RBACService.get_user_permissions(user)

        # Admin has all permissions
        if Permission.ADMIN in user_perms:
            return True

        return all(p in user_perms for p in permissions)

    @staticmethod
    def filter_by_permission(items: List, user: User, permission: Permission) -> List:
        """Filter items based on user permission."""
        if RBACService.has_permission(user, permission):
            return items
        return []


def require_permission(permission: Permission):
    """
    Dependency for requiring a specific permission.

    Usage:
        @router.get("/assets")
        @require_permission(Permission.ASSET_READ)
        def get_assets(current_user: User = Depends(get_current_user)):
            ...
    """

    def permission_checker(current_user: User = Depends(get_current_user)):
        if not RBACService.has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return current_user

    return permission_checker


def require_any_permission(*permissions: Permission):
    """
    Dependency for requiring any of the specified permissions.

    Usage:
        @router.get("/alerts")
        @require_any_permission(Permission.ALERT_READ, Permission.ADMIN)
        def get_alerts(current_user: User = Depends(get_current_user)):
            ...
    """

    def permission_checker(current_user: User = Depends(get_current_user)):
        if not RBACService.has_any_permission(current_user, list(permissions)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these permissions required: {permissions}",
            )
        return current_user

    return permission_checker


def require_all_permissions(*permissions: Permission):
    """
    Dependency for requiring all of the specified permissions.
    """

    def permission_checker(current_user: User = Depends(get_current_user)):
        if not RBACService.has_all_permissions(current_user, list(permissions)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"All of these permissions required: {permissions}",
            )
        return current_user

    return permission_checker


def require_org_access(org_id: int):
    """
    Dependency for requiring access to a specific organization.
    """

    def org_access_checker(
        current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
    ):
        # Admin can access any org
        if RBACService.has_permission(current_user, Permission.ADMIN):
            return current_user

        # Check if user belongs to the org
        if current_user.org_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this organization",
            )

        return current_user

    return org_access_checker


class PermissionContext:
    """Context manager for permission checks within a request."""

    def __init__(self, user: User):
        self.user = user
        self._permissions = RBACService.get_user_permissions(user)

    def can(self, permission: Permission) -> bool:
        if Permission.ADMIN in self._permissions:
            return True
        return permission in self._permissions

    def can_any(self, *permissions: Permission) -> bool:
        if Permission.ADMIN in self._permissions:
            return True
        return any(p in self._permissions for p in permissions)

    def can_all(self, *permissions: Permission) -> bool:
        if Permission.ADMIN in self._permissions:
            return True
        return all(p in self._permissions for p in permissions)


# Backward compatibility
def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Legacy admin check - now uses Permission.ADMIN."""
    if not RBACService.has_permission(current_user, Permission.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )
    return current_user


def require_admin_or_auditor(current_user: User = Depends(get_current_user)) -> User:
    """Legacy admin/auditor check."""
    if not RBACService.has_any_permission(
        current_user, [Permission.ADMIN, Permission.AUDIT_READ]
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or auditor access required",
        )
    return current_user
