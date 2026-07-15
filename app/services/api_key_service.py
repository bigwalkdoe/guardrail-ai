"""
API Key Management Service.
Provides API key generation and management for programmatic access.
"""

import secrets
import hashlib
import redis
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from dataclasses import dataclass

from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey

from app.models import APIKey
from app.config import settings


class APIKeyType(str, Enum):
    """API Key types."""

    STANDARD = "standard"
    ADMIN = "admin"
    READ_ONLY = "read_only"
    SERVICE = "service"


class APIKeyStatus(str, Enum):
    """API Key status."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class APIKeyService:
    """Service for API key management."""

    def __init__(self, db: Session):
        self.db = db
        self._redis = None
        if settings.REDIS_URL:
            try:
                self._redis = redis.from_url(settings.REDIS_URL)
            except:
                pass

    def _hash_key(self, key: str) -> str:
        """Hash API key for storage."""
        return hashlib.sha256(key.encode()).hexdigest()

    def _generate_key(self) -> tuple[str, str]:
        """Generate new API key and prefix."""
        key = f"gr_{secrets.token_urlsafe(32)}"
        prefix = key[:16]
        return key, prefix

    def create_key(
        self,
        user_id: int,
        name: str,
        key_type: APIKeyType = APIKeyType.STANDARD,
        expires_days: Optional[int] = None,
        rate_limit: int = 1000,
        allowed_ips: Optional[List[str]] = None,
        allowed_origins: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create new API key."""
        key, prefix = self._generate_key()
        key_hash = self._hash_key(key)

        expires_at = None
        if expires_days:
            expires_at = datetime.now(tz=timezone.utc).replace(tzinfo=None) + timedelta(days=expires_days)

        api_key = APIKey(
            user_id=user_id,
            name=name,
            key_type=key_type.value,
            key_hash=key_hash,
            key_prefix=prefix,
            expires_at=expires_at,
            rate_limit=rate_limit,
            allowed_ips=",".join(allowed_ips) if allowed_ips else None,
            allowed_origins=",".join(allowed_origins) if allowed_origins else None,
        )

        self.db.add(api_key)
        self.db.commit()
        self.db.refresh(api_key)

        return {
            "id": api_key.id,
            "name": api_key.name,
            "key": key,
            "prefix": prefix,
            "key_type": api_key.key_type,
            "expires_at": api_key.expires_at.isoformat()
            if api_key.expires_at
            else None,
            "rate_limit": api_key.rate_limit,
            "created_at": api_key.created_at.isoformat(),
        }

    def validate_key(
        self, key: str, ip_address: Optional[str] = None
    ) -> Optional[APIKey]:
        """Validate API key."""
        key_hash = self._hash_key(key)

        api_key = (
            self.db.query(APIKey)
            .filter(
                APIKey.key_hash == key_hash,
                APIKey.status == APIKeyStatus.ACTIVE.value,
            )
            .first()
        )

        if not api_key:
            return None

        if api_key.expires_at and api_key.expires_at < datetime.now(tz=timezone.utc).replace(tzinfo=None):
            api_key.status = APIKeyStatus.EXPIRED.value
            self.db.commit()
            return None

        if api_key.allowed_ips and ip_address:
            allowed = api_key.allowed_ips.split(",")
            if ip_address not in allowed:
                return None

        api_key.last_used_at = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        self.db.commit()

        return api_key

    def check_rate_limit(self, api_key: APIKey) -> bool:
        """Check if API key has rate limit available (sliding window via Redis)."""
        if not self._redis:
            return True

        return self._check_sliding_window(f"apikey_rate:{api_key.id}", api_key.rate_limit, 60)

    def _check_sliding_window(self, key: str, max_requests: int, window_seconds: int = 60) -> bool:
        """Sliding window rate limit check using Redis sorted sets."""
        import time as time_module
        now = time_module.time()
        window_start = now - window_seconds

        self._redis.zremrangebyscore(key, 0, window_start)
        current = self._redis.zcard(key)

        if current >= max_requests:
            return False

        self._redis.zadd(key, {str(now): now})
        self._redis.expire(key, window_seconds * 2)
        return True

    def get_rate_limit_info(self, key_id: int) -> Dict[str, Any]:
        """Get current rate limit status for a key."""
        api_key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
        if not api_key:
            return {"error": "Key not found"}

        remaining = api_key.rate_limit
        reset = 60

        if self._redis:
            import time as time_module
            now = time_module.time()
            window_start = now - 60
            key = f"apikey_rate:{api_key.id}"
            self._redis.zremrangebyscore(key, 0, window_start)
            current = self._redis.zcard(key)
            remaining = max(0, api_key.rate_limit - current)
            ttl = self._redis.ttl(key)
            reset = max(0, int(ttl)) if ttl > 0 else 60

        return {
            "key_id": key_id,
            "limit": api_key.rate_limit,
            "remaining": remaining,
            "reset_seconds": reset,
            "window_seconds": 60,
        }

    def list_keys(
        self,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List API keys."""
        query = self.db.query(APIKey)

        if user_id:
            query = query.filter(APIKey.user_id == user_id)
        if status:
            query = query.filter(APIKey.status == status)

        keys = query.order_by(APIKey.created_at.desc()).all()

        return [
            {
                "id": k.id,
                "name": k.name,
                "key_type": k.key_type,
                "prefix": k.key_prefix,
                "status": k.status,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "created_at": k.created_at.isoformat(),
                "rate_limit": k.rate_limit,
            }
            for k in keys
        ]

    def revoke_key(self, key_id: int) -> bool:
        """Revoke API key."""
        api_key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
        if not api_key:
            return False

        api_key.status = APIKeyStatus.REVOKED.value
        self.db.commit()
        return True

    def delete_key(self, key_id: int) -> bool:
        """Delete API key."""
        api_key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
        if not api_key:
            return False

        self.db.delete(api_key)
        self.db.commit()
        return True

    def rotate_key(self, key_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Rotate API key: generate a new key value while preserving metadata."""
        api_key = self.db.query(APIKey).filter(APIKey.id == key_id).first()
        if not api_key:
            return None

        new_key, new_prefix = self._generate_key()
        new_hash = self._hash_key(new_key)

        api_key.key_hash = new_hash
        api_key.key_prefix = new_prefix
        self.db.commit()

        return {
            "id": api_key.id,
            "name": api_key.name,
            "key": new_key,
            "prefix": new_prefix,
            "key_type": api_key.key_type,
            "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
            "rate_limit": api_key.rate_limit,
            "created_at": api_key.created_at.isoformat(),
        }
