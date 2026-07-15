"""
Redis Cache Service.
Provides distributed caching for API responses and session management.
"""

import json
import logging
import pickle
from datetime import timedelta
from functools import wraps
from typing import Any, Callable, Optional, Union
from dataclasses import dataclass

import redis
from redis.connection import ConnectionPool

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class CacheConfig:
    """Redis cache configuration."""

    enabled: bool = True
    default_ttl: int = 300  # 5 minutes
    key_prefix: str = "guardrail:"
    max_connections: int = 50


class RedisCache:
    """
    Redis-based distributed cache service.
    Supports caching, pub/sub, and session management.
    """

    _instance: Optional["RedisCache"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.config = CacheConfig(
            enabled=bool(settings.REDIS_URL),
            default_ttl=int(getattr(settings, "CACHE_TTL", 300)),
            key_prefix=getattr(settings, "CACHE_PREFIX", "guardrail:"),
            max_connections=int(getattr(settings, "REDIS_MAX_CONNECTIONS", 50)),
        )

        self._client: Optional[redis.Redis] = None
        self._pool: Optional[ConnectionPool] = None
        self._connect()

    def _connect(self):
        """Initialize Redis connection."""
        if not self.config.enabled or not settings.REDIS_URL:
            logger.warning("Redis not configured - caching disabled")
            return

        try:
            self._pool = ConnectionPool.from_url(
                settings.REDIS_URL,
                max_connections=self.config.max_connections,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            self._client = redis.Redis(connection_pool=self._pool)
            self._client.ping()
            logger.info(f"Redis cache connected: {settings.REDIS_URL}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._client = None

    @property
    def is_connected(self) -> bool:
        """Check if Redis is connected."""
        if not self._client:
            return False
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def _get_key(self, key: str) -> str:
        """Generate full cache key with prefix."""
        return f"{self.config.key_prefix}{key}"

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if not self.is_connected:
            return None

        try:
            full_key = self._get_key(key)
            value = self._client.get(full_key)
            if value is None:
                return None

            # Try to deserialize JSON, fallback to pickle
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return pickle.loads(value.encode("utf-8"))
        except Exception as e:
            logger.error(f"Cache get error for {key}: {e}")
            return None

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        nx: bool = False,
    ) -> bool:
        """Set value in cache with optional TTL."""
        if not self.is_connected:
            return False

        try:
            full_key = self._get_key(key)
            ttl = ttl or self.config.default_ttl

            # Serialize as JSON, fallback to pickle
            try:
                serialized = json.dumps(value)
            except (TypeError, ValueError):
                serialized = pickle.dumps(value).decode("utf-8")

            if nx:
                return bool(self._client.setex(full_key, ttl, serialized))
            else:
                self._client.setex(full_key, ttl, serialized)
                return True
        except Exception as e:
            logger.error(f"Cache set error for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        if not self.is_connected:
            return False

        try:
            return bool(self._client.delete(self._get_key(key)))
        except Exception as e:
            logger.error(f"Cache delete error for {key}: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        if not self.is_connected:
            return False

        try:
            return bool(self._client.exists(self._get_key(key)))
        except Exception as e:
            logger.error(f"Cache exists error for {key}: {e}")
            return False

    def expire(self, key: str, ttl: int) -> bool:
        """Set expiration time for key."""
        if not self.is_connected:
            return False

        try:
            return bool(self._client.expire(self._get_key(key), ttl))
        except Exception as e:
            logger.error(f"Cache expire error for {key}: {e}")
            return False

    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern."""
        if not self.is_connected:
            return 0

        try:
            full_pattern = self._get_key(pattern)
            keys = self._client.keys(full_pattern)
            if keys:
                return self._client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache clear pattern error for {pattern}: {e}")
            return 0

    def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter in cache."""
        if not self.is_connected:
            return None

        try:
            return self._client.incrby(self._get_key(key), amount)
        except Exception as e:
            logger.error(f"Cache increment error for {key}: {e}")
            return None

    def get_hash(self, key: str) -> dict:
        """Get all fields from hash."""
        if not self.is_connected:
            return {}

        try:
            return self._client.hgetall(self._get_key(key))
        except Exception as e:
            logger.error(f"Cache hash get error for {key}: {e}")
            return {}

    def set_hash(self, key: str, mapping: dict, ttl: Optional[int] = None) -> bool:
        """Set hash fields."""
        if not self.is_connected:
            return False

        try:
            full_key = self._get_key(key)
            self._client.hset(full_key, mapping=mapping)
            if ttl:
                self._client.expire(full_key, ttl)
            return True
        except Exception as e:
            logger.error(f"Cache hash set error for {key}: {e}")
            return False

    def publish(self, channel: str, message: Any) -> int:
        """Publish message to channel."""
        if not self.is_connected:
            return 0

        try:
            serialized = json.dumps(message)
            return self._client.publish(channel, serialized)
        except Exception as e:
            logger.error(f"Cache publish error for {channel}: {e}")
            return 0

    def subscribe(self, channel: str) -> Optional[redis.client.PubSub]:
        """Subscribe to channel."""
        if not self.is_connected:
            return None

        try:
            return self._client.pubsub()
        except Exception as e:
            logger.error(f"Cache subscribe error for {channel}: {e}")
            return None


# Global cache instance
cache = RedisCache()


def cached(
    key: str,
    ttl: Optional[int] = None,
    unless: Optional[Callable] = None,
):
    """
    Decorator to cache function results.

    Usage:
        @cached("user:{user_id}", ttl=600)
        def get_user(user_id: int):
            return database.query(User).get(user_id)
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            cache_key = key.format(*args, **kwargs)

            # Check condition to skip caching
            if callable(unless) and unless(*args, **kwargs):
                return func(*args, **kwargs)

            # Try to get from cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit: {cache_key}")
                return cached_value

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl=ttl)
            logger.debug(f"Cache miss: {cache_key}")

            return result

        return wrapper

    return decorator


def invalidate_cache(key: str):
    """Decorator helper to invalidate specific cache key."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            full_key = key.format(*args, **kwargs)
            cache.delete(full_key)
            return result

        return wrapper

    return decorator
