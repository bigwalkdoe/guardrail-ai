"""
Comprehensive health check endpoints for microservices.
Includes dependency health checks for production deployments.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.config import settings
from app.database import engine
from app.security import get_current_user
from app.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


class ComponentHealth(BaseModel):
    """Health status of a single component."""

    name: str
    status: str  # healthy, degraded, unhealthy
    latency_ms: float = 0
    details: str = ""


class SystemHealth(BaseModel):
    """Overall system health response."""

    status: str  # healthy, degraded, unhealthy
    timestamp: str
    version: str
    components: List[ComponentHealth]


def check_database() -> ComponentHealth:
    """Check PostgreSQL connection."""
    import time

    start = time.time()

    try:
        from sqlalchemy import text

        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency = (time.time() - start) * 1000
        return ComponentHealth(
            name="database",
            status="healthy",
            latency_ms=round(latency, 2),
            details="PostgreSQL connection OK",
        )
    except Exception as e:
        return ComponentHealth(
            name="database",
            status="unhealthy",
            latency_ms=0,
            details=f"Connection failed: {str(e)[:100]}",
        )


def check_redis() -> ComponentHealth:
    """Check Redis connection."""
    import time

    start = time.time()

    try:
        from app.services.cache import cache

        if cache.is_connected:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="cache",
                status="healthy",
                latency_ms=round(latency, 2),
                details="Redis connection OK",
            )
        else:
            return ComponentHealth(
                name="cache",
                status="unhealthy",
                latency_ms=0,
                details="Redis not connected",
            )
    except Exception as e:
        return ComponentHealth(
            name="cache",
            status="unhealthy",
            latency_ms=0,
            details=f"Connection failed: {str(e)[:100]}",
        )


def check_neo4j() -> ComponentHealth:
    """Check Neo4j connection."""
    import time

    start = time.time()

    try:
        from app.neo4j_client import get_neo4j_client

        client = get_neo4j_client()
        if client.connect():
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="graph_db",
                status="healthy",
                latency_ms=round(latency, 2),
                details="Neo4j connection OK",
            )
        return ComponentHealth(
            name="graph_db",
            status="unhealthy",
            latency_ms=0,
            details="Neo4j driver not initialized",
        )
    except Exception as e:
        return ComponentHealth(
            name="graph_db",
            status="unhealthy",
            latency_ms=0,
            details=f"Connection failed: {str(e)[:100]}",
        )


def check_celery() -> ComponentHealth:
    """Check Celery worker availability."""
    import time

    start = time.time()

    try:
        from app.celery_app import celery_app

        inspect = celery_app.control.inspect()
        stats = inspect.stats()

        if stats:
            latency = (time.time() - start) * 1000
            worker_count = len(stats)
            return ComponentHealth(
                name="celery",
                status="healthy",
                latency_ms=round(latency, 2),
                details=f"{worker_count} worker(s) active",
            )
        return ComponentHealth(
            name="celery",
            status="degraded",
            latency_ms=0,
            details="No workers available",
        )
    except Exception as e:
        return ComponentHealth(
            name="celery",
            status="unhealthy",
            latency_ms=0,
            details=f"Connection failed: {str(e)[:100]}",
        )


@router.get("", response_model=SystemHealth)
def health_check():
    """
    Main health check endpoint.
    Returns status of all system components.
    """
    components = []

    # Check all components
    db_health = check_database()
    components.append(db_health)

    redis_health = check_redis()
    components.append(redis_health)

    neo4j_health = check_neo4j()
    components.append(neo4j_health)

    celery_health = check_celery()
    components.append(celery_health)

    # Determine overall status
    statuses = [c.status for c in components]
    if "unhealthy" in statuses:
        overall_status = "unhealthy"
    elif "degraded" in statuses:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return SystemHealth(
        status=overall_status,
        timestamp=datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
        version="1.0.0",
        components=components,
    )


@router.get("/live")
def liveness_check():
    """Kubernetes liveness probe - simple check if app is running."""
    return {"status": "alive", "timestamp": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat()}


@router.get("/ready", response_model=SystemHealth)
def readiness_check():
    """
    Kubernetes readiness probe - checks if app can serve traffic.
    """
    # Only check critical dependencies for readiness
    components = []

    db_health = check_database()
    components.append(db_health)

    # Only mark ready if database is healthy
    if db_health.status != "healthy":
        return SystemHealth(
            status="not_ready",
            timestamp=datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
            version="1.0.0",
            components=components,
        )

    return SystemHealth(
        status="ready",
        timestamp=datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat(),
        version="1.0.0",
        components=components,
    )


@router.get("/components")
def component_status(
    current_user: User = Depends(get_current_user),
):
    """Detailed component status for admin dashboard."""
    return {
        "database": check_database(),
        "cache": check_redis(),
        "graph_db": check_neo4j(),
        "celery": check_celery(),
    }
