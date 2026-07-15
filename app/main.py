from fastapi import FastAPI, Request, Response, Depends
from contextlib import asynccontextmanager
import uuid
import time

from app.config import settings
from app.logging_config import logger
from app.exception_handlers import register_exception_handlers
from app.middleware import setup_security_middleware, setup_audit_middleware
from app.routes import (
    auth,
    reporting,
    security,
    integrations,
    health,
    users,
    audit,
    api_keys,
    webhooks,
    playbooks,
    inventory,
    policies,
    incidents,
    config_scanner,
    network,
    guardrails,
)
from app.security import get_current_user, require_admin
from app.secret_validator import validate_secrets_on_startup
from app.telemetry import setup_opentelemetry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    logger.info(f"Starting {settings.APP_NAME} in {settings.APP_ENV} mode")

    # Validate secrets configuration
    validate_secrets_on_startup()
    logger.info("Secret validation completed")

    # Initialize application services
    try:
        # Initialize database connection
        from app.database import init_db

        init_db()
        logger.info("Database initialized successfully")

        # Initialize Redis connection if available
        if settings.REDIS_URL:
            import redis

            redis_client = redis.from_url(settings.REDIS_URL)
            redis_client.ping()
            logger.info("Redis connection established")

        # Initialize monitoring
        if settings.SENTRY_DSN:
            import sentry_sdk

            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                environment=settings.APP_ENV,
                traces_sample_rate=0.1,
                send_default_pii=False,
            )
            logger.info("Sentry monitoring initialized")

        # Prometheus metrics are served via the /metrics endpoint on the main app.
        # No separate HTTP server needed. Ensure PROMETHEUS_ENABLED=True in .env.

    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise

    yield

    logger.info(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=settings.APP_NAME,
    description="Guardrail AI - Enterprise Cybersecurity Operations Platform with integrated SOC",
    version="1.0.0",
    docs_url=settings.DOCS_URL,
    redoc_url=settings.REDOC_URL,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "Guardrail AI Support",
        "email": "support@guardrail.ai",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Setup security middleware
setup_security_middleware(app)

# Setup OpenTelemetry distributed tracing
setup_opentelemetry(app)

# Setup audit middleware
setup_audit_middleware(app)

# Register exception handlers
register_exception_handlers(app)

# Include routers with API versioning - Blueprint aligned
app.include_router(auth.router, prefix=settings.API_V1_PREFIX, tags=["auth"])
app.include_router(
    reporting.router,
    prefix=settings.API_V1_PREFIX,
    tags=["reporting"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(security.router, prefix=settings.API_V1_PREFIX, tags=["security"])
app.include_router(
    integrations.router, prefix=settings.API_V1_PREFIX, tags=["integrations"]
)
app.include_router(users.router, prefix=settings.API_V1_PREFIX, tags=["users"])
app.include_router(audit.router, prefix=settings.API_V1_PREFIX, tags=["audit"])
app.include_router(api_keys.router, prefix=settings.API_V1_PREFIX, tags=["api-keys"])
app.include_router(webhooks.router, prefix=settings.API_V1_PREFIX, tags=["webhooks"])
app.include_router(health.router, tags=["health"])
app.include_router(playbooks.router, prefix=settings.API_V1_PREFIX, tags=["playbooks"])
app.include_router(inventory.router, prefix=settings.API_V1_PREFIX, tags=["inventory"])
app.include_router(policies.router, prefix=settings.API_V1_PREFIX, tags=["policies"])
app.include_router(incidents.router, prefix=settings.API_V1_PREFIX, tags=["incidents"])
app.include_router(
    config_scanner.router, prefix=settings.API_V1_PREFIX, tags=["config-scanner"]
)
app.include_router(
    network.router, prefix=settings.API_V1_PREFIX, tags=["network-security"]
)
app.include_router(
    guardrails.router, prefix=settings.API_V1_PREFIX, tags=["guardrails"]
)


@app.middleware("http")
async def protect_docs_in_production(request: Request, call_next):
    """Protect Swagger/ReDoc behind auth in production."""
    if settings.is_production and request.url.path in {"/docs", "/redoc", "/openapi.json"}:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "Authentication required for API docs"})
    return await call_next(request)


@app.get("/")
def read_root():
    """Root endpoint with API information."""
    return {
        "message": f"{settings.APP_NAME} API",
        "version": "1.0.0",
        "environment": settings.APP_ENV,
        "api_version": settings.API_V1_PREFIX,
        "docs_url": settings.DOCS_URL if not settings.is_production else None,
        "health_check": "/health",
    }


@app.get("/health")
def health_check():
    """Health check endpoint for container orchestration and load balancers."""
    return {
        "status": "healthy",
        "environment": settings.APP_ENV,
        "version": "1.0.0",
        "timestamp": time.time(),
    }


@app.get("/metrics", dependencies=[Depends(require_admin)])
def metrics():
    """Prometheus metrics endpoint."""
    if not settings.PROMETHEUS_ENABLED:
        return {"error": "Metrics not enabled"}

    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# Add request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID for tracing."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response
