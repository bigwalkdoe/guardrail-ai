"""
Security Middleware Module

Provides enterprise-grade security middleware for:
- Rate limiting
- Security headers
- Request logging
- CORS enhancement
- IP whitelisting/blacklisting
- Audit logging
"""

from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import time
import redis
import ipaddress
from typing import List, Optional
import logging
import threading

from app.config import settings
from app.logging_config import logger, log_security_event

# Prometheus metrics
try:
    from prometheus_client import Counter, Histogram

    request_count = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status"],
    )
    request_duration = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0),
    )
    active_requests = Counter(
        "http_requests_active",
        "Active HTTP requests",
        ["method"],
    )
except ImportError:
    request_count = None
    request_duration = None
    active_requests = None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        if not settings.SECURITY_HEADERS_ENABLED:
            return await call_next(request)

        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # HSTS (HTTPS Strict Transport Security)
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={settings.HSTS_MAX_AGE}; includeSubDomains; preload"
            )

        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with detailed information and record Prometheus metrics."""

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Get client IP
        client_ip = request.client.host
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        # Log request
        logger.info(
            f"Request started",
            extra={
                "extra_data": {
                    "method": request.method,
                    "url": str(request.url),
                    "client_ip": client_ip,
                    "user_agent": request.headers.get("User-Agent"),
                    "referer": request.headers.get("Referer"),
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

        # Record active request
        if request_count:
            active_requests.labels(method=request.method).inc()

        try:
            response = await call_next(request)
        finally:
            if active_requests:
                active_requests.labels(method=request.method).dec()

        # Calculate duration
        process_time = time.time() - start_time

        # Record Prometheus metrics
        if request_count and settings.PROMETHEUS_ENABLED:
            endpoint = request.url.path
            request_count.labels(
                method=request.method, endpoint=endpoint, status=response.status_code
            ).inc()
            request_duration.labels(
                method=request.method, endpoint=endpoint
            ).observe(process_time)

        # Log response
        logger.info(
            f"Request completed",
            extra={
                "extra_data": {
                    "method": request.method,
                    "url": str(request.url),
                    "status_code": response.status_code,
                    "process_time": round(process_time, 4),
                    "client_ip": client_ip,
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

        # Add timing header
        response.headers["X-Process-Time"] = str(round(process_time, 4))

        return response


class IPFilterMiddleware(BaseHTTPMiddleware):
    """Filter requests based on IP whitelist/blacklist."""

    def __init__(
        self,
        app,
        whitelist: Optional[List[str]] = None,
        blacklist: Optional[List[str]] = None,
    ):
        super().__init__(app)
        self.whitelist = whitelist or []
        self.blacklist = blacklist or []

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        # Check blacklist first
        for blocked_ip in self.blacklist:
            try:
                if ipaddress.ip_address(client_ip) in ipaddress.ip_network(
                    blocked_ip, strict=False
                ):
                    log_security_event(
                        "ip_blocked", {"ip": client_ip, "reason": "blacklisted"}
                    )
                    raise HTTPException(status_code=403, detail="IP address blocked")
            except ValueError:
                # Invalid IP format, skip
                continue

        # Check whitelist if configured
        if self.whitelist:
            allowed = False
            for allowed_ip in self.whitelist:
                try:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(
                        allowed_ip, strict=False
                    ):
                        allowed = True
                        break
                except ValueError:
                    # Invalid IP format, skip
                    continue

            if not allowed:
                log_security_event(
                    "ip_blocked", {"ip": client_ip, "reason": "not_whitelisted"}
                )
                raise HTTPException(status_code=403, detail="IP address not allowed")

        return await call_next(request)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforce CSRF protection for cookie-authenticated state-changing requests."""

    async def dispatch(self, request: Request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)

        has_auth_cookie = request.cookies.get(
            settings.ACCESS_TOKEN_COOKIE
        ) or request.cookies.get(settings.REFRESH_TOKEN_COOKIE)
        if not has_auth_cookie:
            return await call_next(request)

        csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
        csrf_header = request.headers.get(settings.CSRF_HEADER_NAME)
        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        return await call_next(request)


def setup_security_middleware(app):
    """Setup all security middleware for the FastAPI app."""
    # Enforce allowed Host headers
    if settings.TRUSTED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.trusted_hosts_list,
        )

    # Add CORS middleware with enhanced settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            settings.CSRF_HEADER_NAME,
        ],
        expose_headers=["X-Process-Time"],
        max_age=600,  # Cache preflight requests for 10 minutes
    )

    # Add security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Add request logging
    app.add_middleware(RequestLoggingMiddleware)

    # Add CSRF protection for cookie-authenticated requests
    app.add_middleware(CSRFMiddleware)

    # Add IP filtering if configured
    if settings.IP_WHITELIST or settings.IP_BLACKLIST:
        whitelist = settings.IP_WHITELIST.split(",") if settings.IP_WHITELIST else None
        blacklist = settings.IP_BLACKLIST.split(",") if settings.IP_BLACKLIST else None
        if whitelist or blacklist:
            app.add_middleware(
                IPFilterMiddleware, whitelist=whitelist, blacklist=blacklist
            )

    # Setup tiered rate limiting (per-key + global fallback)
    try:
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        from slowapi.errors import RateLimitExceeded
        from fastapi.responses import JSONResponse

        _setup_tiered_rate_limiting(app)
    except ImportError:
        if settings.is_production:
            raise RuntimeError(
                "slowapi is required in production for rate limiting. "
                "Install it: pip install slowapi"
            )
        logger.warning("slowapi not installed — rate limiting disabled (pip install slowapi)")


def _setup_tiered_rate_limiting(app):
    """Set up tiered rate limiting with per-API-key support via Redis."""
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from fastapi.responses import JSONResponse

    if settings.REDIS_URL:
        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=settings.REDIS_URL,
            default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
        )
    else:
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
        )

    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded",
                "retry_after": exc.detail if hasattr(exc, "detail") else 60,
            },
        )

    # Add per-API-key rate limiting as a middleware
    @app.middleware("http")
    async def apikey_rate_limit_middleware(request: Request, call_next):
        api_key_header = request.headers.get("X-API-Key")
        if api_key_header and settings.REDIS_URL:
            try:
                import hashlib
                import redis as redis_client
                r = redis_client.from_url(settings.REDIS_URL)

                key_hash = hashlib.sha256(api_key_header.encode()).hexdigest()
                limit_key = f"apikey_sliding:{key_hash}"

                import time as time_module
                now = time_module.time()
                window_start = now - 60
                r.zremrangebyscore(limit_key, 0, window_start)
                current = r.zcard(limit_key)
                r.zadd(limit_key, {str(now): now})
                r.expire(limit_key, 120)

                if current >= 1000:  # default max RPM
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "API key rate limit exceeded", "retry_after": 60},
                    )
            except Exception:
                pass

        response = await call_next(request)
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware to log all API requests for audit trail."""

    def __init__(self, app, exclude_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]
        self._audit_queue = []
        self._worker_started = False

    def _get_client_ip(self, request: Request) -> str:
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        return client_ip

    def _should_audit(self, path: str) -> bool:
        return not any(path.startswith(excluded) for excluded in self.exclude_paths)

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = self._get_client_ip(request)

        response = await call_next(request)

        process_time = time.time() - start_time

        if self._should_audit(request.url.path) and request.url.path.startswith("/api"):
            audit_data = {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time": round(process_time, 4),
                "client_ip": client_ip,
                "user_agent": request.headers.get("User-Agent"),
            }

            if settings.REDIS_URL:
                try:
                    import redis as redis_client

                    r = redis_client.from_url(settings.REDIS_URL)
                    r.lpush("audit:requests", str(audit_data))
                    r.ltrim("audit:requests", 0, 9999)
                except:
                    pass

        return response


def setup_audit_middleware(app):
    """Setup audit logging middleware."""
    app.add_middleware(AuditMiddleware)
