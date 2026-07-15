"""
Logging Configuration Module

Provides structured logging with support for:
- JSON logging for production
- Console logging for development
- File logging for debugging
- Integration with external logging services (DataDog, Sentry, etc.)
"""

import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict
from pythonjsonlogger import jsonlogger
from app.config import settings


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat()
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        log_record['environment'] = settings.APP_ENV
        log_record['app_name'] = settings.APP_NAME
        
        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            log_record['extra'] = record.extra_data


def setup_logging() -> logging.Logger:
    """
    Configure application logging based on environment.
    
    In production:
    - JSON format for machine parsing
    - Log to stdout for container orchestration
    - Integration with Sentry for error tracking
    
    In development:
    - Human-readable format
    - Console output with colors
    """
    logger = logging.getLogger("guardrail-ai")
    
    # Set log level from settings
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    if settings.is_production or settings.LOG_FORMAT == "json":
        # Production: JSON logging
        formatter = CustomJsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
        console_handler.setFormatter(formatter)
    else:
        # Development: Human-readable format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    # Add Sentry handler in production
    if settings.is_production and settings.SENTRY_DSN:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.logging import SentryHandler
            
            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                environment=settings.APP_ENV,
                integrations=[
                    # Add logging integration for error tracking
                ],
                traces_sample_rate=0.1,
            )
            
            sentry_handler = SentryHandler()
            sentry_handler.setLevel(logging.ERROR)
            logger.addHandler(sentry_handler)
        except ImportError:
            logger.warning("Sentry SDK not installed. Skipping Sentry integration.")
    
    return logger


# Create logger instance
logger = setup_logging()


def log_request(endpoint: str, method: str, user_id: str = None, **kwargs):
    """Log HTTP request with additional context."""
    extra_data = {
        "endpoint": endpoint,
        "method": method,
        "user_id": user_id,
        **kwargs
    }
    logger.info(f"{method} {endpoint}", extra={"extra_data": extra_data})


def log_error(error: Exception, context: Dict[str, Any] = None):
    """Log error with context."""
    logger.error(
        f"Error: {str(error)}",
        extra={
            "extra_data": {
                "error_type": type(error).__name__,
                "error_message": str(error),
                "context": context or {}
            }
        },
        exc_info=True
    )


def log_security_event(event_type: str, details: Dict[str, Any]):
    """Log security-related events."""
    logger.warning(
        f"Security Event: {event_type}",
        extra={
            "extra_data": {
                "event_type": event_type,
                "details": details
            }
        }
    )
