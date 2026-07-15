"""
OpenTelemetry distributed tracing configuration.

Configured via environment variables:
  OTEL_EXPORTER_OTLP_ENDPOINT  - OTLP gRPC endpoint (default: http://localhost:4317)
  OTEL_SERVICE_NAME            - Service name for traces
  OTEL_ENABLED                 - Set to "true" to enable tracing
"""

import os
import logging

from app.config import settings

logger = logging.getLogger(__name__)


def setup_opentelemetry(app):
    """Initialize OpenTelemetry tracing for the FastAPI application."""
    otel_enabled = os.getenv("OTEL_ENABLED", "false").lower() == "true"
    if not otel_enabled:
        logger.info("OpenTelemetry tracing disabled (set OTEL_ENABLED=true to enable)")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        from opentelemetry.sdk.resources import Resource

        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
        service_name = os.getenv("OTEL_SERVICE_NAME", settings.APP_NAME)

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint)
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

        FastAPIInstrumentor.instrument_app(app)
        SQLAlchemyInstrumentor().instrument()
        RedisInstrumentor().instrument()
        RequestsInstrumentor().instrument()

        logger.info(
            f"OpenTelemetry tracing enabled: service={service_name}, "
            f"endpoint={endpoint}"
        )
    except ImportError:
        logger.warning(
            "OpenTelemetry packages not installed. "
            "Install with: pip install opentelemetry-api opentelemetry-sdk "
            "opentelemetry-exporter-otlp opentelemetry-instrumentation-fastapi "
            "opentelemetry-instrumentation-sqlalchemy opentelemetry-instrumentation-redis "
            "opentelemetry-instrumentation-requests"
        )
    except Exception as e:
        logger.error(f"Failed to initialize OpenTelemetry: {e}")
