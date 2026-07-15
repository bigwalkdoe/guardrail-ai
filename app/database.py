from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool, NullPool
from contextlib import contextmanager
import logging

from app.config import settings
from app.models import Base

logger = logging.getLogger(__name__)

# Database connection pool configuration for production
DB_POOL_CONFIG = {
    "pool_size": int(getattr(settings, "DB_POOL_SIZE", 20)),
    "max_overflow": int(getattr(settings, "DB_MAX_OVERFLOW", 30)),
    "pool_timeout": int(getattr(settings, "DB_POOL_TIMEOUT", 30)),
    "pool_recycle": int(getattr(settings, "DB_POOL_RECYCLE", 1800)),
    "pool_pre_ping": True,
    "echo": settings.is_development,
}


def get_engine_kwargs() -> dict:
    """Get database engine configuration based on environment."""
    kwargs = {}

    if settings.DATABASE_URL.startswith("postgresql"):
        ssl_mode = "require" if settings.is_production else "prefer"
        kwargs = {
            "connect_args": {
                "sslmode": ssl_mode,
                "connect_timeout": 10,
                "application_name": "guardrail-ai",
                "keepalives": 1,
                "keepalives_idle": 30,
            },
            "poolclass": QueuePool,
            **DB_POOL_CONFIG,
        }
    elif settings.DATABASE_URL.startswith("sqlite"):
        kwargs = {
            "connect_args": {"check_same_thread": False},
            "poolclass": NullPool,
        }
    else:
        kwargs = {**DB_POOL_CONFIG}

    return kwargs


# Create engine with production optimizations
engine = create_engine(settings.DATABASE_URL, **get_engine_kwargs())


@event.listens_for(engine, "connect")
def set_sqlalchemy_ultra_pool(dbapi_connection, connection_record):
    """Configure PostgreSQL connection for better performance."""
    if settings.DATABASE_URL.startswith("postgresql"):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("SET statement_timeout = '30s'")
            cursor.execute("SET lock_timeout = '10s'")
            cursor.close()
        except Exception as e:
            logger.warning(f"Failed to set PostgreSQL session parameters: {e}")


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db():
    """Database session dependency for FastAPI."""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def get_db_context():
    """Context manager for database sessions outside of FastAPI dependency injection."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """Initialize database tables.
    In production, Alembic migrations MUST be used instead.
    In development, create_all is a convenience shortcut."""
    if settings.is_production:
        logger.warning(
            "Skipping create_all in production — use 'alembic upgrade head' instead. "
            "Set APP_ENV=development to auto-create tables."
        )
        return
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created via create_all (development mode)")


def health_check() -> bool:
    """Health check for database connection."""
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
