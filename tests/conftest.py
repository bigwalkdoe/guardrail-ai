"""
Pytest configuration and fixtures for Guardrail AI tests
"""

import os

os.environ["TESTING"] = "true"
os.environ["PROMETHEUS_ENABLED"] = "false"

import pytest
from unittest.mock import MagicMock

# Mock prometheus_client BEFORE any app imports
import sys

if "prometheus_client" not in sys.modules:
    sys.modules["prometheus_client"] = MagicMock()

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models import User, Organization
from app.security import hash_password

# Test database URL (in-memory SQLite)
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db():
    """Create a test database for each test."""
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    """Create a test client with overridden database dependency."""
    from app.routes import (
        auth,
        security,
        users,
        audit,
        api_keys,
        webhooks,
        health,
        reporting,
        integrations,
    )
    from app.config import settings

    # Create a minimal test app without lifespan
    test_app = FastAPI(title="Test App")

    # Include routers with the API prefix
    test_app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(security.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(users.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(audit.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(api_keys.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(webhooks.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(health.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(reporting.router, prefix=settings.API_V1_PREFIX)
    test_app.include_router(integrations.router, prefix=settings.API_V1_PREFIX)

    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db

    with TestClient(test_app) as c:
        yield c

    test_app.dependency_overrides.clear()


@pytest.fixture
def test_organization(test_db):
    """Create a test organization."""
    org = Organization(
        name="Test Organization",
        industry="Technology",
    )
    test_db.add(org)
    test_db.commit()
    test_db.refresh(org)
    return org


@pytest.fixture
def test_user(test_db, test_organization):
    """Create a test user."""
    user = User(
        email="test@example.com",
        hashed_password=hash_password("testpassword123"),
        role="admin",
        org_id=test_organization.id,
        is_active=True,
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def admin_user(test_db, test_organization):
    """Create an admin user."""
    user = User(
        email="admin@example.com",
        hashed_password=hash_password("adminpassword123"),
        role="admin",
        org_id=test_organization.id,
        is_active=True,
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def auth_headers(client, test_user):
    """Get authentication headers for a test user."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "testpassword123"},
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
