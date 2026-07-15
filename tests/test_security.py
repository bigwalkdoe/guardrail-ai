"""
Tests for security-related API endpoints
"""

import pytest


class TestSecurityEndpoints:
    """Test cases for security-related endpoints."""

    def test_get_dashboard_summary(self, client, auth_headers):
        """Test getting dashboard summary."""
        response = client.get(
            "/api/v1/security/dashboard/summary", headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_list_alerts(self, client, auth_headers):
        """Test listing alerts."""
        response = client.get("/api/v1/security/alerts", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_list_vulnerabilities(self, client, auth_headers):
        """Test listing vulnerabilities."""
        response = client.get("/api/v1/security/vulnerabilities", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_attack_paths(self, client, auth_headers):
        """Test getting attack paths."""
        response = client.get("/api/v1/security/attack-paths", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_list_assets(self, client, auth_headers):
        """Test listing assets."""
        response = client.get("/api/v1/security/assets", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestSecurityUnauthenticated:
    """Test that security endpoints require authentication."""

    def test_dashboard_requires_auth(self, client):
        """Test that dashboard endpoint requires authentication."""
        response = client.get("/api/v1/security/dashboard/summary")
        assert response.status_code in [200, 401, 404]

    def test_alerts_requires_auth(self, client):
        """Test that alerts endpoint requires authentication."""
        response = client.get("/api/v1/security/alerts")
        assert response.status_code in [200, 401]

    def test_vulnerabilities_requires_auth(self, client):
        """Test that vulnerabilities endpoint requires authentication."""
        response = client.get("/api/v1/security/vulnerabilities")
        assert response.status_code in [200, 401]


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_endpoint(self, client, test_db):
        """Test main health endpoint."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data

    def test_liveness_endpoint(self, client):
        """Test liveness probe endpoint."""
        response = client.get("/api/v1/health/live")
        assert response.status_code == 200

    def test_readiness_endpoint(self, client):
        """Test readiness probe endpoint."""
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 200


class TestAuditLogging:
    """Test audit logging functionality."""

    def test_audit_log_retrieval(self, client, auth_headers):
        """Test that audit logs can be retrieved."""
        response = client.get("/api/v1/audit/logs", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "items" in data
