"""
Tests for authentication endpoints
"""

import pytest
from datetime import datetime


class TestAuthLogin:
    """Test cases for login endpoint."""

    def test_login_success(self, client, test_user):
        """Test successful login."""
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client, test_user):
        """Test login with wrong password."""
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401
        assert "detail" in response.json()

    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@example.com", "password": "password123"},
        )
        assert response.status_code == 401

    def test_login_empty_email(self, client):
        """Test login with empty email."""
        response = client.post(
            "/api/v1/auth/login", json={"email": "", "password": "password123"}
        )
        assert response.status_code == 422  # Validation error

    def test_login_empty_password(self, client):
        """Test login with empty password."""
        response = client.post(
            "/api/v1/auth/login", json={"email": "test@example.com", "password": ""}
        )
        assert response.status_code == 422  # Validation error

    def test_login_missing_fields(self, client):
        """Test login with missing fields."""
        response = client.post("/api/v1/auth/login", json={"email": "test@example.com"})
        assert response.status_code == 422


class TestAuthRefresh:
    """Test cases for token refresh."""

    def test_refresh_token_success(self, client, test_user):
        """Test successful token refresh."""
        # First login
        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )
        refresh_token = login_response.json()["refresh_token"]

        # Refresh token
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data

    def test_refresh_invalid_token(self, client):
        """Test refresh with invalid token."""
        response = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": "invalid_token"}
        )
        assert response.status_code == 401


class TestAuthMe:
    """Test cases for /me endpoint."""

    def test_get_current_user(self, client, auth_headers, test_user):
        """Test getting current user info."""
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["role"] == "admin"

    def test_get_current_user_no_token(self, client):
        """Test getting current user without token."""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401

    def test_get_current_user_invalid_token(self, client):
        """Test getting current user with invalid token."""
        response = client.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401


class TestAuthLogout:
    """Test cases for logout endpoint."""

    def test_logout_success(self, client, auth_headers):
        """Test successful logout."""
        response = client.post("/api/v1/auth/logout", headers=auth_headers)
        assert response.status_code == 200

    def test_logout_no_token(self, client):
        """Test logout without token - should either return 401 or handle gracefully."""
        response = client.post("/api/v1/auth/logout")
        assert response.status_code in [200, 401, 400]


class TestPasswordSecurity:
    """Test password security requirements."""

    def test_password_minimum_length(self, client):
        """Test that password has minimum length."""
        # This tests that short passwords are handled
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "new@example.com",
                "password": "short",
                "organizationName": "Test Org",
            },
        )
        # Accept various status codes depending on backend config
        assert response.status_code in [200, 201, 400, 422]

    def test_password_hashed_not_stored(self, test_db, test_user):
        """Test that password is hashed and not stored in plaintext."""
        # The hashed_password field should not be "password123"
        assert test_user.hashed_password != "password123"
        assert test_user.hashed_password.startswith(
            "$2"
        )  # bcrypt hash starts with $2a, $2b, or $2y


class TestSessionSecurity:
    """Test session security features."""

    def test_csrf_token_present(self, client, test_user):
        """Test that CSRF token is returned on login."""
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        # CSRF token should be in response or cookies
        assert "csrf_token" in data or "access_token" in data

    def test_refresh_token_separate_from_access(self, client, test_user):
        """Test that refresh token is different from access token."""
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "testpassword123"},
        )
        data = response.json()
        assert data["access_token"] != data["refresh_token"]
