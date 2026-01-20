import pytest
from datetime import datetime, timedelta, timezone


# =========================
# Registration Tests
# =========================

def test_register(client, seed_roles):
    """Test user registration"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "StrongPass123!",
            "full_name": "New User"
        }
    )
    assert response.status_code == 200, f"Registration failed: {response.json()}"
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_register_weak_password(client, seed_roles):
    """Test registration with weak password"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "weak@example.com",
            "password": "weak",
            "full_name": "Weak User"
        }
    )
    assert response.status_code == 400
    data = response.json()

    # Validate error structure (API contract)
    assert "detail" in data
    assert "password" in data["detail"].lower()

    # Ensure no sensitive data leaked
    assert "hashed" not in str(data)
    assert "secret" not in str(data).lower()



def test_register_duplicate_email(client, create_user, seed_roles):
    """Test registration with existing email"""
    create_user("existing@test.com", password="StrongPass123!")

    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "existing@test.com",
            "password": "NewPassword123!",
            "full_name": "Duplicate User"
        }
    )
    assert response.status_code == 400


def test_password_too_long(client, seed_roles):
    """Test registration fails with password > 72 characters"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "long@test.com",
            "password": "A1b!" + "a" * 120,
            "full_name": "Long Password"
        }
    )
    assert response.status_code == 400


# =========================
# Login Tests
# =========================

def test_login_success(client, test_user, seed_roles):
    """Test successful login"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": test_user.email,
            "password": "password123"
        }
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_wrong_password(client, create_user, seed_roles):
    """Test login fails with incorrect password"""
    create_user("user@test.com", password="correctpass")

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "user@test.com",
            "password": "wrongpass"
        }
    )
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower()


def test_login_nonexistent_user(client, seed_roles):
    """Test login fails for non-existent user"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "ghost@test.com",
            "password": "anypass"
        }
    )
    assert response.status_code == 401


def test_login_unverified_email(client, create_user, seed_roles):
    """Test login with unverified email"""
    create_user("unverified@example.com", is_verified=False)

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "unverified@example.com",
            "password": "Test123!"
        }
    )
    assert response.status_code in [403, 400]


def test_login_inactive_user(client, create_user, db_session, seed_roles):
    """Test login fails for inactive user"""
    user = create_user("inactive@test.com", password="StrongPass123!")
    user.is_active = False
    db_session.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "inactive@test.com",
            "password": "StrongPass123!"
        }
    )
    assert response.status_code in [400, 403]


# =========================
# Authenticated Access Tests
# =========================

def test_get_current_user(client, test_user, seed_roles):
    """Test getting current user info"""
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": test_user.email,
            "password": "password123"
        }
    )
    token = login_response.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == test_user.email



def test_access_protected_route_without_token(client):
    """Test accessing protected route without authentication"""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_access_with_invalid_token(client):
    """Test accessing protected route with invalid JWT"""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.token.here"}
    )
    assert response.status_code == 401


def test_access_with_malformed_token(client):
    """Test accessing protected route with malformed token"""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer notajwt"}
    )
    assert response.status_code == 401

# Add these tests (Auth0/Clerk standard)
@pytest.mark.parametrize("password,reason", [
    ("abcdefgh", "no uppercase"),
    ("ABCDEFGH", "no lowercase"),
    ("Abcdefgh", "no numbers"),
    ("Abc12345", "no special chars"),
    ("Qwerty123!", "keyboard pattern"),
    (" Pass123! ", "leading/trailing whitespace"),
])
def test_password_complexity_requirements(client, seed_roles, password, reason):
    """Test all password complexity requirements"""
    response = client.post("/api/v1/auth/register", json={
        "email": f"test_{reason.replace(' ', '_')}@test.com",
        "password": password,
        "full_name": "Test User"
    })

    assert response.status_code == 400, f"Failed to reject password: {reason}"
    assert "password" in response.json()["detail"].lower()


