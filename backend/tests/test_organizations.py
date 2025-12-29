import pytest

def test_create_organization(client, test_user, seed_roles):
    """Test creating a new organization"""
    # Login first
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "password123"
        }
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Create organization
    response = client.post(
        "/api/v1/orgs",
        json={
            "name": "New Org",
            "slug": "new-org",
            "description": "Test organization"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200, f"Failed: {response.json()}"
    data = response.json()
    assert data["name"] == "New Org"
    assert data["slug"] == "new-org"


def test_list_organizations(client, test_user, test_org, seed_roles):
    """Test listing organizations"""
    # Login first
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "password123"
        }
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # List organizations
    response = client.get(
        "/api/v1/orgs",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    # Should include test_org
    org_names = [org["name"] for org in data]
    assert "Test Organization" in org_names


def test_get_organization_members(client, test_user, test_org, seed_roles):
    """Test getting organization members"""
    # Login first
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "password123"
        }
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Get members
    response = client.get(
        f"/api/v1/orgs/{test_org.id}/members",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    # Should include test_user
    member_emails = [m["user_email"] for m in data]
    assert "test@example.com" in member_emails

def test_cannot_delete_organization_as_member(client, test_user, test_org, seed_roles, db_session):
    """Test member cannot delete organization"""
    from app.models.user import User
    from app.models.membership import Membership, MembershipStatus
    from app.core.security import get_password_hash

    # Create member user
    member_user = User(
        email="member@test.com",
        hashed_password=get_password_hash("StrongPass123!"),
        full_name="Member User",
        is_active=True,
        is_email_verified=True
    )
    db_session.add(member_user)
    db_session.commit()

    # Add as member
    member_role = seed_roles["member"]
    membership = Membership(
        user_id=member_user.id,
        organization_id=test_org.id,
        role_id=member_role.id,
        status=MembershipStatus.active
    )
    db_session.add(membership)
    db_session.commit()

    # Login as member
    login_response = client.post("/api/v1/auth/login", json={
        "email": "member@test.com",
        "password": "StrongPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try to delete org (should fail)
    response = client.delete(f"/api/v1/orgs/{test_org.id}", headers=headers)
    assert response.status_code in [403, 404, 405]  # Forbidden, Not Found, or Method Not Allowed