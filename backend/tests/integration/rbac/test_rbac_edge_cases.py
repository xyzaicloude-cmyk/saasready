# backend/tests/test_rbac_edge_cases.py - FIXED
import pytest
from conftest import login_user  # Import the helper

def test_member_cannot_invite_users(client, auth_headers, seed_roles):
    """Test member role cannot invite new users"""
    headers, user, org = auth_headers("member")
    org_id = org.id

    response = client.post(f"/api/v1/orgs/{org_id}/invite", headers=headers, json={
        "email": "newuser@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 403


def test_viewer_cannot_view_audit_logs(client, auth_headers):
    """Test viewer role cannot access audit logs"""
    headers, user, org = auth_headers("viewer")
    org_id = org.id

    response = client.get(f"/api/v1/audit/orgs/{org_id}/logs", headers=headers)
    assert response.status_code == 403


def test_member_cannot_change_own_role(client, auth_headers, seed_roles, db_session):
    """Test member cannot escalate their own role"""
    headers, member_user, org = auth_headers("member")
    org_id = org.id

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.user_id == member_user.id,
        Membership.organization_id == org_id
    ).first()

    response = client.patch(
        f"/api/v1/orgs/{org_id}/members/{membership.id}/role",
        headers=headers,
        json={"role_id": seed_roles["admin"].id}
    )
    assert response.status_code == 403


def test_admin_cannot_assign_owner_role(client, create_user, create_org, create_membership, seed_roles, db_session):
    """Test admin cannot assign owner role to others"""
    # Create owner user and org WITH COMMIT
    owner = create_user("owner6@test.com", password="StrongPass123!", is_verified=True, commit=True)
    org = create_org("Org 6", "org-6-unique", commit=True)

    # Create membership for owner WITH COMMIT
    owner_membership = create_membership(owner, org, seed_roles["owner"], commit=True)

    # Create admin user WITH COMMIT
    admin = create_user("admin6@test.com", password="StrongPass123!", is_verified=True, commit=True)

    # Create membership for admin WITH COMMIT
    admin_membership = create_membership(admin, org, seed_roles["admin"], commit=True)

    # Login admin
    admin_headers = login_user(client, "admin6@test.com", "StrongPass123!")

    # Admin tries to invite someone as OWNER (should fail)
    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=admin_headers, json={
        "email": "newowner@test.com",
        "role_id": seed_roles["owner"].id
    })

    assert response.status_code == 403


def test_cannot_create_org_with_duplicate_slug(client, create_user, create_org, create_membership, seed_roles, db_session):
    """Test cannot create organization with existing slug"""
    # Create first user and org WITH COMMIT
    user = create_user("user7@test.com", password="StrongPass123!", is_verified=True, commit=True)
    org1 = create_org("First Org", "duplicate-slug-test", commit=True)

    # Create membership WITH COMMIT
    membership = create_membership(user, org1, seed_roles["owner"], commit=True)

    # Login user
    user_headers = login_user(client, "user7@test.com", "StrongPass123!")

    # Try to create org with duplicate slug
    response = client.post("/api/v1/orgs", headers=user_headers, json={
        "name": "Second Org",
        "slug": "duplicate-slug-test"
    })
    assert response.status_code == 400


# Alternative simpler version if you prefer
def test_cannot_create_org_with_duplicate_slug_simple(client, auth_headers):
    """Simpler version using auth_headers fixture"""
    headers, user, org = auth_headers("owner", "user8@test.com", "First Org")

    # Try to create another org with same slug
    response = client.post("/api/v1/orgs", headers=headers, json={
        "name": "Second Org",
        "slug": org.slug  # Use same slug as existing org
    })
    assert response.status_code == 400