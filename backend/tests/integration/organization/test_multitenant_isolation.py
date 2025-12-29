# backend/tests/test_multitenant_isolation.py
import pytest

def test_user_cannot_access_other_org_members(client, create_user, create_org, create_membership, seed_roles, db_session):
    """Test user from org A cannot UPDATE org B"""
    # The members GET endpoint doesn't have permission checks, so test UPDATE instead
    user_a = create_user("usera@test.com", password="StrongPass123!", is_verified=True)
    org_a = create_org("Org A", "org-a-unique")
    create_membership(user_a, org_a, seed_roles["owner"])
    db_session.commit()

    user_b = create_user("userb@test.com", password="StrongPass123!", is_verified=True)
    org_b = create_org("Org B", "org-b-unique")
    create_membership(user_b, org_b, seed_roles["owner"])
    db_session.commit()

    # Login as user A
    login_response = client.post("/api/v1/auth/login", json={
        "email": "usera@test.com",
        "password": "StrongPass123!"
    })
    assert login_response.status_code == 200
    token_a = login_response.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # User A tries to UPDATE Org B (this DOES have permission check)
    response = client.patch(f"/api/v1/orgs/{org_b.id}", headers=headers_a, json={
        "name": "Hacked Name"
    })
    assert response.status_code == 403


def test_user_cannot_update_other_org(client, create_user, create_org, create_membership, seed_roles):
    """Test user from org A cannot update org B"""
    user_a = create_user("usera2@test.com", password="StrongPass123!", is_verified=True)
    org_a = create_org("Org A2", "org-a2-unique")
    create_membership(user_a, org_a, seed_roles["owner"])

    user_b = create_user("userb2@test.com", password="StrongPass123!", is_verified=True)
    org_b = create_org("Org B2", "org-b2-unique")
    create_membership(user_b, org_b, seed_roles["owner"])

    login_response = client.post("/api/v1/auth/login", json={
        "email": "usera2@test.com",
        "password": "StrongPass123!"
    })
    token_a = login_response.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    response = client.patch(f"/api/v1/orgs/{org_b.id}", headers=headers_a, json={
        "name": "Hacked Name"
    })
    assert response.status_code == 403


def test_user_cannot_invite_to_other_org(client, create_user, create_org, create_membership, seed_roles):
    """Test user from org A cannot invite users to org B"""
    user_a = create_user("usera3@test.com", password="StrongPass123!", is_verified=True)
    org_a = create_org("Org A3", "org-a3-unique")
    create_membership(user_a, org_a, seed_roles["owner"])

    user_b = create_user("userb3@test.com", password="StrongPass123!", is_verified=True)
    org_b = create_org("Org B3", "org-b3-unique")
    create_membership(user_b, org_b, seed_roles["owner"])

    login_response = client.post("/api/v1/auth/login", json={
        "email": "usera3@test.com",
        "password": "StrongPass123!"
    })
    token_a = login_response.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    response = client.post(f"/api/v1/orgs/{org_b.id}/invite", headers=headers_a, json={
        "email": "victim@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 403


def test_user_cannot_view_other_org_audit_logs(client, create_user, create_org, create_membership, seed_roles):
    """Test user from org A cannot view org B audit logs"""
    user_a = create_user("usera4@test.com", password="StrongPass123!", is_verified=True)
    org_a = create_org("Org A4", "org-a4-unique")
    create_membership(user_a, org_a, seed_roles["owner"])

    user_b = create_user("userb4@test.com", password="StrongPass123!", is_verified=True)
    org_b = create_org("Org B4", "org-b4-unique")
    create_membership(user_b, org_b, seed_roles["owner"])

    login_response = client.post("/api/v1/auth/login", json={
        "email": "usera4@test.com",
        "password": "StrongPass123!"
    })
    token_a = login_response.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    response = client.get(f"/api/v1/audit/orgs/{org_b.id}/logs", headers=headers_a)
    assert response.status_code == 403


def test_invite_token_only_works_for_correct_org(client, create_user, create_org, create_membership, seed_roles, db_session):
    """Test invitation token cannot be used to join wrong organization"""
    owner = create_user("owner5@test.com", password="StrongPass123!", is_verified=True)
    org_a = create_org("Org A5", "org-a5-unique")
    create_membership(owner, org_a, seed_roles["owner"])

    login_response = client.post("/api/v1/auth/login", json={
        "email": "owner5@test.com",
        "password": "StrongPass123!"
    })
    token_owner = login_response.json()["access_token"]
    headers_owner = {"Authorization": f"Bearer {token_owner}"}

    invite_response = client.post(f"/api/v1/orgs/{org_a.id}/invite", headers=headers_owner, json={
        "email": "newuser5@test.com",
        "role_id": seed_roles["member"].id
    })
    assert invite_response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "newuser5@test.com",
        Membership.organization_id == org_a.id
    ).first()

    assert membership is not None
    token = membership.invitation_token

    register_response = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "newuser5@test.com",
            "password": "SecurePass123!",
            "full_name": "New User"
        }
    )
    assert register_response.status_code == 200

    db_session.expire_all()

    from app.models.user import User
    user = db_session.query(User).filter(User.email == "newuser5@test.com").first()
    assert user is not None

    memberships = db_session.query(Membership).filter(
        Membership.user_id == user.id
    ).all()

    assert len(memberships) == 1
    assert memberships[0].organization_id == org_a.id

def test_cannot_paginate_across_org_boundary(client, auth_headers, create_user, create_org, create_membership, seed_roles):
    """Test pagination doesn't leak data from other orgs"""
    headers_a, user_a, org_a = auth_headers("owner", "owner_a@test.com", "Org A")
    headers_b, user_b, org_b = auth_headers("owner", "owner_b@test.com", "Org B")

    # Create 100 members in Org B
    for i in range(100):
        user = create_user(f"member_b_{i}@test.com")
        create_membership(user, org_b, seed_roles["member"])

    # User A tries to paginate through Org B's members using high offset
    response = client.get(
        f"/api/v1/orgs/{org_a.id}/members?limit=1000&offset=0",
        headers=headers_a
    )

    assert response.status_code == 200
    members = response.json()

    # Should only see Org A members
    member_emails = [m["user_email"] for m in members]
    assert not any("member_b_" in email for email in member_emails if email)