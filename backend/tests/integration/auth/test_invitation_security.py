# backend/tests/test_invitation_security.py
import pytest
from datetime import datetime, timedelta, timezone
import uuid

def test_cannot_use_invitation_twice(client, auth_headers, seed_roles, db_session):
    """Test invitation token can only be used once"""
    headers, owner, org = auth_headers("owner")

    invite_response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "once@test.com",
        "role_id": seed_roles["member"].id
    })
    assert invite_response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "once@test.com"
    ).first()
    token = membership.invitation_token

    # First registration succeeds
    register_response_1 = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "once@test.com",
            "password": "SecurePass123!",
            "full_name": "Once User"
        }
    )
    assert register_response_1.status_code == 200

    # Second attempt with same token fails
    register_response_2 = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "once@test.com",
            "password": "SecurePass123!",
            "full_name": "Once User"
        }
    )
    assert register_response_2.status_code == 400


def test_invitation_expires_after_7_days(client, auth_headers, seed_roles, db_session):
    """Test invitation token expires after 7 days"""
    headers, owner, org = auth_headers("owner")

    invite_response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "expired@test.com",
        "role_id": seed_roles["member"].id
    })
    assert invite_response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "expired@test.com"
    ).first()
    token = membership.invitation_token

    # Manually expire the invitation
    membership.invitation_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    register_response = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "expired@test.com",
            "password": "SecurePass123!",
            "full_name": "Expired User"
        }
    )
    assert register_response.status_code == 400


def test_cannot_invite_existing_member(client, auth_headers, create_user, create_membership, seed_roles):
    """Test cannot send invitation to existing organization member"""
    headers, owner, org = auth_headers("owner")

    unique_email = f"existing_{uuid.uuid4().hex[:8]}@test.com"
    existing_user = create_user(unique_email, password="StrongPass123!")
    create_membership(existing_user, org, seed_roles["member"])

    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": unique_email,
        "role_id": seed_roles["admin"].id
    })
    assert response.status_code == 400
