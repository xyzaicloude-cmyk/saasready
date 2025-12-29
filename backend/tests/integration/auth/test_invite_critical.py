import pytest
from datetime import datetime, timedelta, timezone
import uuid

def test_invite_user_creates_membership(client, auth_headers, seed_roles, db_session):
    headers, user, org = auth_headers("owner")

    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "invited@test.com",
        "role_id": seed_roles["member"].id,
        "full_name": "Invited User"
    })
    assert response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "invited@test.com"
    ).first()
    assert membership is not None
    assert membership.status.value == "invited"
    assert membership.invitation_token is not None

def test_invite_generates_valid_token(client, auth_headers, seed_roles, db_session):
    headers, user, org = auth_headers("owner")

    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "token@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "token@test.com"
    ).first()
    assert len(membership.invitation_token) > 20
    assert membership.invitation_expires_at > naive_utc(datetime.now(timezone.utc))

def test_invite_sets_expiry_7_days(client, auth_headers, seed_roles, db_session):
    headers, user, org = auth_headers("owner")

    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "expiry@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "expiry@test.com"
    ).first()

    expected_expiry = as_utc_naive(datetime.now(timezone.utc) + timedelta(days=7))
    time_diff = abs((membership.invitation_expires_at - expected_expiry).total_seconds())
    assert time_diff < 60

def test_register_with_valid_invite_joins_org(client, auth_headers, seed_roles, db_session):
    headers, owner, org = auth_headers("owner")

    invite_response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "newmember@test.com",
        "role_id": seed_roles["member"].id
    })
    assert invite_response.status_code == 200

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "newmember@test.com"
    ).first()
    token = membership.invitation_token

    register_response = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "newmember@test.com",
            "password": "SecurePass123!",
            "full_name": "New Member"
        }
    )
    assert register_response.status_code == 200

    db_session.expire_all()
    updated_membership = db_session.query(Membership).filter(
        Membership.invited_email == "newmember@test.com"
    ).first()
    assert updated_membership.status.value == "active"
    assert updated_membership.user_id is not None

def test_register_with_invite_no_personal_org(client, auth_headers, seed_roles, db_session):
    headers, owner, org = auth_headers("owner")

    invite_response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "nopersonalorg@test.com",
        "role_id": seed_roles["member"].id
    })

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "nopersonalorg@test.com"
    ).first()
    token = membership.invitation_token

    register_response = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "nopersonalorg@test.com",
            "password": "SecurePass123!",
            "full_name": "No Personal Org"
        }
    )
    assert register_response.status_code == 200

    from app.models.user import User
    user = db_session.query(User).filter(User.email == "nopersonalorg@test.com").first()

    memberships = db_session.query(Membership).filter(Membership.user_id == user.id).all()
    assert len(memberships) == 1
    assert memberships[0].organization_id == org.id

def test_invite_wrong_email_fails(client, auth_headers, seed_roles, db_session):
    headers, owner, org = auth_headers("owner")

    invite_response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "correct@test.com",
        "role_id": seed_roles["member"].id
    })

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "correct@test.com"
    ).first()
    token = membership.invitation_token

    register_response = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "wrong@test.com",
            "password": "SecurePass123!",
            "full_name": "Wrong Email"
        }
    )
    assert register_response.status_code == 400

def test_invite_expired_token_fails(client, auth_headers, seed_roles, db_session):
    headers, owner, org = auth_headers("owner")

    invite_response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "expired@test.com",
        "role_id": seed_roles["member"].id
    })

    from app.models.membership import Membership
    membership = db_session.query(Membership).filter(
        Membership.invited_email == "expired@test.com"
    ).first()
    token = membership.invitation_token

    membership.invitation_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    register_response = client.post(
        f"/api/v1/auth/register-with-invite?invite_token={token}",
        json={
            "email": "expired@test.com",
            "password": "SecurePass123!",
            "full_name": "Expired"
        }
    )
    assert register_response.status_code == 400

def test_invite_duplicate_email_in_org(client, auth_headers, seed_roles, create_user, create_membership, db_session):
    """Test cannot send invitation to existing organization member"""
    headers, owner, org = auth_headers("owner")

    # Create a UNIQUE email for this specific test
    unique_email = f"existing_member_{uuid.uuid4().hex[:8]}@test.com"

    print(f"\n=== DEBUG: Testing duplicate invitation for {unique_email} ===")

    # Create user with this unique email
    existing_user = create_user(unique_email)
    print(f"Created user ID: {existing_user.id}")

    # Make them a member of the org
    membership = create_membership(existing_user, org, seed_roles["member"])
    print(f"Created membership ID: {membership.id}, Status: {membership.status}")

    # COMMIT to ensure it's in the database
    db_session.commit()

    # Verify the membership exists
    from app.models.membership import Membership as MembershipModel
    verify_membership = db_session.query(MembershipModel).filter(
        MembershipModel.user_id == existing_user.id,
        MembershipModel.organization_id == org.id
    ).first()
    print(f"Verified membership exists: {verify_membership is not None}")
    if verify_membership:
        print(f"Verified status: {verify_membership.status}")

    # Now try to invite the SAME email - should fail (duplicate in org)
    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": unique_email,  # Same email as existing member
        "role_id": seed_roles["admin"].id
    })

    print(f"Response status: {response.status_code}")
    print(f"Response body: {response.text}")
    print("=========================================\n")

    assert response.status_code == 400, f"Expected 400 for duplicate invitation, got {response.status_code}"

def as_utc_naive(dt):
    if dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt

def naive_utc(dt):
    return dt.replace(tzinfo=None) if dt.tzinfo else dt
