# backend/tests/test_rbac_critical.py - UPDATED
import pytest

def test_owner_can_update_org(client, auth_headers):
    headers, user, org = auth_headers("owner")
    # Store org ID immediately
    org_id = org.id
    response = client.patch(f"/api/v1/orgs/{org_id}", headers=headers, json={
        "name": "Updated Name"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Name"

def test_admin_can_invite_users(client, auth_headers, seed_roles):
    headers, user, org = auth_headers("admin")
    org_id = org.id
    response = client.post(f"/api/v1/orgs/{org_id}/invite", headers=headers, json={
        "email": "newmember@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 200

def test_admin_cannot_assign_owner_role(client, auth_headers, seed_roles):
    headers, user, org = auth_headers("admin")
    org_id = org.id
    response = client.post(f"/api/v1/orgs/{org_id}/invite", headers=headers, json={
        "email": "newowner@test.com",
        "role_id": seed_roles["owner"].id
    })
    assert response.status_code == 403

def test_member_cannot_update_org(client, auth_headers):
    headers, user, org = auth_headers("member")
    org_id = org.id
    response = client.patch(f"/api/v1/orgs/{org_id}", headers=headers, json={
        "name": "Hacked Name"
    })
    assert response.status_code == 403

def test_viewer_cannot_invite_users(client, auth_headers, seed_roles):
    headers, user, org = auth_headers("viewer")
    org_id = org.id
    response = client.post(f"/api/v1/orgs/{org_id}/invite", headers=headers, json={
        "email": "spam@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 403

def test_member_cannot_manage_users(client, auth_headers, create_user, create_membership, seed_roles, db_session):
    headers, member_user, org = auth_headers("member")
    org_id = org.id

    target_user = create_user("target@test.com")
    db_session.flush()  # Ensure user has ID

    target_membership = create_membership(target_user, org, seed_roles["viewer"])
    db_session.commit()  # Commit the membership

    response = client.patch(
        f"/api/v1/orgs/{org_id}/members/{target_membership.id}/role",
        headers=headers,
        json={"role_id": seed_roles["admin"].id}
    )
    assert response.status_code == 403

def test_owner_can_manage_all_roles(client, auth_headers, create_user, create_membership, seed_roles, db_session):
    headers, owner_user, org = auth_headers("owner")
    org_id = org.id

    target_user = create_user("promote@test.com")
    db_session.flush()

    target_membership = create_membership(target_user, org, seed_roles["member"])
    db_session.commit()

    response = client.patch(
        f"/api/v1/orgs/{org_id}/members/{target_membership.id}/role",
        headers=headers,
        json={"role_id": seed_roles["admin"].id}
    )
    assert response.status_code == 200

def test_unauthorized_user_cannot_access_org(client, auth_headers, create_org, db_session):
    headers, user, user_org = auth_headers("owner", "owner1@test.com")
    other_org = create_org("Other Org", "other-org")
    db_session.commit()  # Commit the other org

    response = client.patch(f"/api/v1/orgs/{other_org.id}", headers=headers, json={
        "name": "Hacked"
    })
    assert response.status_code == 403

def test_no_auth_header_returns_401(client, create_org, db_session):
    org = create_org("Test", "test")
    db_session.commit()
    response = client.get(f"/api/v1/orgs/{org.id}/members")
    assert response.status_code == 401