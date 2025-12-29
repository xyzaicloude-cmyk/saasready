import pytest

def test_audit_log_created_on_org_update(client, auth_headers, db_session):
    """Test audit log is created when organization is updated"""
    headers, user, org = auth_headers("owner")

    response = client.patch(f"/api/v1/orgs/{org.id}", headers=headers, json={
        "name": "Updated Org Name"
    })
    assert response.status_code == 200

    from app.models.audit_log import AuditLog
    log = db_session.query(AuditLog).filter(
        AuditLog.organization_id == org.id,
        AuditLog.action == "org.updated"
    ).first()

    assert log is not None
    assert log.actor_user_id == user.id
    assert "Updated Org Name" in str(log.audit_metadata)


def test_audit_log_created_on_member_invite(client, auth_headers, seed_roles, db_session):
    """Test audit log is created when user is invited"""
    headers, user, org = auth_headers("owner")

    response = client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "invited@test.com",
        "role_id": seed_roles["member"].id
    })
    assert response.status_code == 200

    from app.models.audit_log import AuditLog
    log = db_session.query(AuditLog).filter(
        AuditLog.organization_id == org.id,
        AuditLog.action == "user.invite.sent"
    ).first()

    assert log is not None
    assert log.actor_user_id == user.id
    assert "invited@test.com" in str(log.audit_metadata)


def test_audit_log_actor_is_correct(client, auth_headers, seed_roles, db_session):
    """Test audit log records correct actor for actions"""
    headers, user, org = auth_headers("owner")

    # Perform action
    client.post(f"/api/v1/orgs/{org.id}/invite", headers=headers, json={
        "email": "actor@test.com",
        "role_id": seed_roles["member"].id
    })

    from app.models.audit_log import AuditLog
    log = db_session.query(AuditLog).filter(
        AuditLog.organization_id == org.id,
        AuditLog.action == "user.invite.sent"
    ).first()

    # Verify actor is the user who performed the action
    assert log.actor_user_id == user.id
    assert log.actor_user_id is not None