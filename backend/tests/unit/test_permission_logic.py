"""
Unit Tests for Permission Logic
"""

def test_owner_role_has_all_permissions(db_session, seed_roles):
    """Test owner role includes all permissions"""
    from app.services.rbac_service import RBACService
    from app.models.membership import Membership

    rbac = RBACService(db_session)
    owner_role = seed_roles["owner"]

    # Create mock membership
    membership = Membership(role_id=owner_role.id)

    critical_permissions = [
        "org.read", "org.update", "user.invite",
        "user.manage", "audit.read"
    ]

    for perm in critical_permissions:
        assert rbac.has_permission(membership, perm) is True

def test_member_has_read_only_permissions(db_session, seed_roles):
    """Test member role has limited permissions"""
    from app.services.rbac_service import RBACService
    from app.models.membership import Membership

    rbac = RBACService(db_session)
    member_role = seed_roles["member"]

    membership = Membership(role_id=member_role.id)

    # Should have read
    assert rbac.has_permission(membership, "org.read") is True

    # Should NOT have write
    assert rbac.has_permission(membership, "org.update") is False
    assert rbac.has_permission(membership, "user.invite") is False

def test_role_hierarchy_enforcement(db_session, seed_roles):
    """Test role hierarchy prevents privilege escalation"""
    from app.services.rbac_service import RBACService

    rbac = RBACService(db_session)

    owner_role = seed_roles["owner"]
    admin_role = seed_roles["admin"]
    member_role = seed_roles["member"]

    # Owner can manage all roles
    assert rbac.can_manage_role(owner_role, admin_role) is True
    assert rbac.can_manage_role(owner_role, member_role) is True

    # Admin cannot manage owner
    assert rbac.can_manage_role(admin_role, owner_role) is False

    # Member cannot manage anyone
    assert rbac.can_manage_role(member_role, admin_role) is False

