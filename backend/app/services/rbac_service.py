from sqlalchemy.orm import Session
from ..models.membership import Membership
from ..models.role import Role
from ..models.permission import Permission, RolePermission


class RBACService:
    def __init__(self, db: Session):
        self.db = db

    def has_permission(self, membership: Membership, permission_key: str) -> bool:
        """
        Check if a membership has a specific permission through their role.
        Uses permission.key instead of permission.name for lookup.
        """
        if not membership.role_id:
            return False

        # Query permission by key (not name)
        permission = self.db.query(Permission).filter(
            Permission.key == permission_key
        ).first()

        if not permission:
            return False

        # Check if role has this permission
        role_permission = self.db.query(RolePermission).filter(
            RolePermission.role_id == membership.role_id,
            RolePermission.permission_id == permission.id
        ).first()

        return role_permission is not None

    def get_user_permissions(self, membership: Membership) -> list[str]:
        """
        Get all permission keys (not names) for a membership's role.
        Returns list of permission keys like ['org.update', 'user.invite'].
        """
        if not membership.role_id:
            return []

        role_permissions = self.db.query(RolePermission).filter(
            RolePermission.role_id == membership.role_id
        ).all()

        permission_ids = [rp.permission_id for rp in role_permissions]
        permissions = self.db.query(Permission).filter(
            Permission.id.in_(permission_ids)
        ).all()

        # Return keys instead of names
        return [p.key for p in permissions]

    def assign_role_to_membership(self, membership_id: str, role_id: str):
        """Assign a role to a membership."""
        membership = self.db.query(Membership).filter(
            Membership.id == membership_id
        ).first()

        if membership:
            membership.role_id = role_id
            self.db.commit()
            self.db.refresh(membership)

        return membership

    def get_role_permissions(self, role_id: str) -> list[Permission]:
        """Get all permissions for a specific role."""
        role_permissions = self.db.query(RolePermission).filter(
            RolePermission.role_id == role_id
        ).all()

        permission_ids = [rp.permission_id for rp in role_permissions]
        permissions = self.db.query(Permission).filter(
            Permission.id.in_(permission_ids)
        ).all()

        return permissions

    def add_permission_to_role(self, role_id: str, permission_key: str) -> bool:
        """Add a permission to a role. Returns True if added, False if already exists."""
        permission = self.db.query(Permission).filter(
            Permission.key == permission_key
        ).first()

        if not permission:
            return False

        # Check if already exists
        existing = self.db.query(RolePermission).filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission.id
        ).first()

        if existing:
            return False

        # Create new role-permission link
        role_permission = RolePermission(
            role_id=role_id,
            permission_id=permission.id
        )
        self.db.add(role_permission)
        self.db.commit()

        return True

    def remove_permission_from_role(self, role_id: str, permission_key: str) -> bool:
        """Remove a permission from a role. Returns True if removed, False if not found."""
        permission = self.db.query(Permission).filter(
            Permission.key == permission_key
        ).first()

        if not permission:
            return False

        role_permission = self.db.query(RolePermission).filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission.id
        ).first()

        if not role_permission:
            return False

        self.db.delete(role_permission)
        self.db.commit()

        return True