from sqlalchemy.orm import Session
from ..models.membership import Membership
from ..models.role import Role
from ..models.permission import Permission, RolePermission


class RBACService:
    def __init__(self, db: Session):
        self.db = db

    def has_permission(self, membership: Membership, permission_name: str) -> bool:
        if not membership.role_id:
            return False

        permission = self.db.query(Permission).filter(
            Permission.name == permission_name
        ).first()

        if not permission:
            return False

        role_permission = self.db.query(RolePermission).filter(
            RolePermission.role_id == membership.role_id,
            RolePermission.permission_id == permission.id
        ).first()

        return role_permission is not None

    def get_user_permissions(self, membership: Membership) -> list[str]:
        if not membership.role_id:
            return []

        role_permissions = self.db.query(RolePermission).filter(
            RolePermission.role_id == membership.role_id
        ).all()

        permission_ids = [rp.permission_id for rp in role_permissions]
        permissions = self.db.query(Permission).filter(
            Permission.id.in_(permission_ids)
        ).all()

        return [p.name for p in permissions]

    def assign_role_to_membership(self, membership_id: str, role_id: str):
        membership = self.db.query(Membership).filter(
            Membership.id == membership_id
        ).first()

        if membership:
            membership.role_id = role_id
            self.db.commit()