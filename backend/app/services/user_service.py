from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from ..models.user import User
from ..models.organization import Organization
from ..models.membership import Membership, MembershipStatus
from ..models.role import Role
from ..schemas.invitation import InviteUserRequest
from ..core.security import get_password_hash
import secrets


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def invite_user_to_org(
            self,
            org_id: str,
            inviter: User,
            data: InviteUserRequest
    ) -> Membership:
        """
        Invite a user to join an organization.
        If the user doesn't exist, create a placeholder account.
        """

        # Verify organization exists
        org = self.db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Verify role exists
        role = self.db.query(Role).filter(Role.id == data.role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Check if user exists
        user = self.db.query(User).filter(User.email == data.email).first()

        if not user:
            # Create placeholder user account for invitation
            temp_password = secrets.token_urlsafe(32)
            user = User(
                email=data.email,
                hashed_password=get_password_hash(temp_password),
                full_name=data.email.split('@')[0],
                is_active=True
            )
            self.db.add(user)
            self.db.flush()

        # Check if membership already exists
        existing_membership = self.db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.organization_id == org_id
        ).first()

        if existing_membership:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already a member of this organization"
            )

        # Create membership with invited status
        membership = Membership(
            user_id=user.id,
            organization_id=org_id,
            role_id=data.role_id,
            status=MembershipStatus.invited
        )

        self.db.add(membership)
        self.db.commit()
        self.db.refresh(membership)

        return membership

    def update_user_role(
            self,
            membership_id: str,
            new_role_id: str
    ) -> Membership:
        """Update a user's role in an organization."""

        membership = self.db.query(Membership).filter(
            Membership.id == membership_id
        ).first()

        if not membership:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Membership not found"
            )

        # Verify new role exists
        role = self.db.query(Role).filter(Role.id == new_role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        membership.role_id = new_role_id
        self.db.commit()
        self.db.refresh(membership)

        return membership

    def remove_user_from_org(
            self,
            membership_id: str,
            org_id: str
    ) -> None:
        """Remove a user from an organization."""

        membership = self.db.query(Membership).filter(
            Membership.id == membership_id,
            Membership.organization_id == org_id
        ).first()

        if not membership:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Membership not found"
            )

        self.db.delete(membership)
        self.db.commit()
