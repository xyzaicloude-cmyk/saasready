from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from ..models.user import User
from ..models.organization import Organization
from ..models.membership import Membership, MembershipStatus
from ..models.role import Role
from ..schemas.invitation import InviteUserRequest
from ..core.security import get_password_hash
from ..services.email_service import email_service
from ..core.config import settings
import secrets
from datetime import datetime, timedelta,timezone
import asyncio


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
                full_name=data.full_name or data.email.split('@')[0],
                is_active=True,
                is_email_verified=False  # Will need verification
            )
            self.db.add(user)
            self.db.flush()

        # Check if membership already exists
        existing_membership = self.db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.organization_id == org_id
        ).first()

        if existing_membership:
            # If existing membership is invited, we can resend the invitation
            if existing_membership.status == MembershipStatus.invited:
                # Update token and expiry
                existing_membership.invitation_token = secrets.token_urlsafe(32)
                existing_membership.invitation_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
                self.db.commit()

                # 🎯 ENTERPRISE: Async email sending
                invite_link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={existing_membership.invitation_token}"
                asyncio.create_task(
                    email_service.send_invitation_email(
                        to_email=data.email,
                        invite_link=invite_link,
                        org_name=org.name,
                        invited_by=inviter.full_name or inviter.email
                    )
                )

                return existing_membership
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User is already a member of this organization"
                )

        # Generate invitation token
        invitation_token = secrets.token_urlsafe(32)
        invitation_expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        # Create membership with invited status
        membership = Membership(
            user_id=user.id,
            organization_id=org_id,
            role_id=data.role_id,
            status=MembershipStatus.invited,
            invitation_token=invitation_token,
            invitation_expires_at=invitation_expires_at
        )

        self.db.add(membership)
        self.db.commit()
        self.db.refresh(membership)

        # 🎯 ENTERPRISE: Async email sending
        invite_link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={invitation_token}"
        asyncio.create_task(
            email_service.send_invitation_email(
                to_email=data.email,
                invite_link=invite_link,
                org_name=org.name,
                invited_by=inviter.full_name or inviter.email
            )
        )

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

# In the invite_user_to_org method, enhance the audit logging:

# After sending the invitation email, add more detailed audit logging
print(f"✅ Invitation sent to {data.email} for organization {org.name}")

# Log the invitation event in more detail
if request:
    audit_service = AuditService(self.db)
    audit_service.log_event(
        actor_user_id=inviter.id,
        organization_id=org_id,
        action="user.invite.sent",
        target_type="membership",
        target_id=membership.id,
        metadata={
            "invited_email": data.email,
            "role_id": str(data.role_id),
            "role_name": role.name,
            "inviter_id": str(inviter.id),
            "inviter_email": inviter.email,
            "invitation_expires_at": invitation_expires_at.isoformat()
        },
        request=request
    )