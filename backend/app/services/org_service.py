from sqlalchemy.orm import Session
from fastapi import HTTPException, status, BackgroundTasks
from typing import List, Dict, Tuple, Optional
from ..models.user import User
from ..models.organization import Organization
from ..models.membership import Membership, MembershipStatus
from ..models.role import Role
from ..models.org_settings import OrgSettings
from ..schemas.organization import OrganizationCreate
from ..schemas.membership import InviteUserRequest
from ..core.security import get_password_hash
from ..services.email_service import email_service
from ..core.config import settings
from ..core.database import SessionLocal  # 🆕 Import SessionLocal for background tasks
import re
import secrets
from datetime import datetime, timedelta, timezone
import asyncio
import threading
import logging

logger = logging.getLogger(__name__)


class OrgService:
    def __init__(self, db: Session):
        self.db = db
        self.role_hierarchy = {"owner": 4, "admin": 3, "manager": 2, "member": 1}
        self.background_tasks = None

    def set_background_tasks(self, background_tasks: BackgroundTasks):
        """Set background tasks from the route"""
        self.background_tasks = background_tasks

    def _get_role_level(self, role_name: str) -> int:
        """Get hierarchy level for role"""
        if not role_name:
            return 0
        return self.role_hierarchy.get(role_name.lower(), 0)

    def _can_assign_role(self, inviter_role: Role, target_role: Role) -> bool:
        """Enterprise: Check if inviter can assign target role based on hierarchy"""
        if not inviter_role or not target_role:
            return False

        inviter_level = self._get_role_level(inviter_role.name)
        target_level = self._get_role_level(target_role.name)

        if inviter_role.name.lower() == "owner":
            return True

        return inviter_level >= target_level

    def _validate_invitation_limits(self, org_id: str, inviter: User) -> bool:
        """Enterprise: Validate organization invitation limits"""
        pending_count = self.db.query(Membership).filter(
            Membership.organization_id == org_id,
            Membership.status == MembershipStatus.invited,
            Membership.invitation_expires_at > datetime.now(timezone.utc)
        ).count()

        return pending_count < 100

    def create_organization(self, data: OrganizationCreate, creator_user: User) -> Organization:
        existing_org = self.db.query(Organization).filter(
            Organization.slug == data.slug
        ).first()

        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization slug already exists"
            )

        org = Organization(
            name=data.name,
            slug=data.slug,
            description=data.description
        )
        self.db.add(org)
        self.db.commit()
        self.db.refresh(org)

        settings = OrgSettings(organization_id=org.id)
        self.db.add(settings)

        owner_role = self.db.query(Role).filter(Role.name == "owner").first()

        membership = Membership(
            user_id=creator_user.id,
            organization_id=org.id,
            role_id=owner_role.id if owner_role else None,
            status=MembershipStatus.active
        )
        self.db.add(membership)
        self.db.commit()

        return org

    def get_user_organizations(self, user: User) -> list[Organization]:
        logger.info(f"Getting organizations for user: {user.email}")

        memberships = self.db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.status == MembershipStatus.active
        ).all()

        if not memberships:
            logger.warning(f"No memberships found for user {user.email}")
            return []

        org_ids = [m.organization_id for m in memberships]
        organizations = self.db.query(Organization).filter(
            Organization.id.in_(org_ids)
        ).all()
        logger.info(f"Found {len(organizations)} organizations for user {user.email}")

        return organizations

    def get_organization_members(self, org_id: str) -> list[dict]:
        """Enterprise: Get members with full_name from membership.invited_full_name for pending"""
        memberships = self.db.query(Membership).filter(
            Membership.organization_id == org_id
        ).all()

        result = []
        for membership in memberships:
            user = None
            if membership.user_id:
                user = self.db.query(User).filter(User.id == membership.user_id).first()

            role = None
            if membership.role_id:
                role = self.db.query(Role).filter(Role.id == membership.role_id).first()

            if membership.status == MembershipStatus.invited and not user:
                user_email = membership.invited_email
                user_full_name = membership.invited_full_name
            else:
                user_email = user.email if user else membership.invited_email
                user_full_name = user.full_name if user else membership.invited_full_name

            result.append({
                "id": membership.id,
                "user_id": membership.user_id,
                "organization_id": membership.organization_id,
                "role_id": membership.role_id,
                "status": membership.status,
                "created_at": membership.created_at,
                "user_email": user_email,
                "user_full_name": user_full_name,
                "role_name": role.name if role else None,
                "invited_email": membership.invited_email,
                "invitation_expires_at": membership.invitation_expires_at,
                "is_pending": membership.status == MembershipStatus.invited
            })

        return result

    def invite_user(self, org_id: str, data: InviteUserRequest, inviter: User = None, background_tasks: BackgroundTasks = None) -> Membership:
        """Enterprise: Invite user with enhanced validation"""
        logger.info(f"ENTERPRISE invitation process for {data.email} to org {org_id}")

        # Set background tasks if provided
        if background_tasks:
            self.background_tasks = background_tasks

        org = self.db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        role = self.db.query(Role).filter(Role.id == data.role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # ENTERPRISE: Role hierarchy validation
        if inviter:
            inviter_membership = self.db.query(Membership).filter(
                Membership.user_id == inviter.id,
                Membership.organization_id == org_id
            ).first()

            if inviter_membership and inviter_membership.role_id:
                inviter_role = self.db.query(Role).filter(Role.id == inviter_membership.role_id).first()
                if inviter_role and not self._can_assign_role(inviter_role, role):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Cannot assign role '{role.name}' - you can only assign roles equal or lower than your current role '{inviter_role.name}'"
                    )

        # ENTERPRISE: Invitation limits
        if not self._validate_invitation_limits(org_id, inviter):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization invitation limit reached. Please try again later."
            )

        user = self.db.query(User).filter(User.email == data.email).first()

        if user:
            existing_membership = self.db.query(Membership).filter(
                Membership.user_id == user.id,
                Membership.organization_id == org_id
            ).first()

            if existing_membership:
                if existing_membership.status == MembershipStatus.invited:
                    logger.warning(f"User already invited, regenerating token for {data.email}")
                    existing_membership.invitation_token = secrets.token_urlsafe(32)
                    existing_membership.invitation_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
                    # CRITICAL FIX: Ensure email is set when regenerating token
                    existing_membership.invited_email = data.email
                    existing_membership.invited_full_name = getattr(data, 'full_name', None)
                    self.db.commit()
                    self.db.refresh(existing_membership)  # 🆕 Refresh to get updated token

                    if getattr(data, 'send_invitation_email', True):
                        # 🎯 ENTERPRISE: Extract data BEFORE passing to background task
                        email_data = {
                            "to_email": data.email,
                            "invitation_token": existing_membership.invitation_token,
                            "org_name": org.name,
                            "inviter_name": inviter.full_name if inviter and inviter.full_name else (inviter.email if inviter else "Someone"),
                            "org_id": org_id
                        }

                        if self.background_tasks:
                            self.background_tasks.add_task(
                                self._send_invitation_email_background,
                                **email_data
                            )
                        else:
                            # Fallback: run in background thread
                            self._run_in_background_thread(
                                self._send_invitation_email_background,
                                **email_data
                            )

                    logger.info(f"Invitation resent to {data.email}")
                    return existing_membership
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="User is already a member of this organization"
                    )
            else:
                logger.info(f"User exists, creating invitation membership for {data.email}")
                return self._create_invitation_membership(
                    user.id, org_id, data.role_id, data.email, org.name, inviter,
                    getattr(data, 'send_invitation_email', True), getattr(data, 'full_name', None)
                )
        else:
            logger.info(f"User doesn't exist, creating invitation record for {data.email}")
            return self._create_invitation_only_membership(
                data.email, org_id, data.role_id, org.name, inviter,
                getattr(data, 'send_invitation_email', True), getattr(data, 'full_name', None)
            )

    async def _send_invitation_email_async(self, to_email: str, invitation_token: str, org_name: str, inviter_name: str):
        """🎯 ENTERPRISE: Async email sending with queue"""
        try:
            invite_link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={invitation_token}"

            # 🎯 ENTERPRISE: Use async email service with queue
            await email_service.send_invitation_email(
                to_email=to_email,
                invite_link=invite_link,
                org_name=org_name,
                invited_by=inviter_name
                # Note: We don't pass db here - email service creates its own session
            )
            logger.info(f"Invitation email queued to {to_email}")
        except Exception as e:
            logger.error(f"Failed to send invitation email to {to_email}: {e}")
            # 🎯 ENTERPRISE: Log error but don't crash the background task

    def _send_invitation_email_background(self, to_email: str, invitation_token: str, org_name: str, inviter_name: str, org_id: Optional[str] = None):
        """🎯 ENTERPRISE: Background task wrapper for email sending"""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    self._send_invitation_email_async(
                        to_email=to_email,
                        invitation_token=invitation_token,
                        org_name=org_name,
                        inviter_name=inviter_name
                    )
                )
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"Background email task failed for {to_email}: {e}")

    def _run_in_background_thread(self, func, *args, **kwargs):
        """Run function in background thread (enterprise-safe)"""
        thread = threading.Thread(
            target=func,
            args=args,
            kwargs=kwargs,
            daemon=True  # 🎯 ENTERPRISE: Daemon thread won't block shutdown
        )
        thread.start()
        logger.debug(f"Started background thread for {func.__name__}")

    def _create_invitation_membership(self, user_id: str, org_id: str, role_id: str, email: str,
                                      org_name: str, inviter: User = None, send_email: bool = True,
                                      full_name: str = None) -> Membership:
        """Create membership for existing user"""
        invitation_token = secrets.token_urlsafe(32)
        invitation_expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        membership = Membership(
            user_id=user_id,
            organization_id=org_id,
            role_id=role_id,
            status=MembershipStatus.invited,
            invitation_token=invitation_token,
            invitation_expires_at=invitation_expires_at,
            invited_email=email,
            invited_full_name=full_name
        )
        self.db.add(membership)
        self.db.commit()
        self.db.refresh(membership)

        if send_email:
            # 🎯 ENTERPRISE: Extract inviter data BEFORE background task
            inviter_name = inviter.full_name if inviter and inviter.full_name else (inviter.email if inviter else "Someone")

            email_data = {
                "to_email": email,
                "invitation_token": invitation_token,
                "org_name": org_name,
                "inviter_name": inviter_name,
                "org_id": org_id
            }

            if self.background_tasks:
                self.background_tasks.add_task(
                    self._send_invitation_email_background,
                    **email_data
                )
            else:
                self._run_in_background_thread(
                    self._send_invitation_email_background,
                    **email_data
                )

        return membership

    def _create_invitation_only_membership(self, email: str, org_id: str, role_id: str, org_name: str,
                                           inviter: User = None, send_email: bool = True,
                                           full_name: str = None) -> Membership:
        """Enterprise: Create invitation for non-existent user with full_name"""
        invitation_token = secrets.token_urlsafe(32)
        invitation_expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        membership = Membership(
            user_id=None,
            organization_id=org_id,
            role_id=role_id,
            status=MembershipStatus.invited,
            invitation_token=invitation_token,
            invitation_expires_at=invitation_expires_at,
            invited_email=email,
            invited_full_name=full_name
        )
        self.db.add(membership)
        self.db.commit()
        self.db.refresh(membership)

        if send_email:
            # 🎯 ENTERPRISE: Extract inviter data BEFORE background task
            inviter_name = inviter.full_name if inviter and inviter.full_name else (inviter.email if inviter else "Someone")

            email_data = {
                "to_email": email,
                "invitation_token": invitation_token,
                "org_name": org_name,
                "inviter_name": inviter_name,
                "org_id": org_id
            }

            if self.background_tasks:
                self.background_tasks.add_task(
                    self._send_invitation_email_background,
                    **email_data
                )
            else:
                self._run_in_background_thread(
                    self._send_invitation_email_background,
                    **email_data
                )

        return membership

    def update_member_role(self, membership_id: str, new_role_id: str, updater: User = None, org_id: str = None) -> Membership:
        """Enterprise: Update member role with hierarchy validation"""
        membership = self.db.query(Membership).filter(
            Membership.id == membership_id
        ).first()

        if not membership:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Membership not found"
            )

        role = self.db.query(Role).filter(Role.id == new_role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        if updater and org_id:
            updater_membership = self.db.query(Membership).filter(
                Membership.user_id == updater.id,
                Membership.organization_id == org_id
            ).first()

            if updater_membership and updater_membership.role_id:
                updater_role = self.db.query(Role).filter(Role.id == updater_membership.role_id).first()
                if updater_role and not self._can_assign_role(updater_role, role):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Cannot assign role '{role.name}' - you can only assign roles equal or lower than your current role"
                    )

        membership.role_id = new_role_id
        self.db.commit()
        self.db.refresh(membership)

        return membership