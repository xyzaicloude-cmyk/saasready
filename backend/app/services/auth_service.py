# backend/app/services/auth_service.py
"""
🔧 FIXED VERSION - Enterprise Auth Service
All token handling issues resolved, invitation flow fixed
"""
from sqlalchemy.orm import Session
from datetime import timedelta
from fastapi import HTTPException, status, Request, BackgroundTasks
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from ..models.user import User
from ..models.organization import Organization
from ..models.membership import Membership, MembershipStatus
from ..models.role import Role
from ..core.security import (
    verify_password,
    get_password_hash,
    validate_password_length,
    create_access_token,  # 🔧 FIXED: This returns string
    validate_password_strength,
    revoke_all_user_tokens
)
from ..core.config import settings
from ..schemas.auth import RegisterRequest, LoginRequest
from ..services.audit_service import AuditService
from ..services.email_service import email_service
import re
import traceback
import secrets
from datetime import datetime, timezone
import threading


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.background_tasks = None

    def set_background_tasks(self, background_tasks: BackgroundTasks):
        """Set background tasks from the route"""
        self.background_tasks = background_tasks

    def _run_in_background_thread(self, coro_func, *args, **kwargs):
        """Run async function in background thread"""

        def run_async():
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(coro_func(*args, **kwargs))
            except Exception as e:
                print(f"❌ Error in background thread: {e}")
            finally:
                loop.close()

        thread = threading.Thread(target=run_async, daemon=True)
        thread.start()

    def register_user(
            self,
            data: RegisterRequest,
            request: Request = None,
            invitation_token: str = None,
            background_tasks: BackgroundTasks = None
    ) -> tuple[User, str]:
        """
        🔧 FIXED: Register user with proper transaction management
        Returns: (user, access_token_string)
        """
        print(f"📧 [DEBUG] Starting registration process for: {data.email}")
        print(f"📧 [DEBUG] Invitation token: {invitation_token}")

        transaction_active = self.db.in_transaction()
        print(f"📧 [DEBUG] Transaction already active: {transaction_active}")

        # Set background tasks if provided
        if background_tasks:
            self.background_tasks = background_tasks

        # 🆕 INPUT SANITIZATION: Normalize email and trim name
        data.email = data.email.strip().lower()
        data.full_name = data.full_name.strip()[:255]

        if not validate_password_length(data.password):
            print(f"❌ Password too long for user: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password cannot exceed 72 characters. Please use a shorter password."
            )

        existing_user = self.db.query(User).filter(User.email == data.email).first()
        if existing_user:
            print(f"❌ User already exists: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Start a fresh transaction
        try:
            print("📧 [DEBUG] Starting database transaction...")

            # Check if this is the first user in the system (admin)
            user_count = self.db.query(User).count()
            is_first_user = user_count == 0
            print(f"📧 [DEBUG] Is first user: {is_first_user}")

            # CRITICAL FIX: Check for invitation BEFORE creating user
            is_invitation_registration = invitation_token is not None
            print(f"📧 [DEBUG] Is invitation registration: {is_invitation_registration}")

            # If there's an invitation token, validate it first
            invitation_membership = None
            if is_invitation_registration:
                print(f"📧 [DEBUG] Validating invitation token before creating user...")
                invitation_membership = self.db.query(Membership).filter(
                    Membership.invitation_token == invitation_token,
                    Membership.invitation_expires_at > datetime.now(timezone.utc),
                    Membership.status == MembershipStatus.invited
                ).first()

                if not invitation_membership:
                    print("❌ Invalid or expired invitation token")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid or expired invitation token"
                    )

                # ENTERPRISE: Strict email matching for invited users
                if (
                        invitation_membership.invited_email
                        and data.email.lower() != invitation_membership.invited_email.lower()
                ):
                    print(
                        f"❌ Email mismatch. Expected: {invitation_membership.invited_email}, "
                        f"Got: {data.email}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            "Please register with the invited email address: "
                            f"{invitation_membership.invited_email}"
                        )
                    )

                print(f"✅ Valid invitation found for org: {invitation_membership.organization_id}")

            verification_token = secrets.token_urlsafe(32)
            verification_sent_at = datetime.now(timezone.utc)
            # Auto-verify if it's first user OR invitation-based registration
            is_email_verified = is_first_user or is_invitation_registration
            print(f"📧 [DEBUG] Email verified: {is_email_verified}")

            print("📧 [DEBUG] Creating user object...")
            user = User(
                email=data.email,
                hashed_password=get_password_hash(data.password),
                full_name=data.full_name,
                is_active=True,
                is_email_verified=is_email_verified,
                is_superuser=is_first_user,
                email_verification_token=verification_token if not is_email_verified else None,
                email_verification_sent_at=verification_sent_at if not is_email_verified else None,
            )
            self.db.add(user)
            self.db.flush()  # Use flush instead of commit to keep transaction open
            print(f"✅ User created with ID: {user.id}")

            # CRITICAL FIX: Handle invitation-based registration FIRST - NO PERSONAL ORG
            if is_invitation_registration and invitation_membership:
                print("🎯 [DEBUG] ENTERPRISE FLOW: Processing invitation during registration")

                # Activate the membership
                invitation_membership.user_id = user.id
                invitation_membership.status = MembershipStatus.active
                invitation_membership.invitation_token = None
                invitation_membership.invitation_expires_at = None

                print(
                    "✅ Membership activated for user in org: "
                    f"{invitation_membership.organization_id}"
                )

                # CRITICAL: Commit and return immediately - NO personal org creation
                print("📧 [DEBUG] Committing invitation transaction...")
                self.db.commit()
                self.db.refresh(user)

                # 🔧 FIXED: Generate token properly
                access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
                access_token = create_access_token(
                    data={"sub": str(user.id)},
                    expires_delta=access_token_expires
                )
                print(f"✅ Access token generated for user: {user.id}")

                if request:
                    audit_service = AuditService(self.db)
                    audit_service.log_event(
                        actor_user_id=user.id,
                        organization_id=invitation_membership.organization_id,
                        action="user.registered.via_invitation",
                        target_type="user",
                        target_id=user.id,
                        metadata={
                            "email": user.email,
                            "organization_id": invitation_membership.organization_id,
                            "invitation_token": invitation_token,
                            "role_id": str(invitation_membership.role_id),
                        },
                        request=request,
                    )

                print(
                    f"🎉 ENTERPRISE: User registered via invitation: {user.email} "
                    "- NO personal org created"
                )
                return user, access_token  # 🔧 FIXED: Return (user, token_string)

            # NORMAL REGISTRATION FLOW - Only for non-invited users
            print("📧 [DEBUG] Standard registration flow - creating personal organization")
            base_name = data.full_name or data.email.split("@")[0]
            base_slug = re.sub(r"[^a-z0-9]+", "-", base_name.lower()).strip("-")
            slug = base_slug
            counter = 1

            while self.db.query(Organization).filter(Organization.slug == slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1

            print(f"📧 Creating organization with slug: {slug}")
            org = Organization(
                name=f"{base_name}'s Organization",
                slug=slug,
                description="Personal workspace",
            )
            self.db.add(org)
            self.db.flush()
            print(f"✅ Organization created with ID: {org.id}")

            print("📧 Looking for owner role...")
            owner_role = self.db.query(Role).filter(Role.name == "owner").first()
            if not owner_role:
                print("❌ Owner role not found, creating...")
                owner_role = Role(name="owner", description="Organization owner")
                self.db.add(owner_role)
                self.db.flush()
                print(f"✅ Created owner role with ID: {owner_role.id}")
            else:
                print(f"✅ Found owner role with ID: {owner_role.id}")

            print("📧 Creating membership...")
            membership = Membership(
                user_id=user.id,
                organization_id=org.id,
                role_id=owner_role.id,
                status=MembershipStatus.active,
            )
            self.db.add(membership)

            print("📧 Committing main transaction...")
            self.db.commit()
            self.db.refresh(user)
            print("✅ Transaction committed successfully")

            # 🎯 ENTERPRISE: Background email sending with queue
            # Only send verification email if it's NOT the first user
            if not is_first_user:
                verify_link = (
                    f"{settings.FRONTEND_BASE_URL}/verify-email?token={verification_token}"
                )

                # Use background tasks or fallback thread
                if self.background_tasks:
                    self.background_tasks.add_task(
                        self._send_verification_email_async,
                        user.email,
                        verify_link,
                    )
                else:
                    self._run_in_background_thread(
                        self._send_verification_email_async,
                        user.email,
                        verify_link,
                    )
                print(f"✅ Verification email queued for: {user.email}")
            elif is_first_user:
                print(f"🎉 First user ({user.email}) auto-verified as admin")

            if request:
                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=org.id,
                    action="user.registered",
                    target_type="user",
                    target_id=user.id,
                    metadata={
                        "email": user.email,
                        "full_name": user.full_name,
                        "is_first_user": is_first_user,
                        "auto_verified": is_first_user,
                    },
                    request=request,
                )

                if not is_first_user:
                    audit_service.log_event(
                        actor_user_id=user.id,
                        organization_id=org.id,
                        action="user.email.verification.sent",
                        target_type="user",
                        target_id=user.id,
                        metadata={"email": user.email},
                        request=request,
                    )

        except IntegrityError as e:
            print(f"❌ [DEBUG] Database integrity error: {str(e)}")
            if self.db.is_active:
                try:
                    self.db.rollback()
                    print("✅ Transaction rolled back due to integrity error")
                except Exception as rollback_error:
                    print(f"⚠️ Rollback failed: {rollback_error}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed due to database constraints",
            )
        except SQLAlchemyError as e:
            print(f"❌ [DEBUG] Database error: {str(e)}")
            if self.db.is_active:
                try:
                    self.db.rollback()
                    print("✅ Transaction rolled back due to SQLAlchemy error")
                except Exception as rollback_error:
                    print(f"⚠️ Rollback failed: {rollback_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error during registration",
            )
        except HTTPException as e:
            print(f"❌ [DEBUG] HTTP Exception: {e.detail}")
            if self.db.is_active:
                try:
                    self.db.rollback()
                    print("✅ Transaction rolled back due to HTTP exception")
                except Exception as rollback_error:
                    print(f"⚠️ Rollback failed: {rollback_error}")
            raise e
        except Exception as e:
            print(f"❌ [DEBUG] Unexpected error: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            if self.db.is_active:
                try:
                    self.db.rollback()
                    print("✅ Transaction rolled back due to unexpected error")
                except Exception as rollback_error:
                    print(f"⚠️ Rollback failed: {rollback_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Registration failed: {str(e)}",
            )

        # 🔧 FIXED: Generate token properly for normal registration
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)},
            expires_delta=access_token_expires,
        )
        print(f"✅ Access token created for user: {user.id}")

        return user, access_token

    async def _send_verification_email_async(self, email: str, verify_link: str):
        """Async wrapper for sending verification email"""
        try:
            await email_service.send_verification_email(
                to_email=email,
                verify_link=verify_link,
            )
        except Exception as e:
            print(f"❌ Error sending verification email: {e}")

    def verify_email(self, token: str, request: Request = None) -> User:
        """Verify user email using token"""
        print("📧 Email verification attempt with token")

        user = self.db.query(User).filter(
            User.email_verification_token == token,
            User.email_verification_sent_at
            > datetime.now(timezone.utc) - timedelta(hours=24),
            ).first()

        if not user:
            print("❌ Invalid or expired email verification token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        if user.is_email_verified:
            print(f"⚠️ Email already verified for: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already verified",
            )

        user.is_email_verified = True
        user.email_verification_token = None
        user.email_verification_sent_at = None
        self.db.commit()

        print(f"✅ Email verified successfully for: {user.email}")

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.email.verified",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request,
            )

        return user

    def resend_verification_email(self, email: str, request: Request = None) -> bool:
        """Resend email verification"""
        print(f"📧 Resend verification email for: {email}")

        user = self.db.query(User).filter(User.email == email).first()

        if not user:
            return True

        if user.is_email_verified:
            print(f"⚠️ Email already verified for: {user.email}")
            return True

        verification_token = secrets.token_urlsafe(32)
        verification_sent_at = datetime.now(timezone.utc)

        user.email_verification_token = verification_token
        user.email_verification_sent_at = verification_sent_at
        self.db.commit()

        verify_link = f"{settings.FRONTEND_BASE_URL}/verify-email?token={verification_token}"

        # 🎯 ENTERPRISE: Background email sending
        if self.background_tasks:
            self.background_tasks.add_task(
                self._send_verification_email_async,
                user.email,
                verify_link,
            )
        else:
            self._run_in_background_thread(
                self._send_verification_email_async,
                user.email,
                verify_link,
            )

        print(f"✅ Verification email queued for resend to: {user.email}")

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.email.verification.sent",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email, "resend": True},
                request=request,
            )

        return True

    def login_user(self, data: LoginRequest, request: Request = None) -> tuple[User, str]:
        """
        🔧 FIXED: Login user with proper token handling
        Returns: (user, access_token_string)
        """
        print(f"📧 Login attempt for: {data.email}")
# In login_user method
        email_normalized = data.email.strip().lower()
        user = self.db.query(User).filter(User.email == email_normalized).first()
        #user = self.db.query(User).filter(User.email == data.email).first()

        if not user:
            print(f"❌ User not found: {data.email}")

            if request:
                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=None,
                    organization_id=None,
                    action="user.login.failed",
                    target_type="user",
                    target_id=None,
                    metadata={"email": data.email, "reason": "user_not_found"},
                    request=request,
                )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )

        if not verify_password(data.password, user.hashed_password):
            print(f"❌ Invalid password for: {data.email}")

            if request:
                membership = self.db.query(Membership).filter(
                    Membership.user_id == user.id
                ).first()

                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=membership.organization_id if membership else None,
                    action="user.login.failed",
                    target_type="user",
                    target_id=user.id,
                    metadata={"email": data.email, "reason": "invalid_password"},
                    request=request,
                )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )

        if not user.is_active:
            print(f"❌ User inactive: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user",
            )

        # Check if user has at least one active organization membership
        active_membership = self.db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.status == MembershipStatus.active,
            ).first()

        if not active_membership:
            print(
                f"❌ User has no active organization memberships: {data.email}"
            )

            if request:
                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=None,
                    action="user.login.failed",
                    target_type="user",
                    target_id=user.id,
                    metadata={"email": data.email, "reason": "no_active_organization"},
                    request=request,
                )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Your account is not associated with any active organization. "
                    "Please accept any pending invitations."
                ),
            )

        if not user.is_email_verified:
            print(f"❌ Email not verified for: {data.email}")

            if request:
                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=active_membership.organization_id,
                    action="user.login.failed",
                    target_type="user",
                    target_id=user.id,
                    metadata={"email": data.email, "reason": "email_not_verified"},
                    request=request,
                )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please verify your email address before logging in",
            )

        # 🔧 FIXED: Generate token properly
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)},
            expires_delta=access_token_expires,
        )
        print(f"✅ Login successful for: {data.email}")

        if request:
            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=active_membership.organization_id,
                action="user.login.success",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request,
            )

            pending_invitations = self.db.query(Membership).filter(
                Membership.user_id == user.id,
                Membership.status == MembershipStatus.invited,
                ).count()

            if pending_invitations > 0:
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=active_membership.organization_id,
                    action="user.login.with_pending_invitations",
                    target_type="user",
                    target_id=user.id,
                    metadata={
                        "email": user.email,
                        "pending_invitations_count": pending_invitations,
                    },
                    request=request,
                )

        return user, access_token

    def request_password_reset(self, email: str, request: Request = None) -> bool:
        """Request a password reset for a user"""
        print(f"📧 Password reset request for: {email}")

        user = self.db.query(User).filter(User.email == email).first()

        if not user:
            print(f"⚠️ Password reset requested for non-existent email: {email}")
            return True

        if not user.is_active:
            print(f"⚠️ Password reset requested for inactive user: {email}")
            return True

        reset_token = secrets.token_urlsafe(32)
        reset_token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        user.reset_token = reset_token
        user.reset_token_expires_at = reset_token_expires_at
        self.db.commit()

        reset_link = (
            f"{settings.FRONTEND_BASE_URL}/reset-password?token={reset_token}"
        )

        # 🎯 ENTERPRISE: Background email sending
        async def send_password_reset_async():
            await email_service.send_password_reset_email(
                to_email=user.email,
                reset_link=reset_link,
            )

        if self.background_tasks:
            self.background_tasks.add_task(send_password_reset_async)
        else:
            self._run_in_background_thread(send_password_reset_async)

        print(f"✅ Password reset email queued for: {email}")

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.password.reset_request",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request,
            )

        return True

    def reset_password(
            self, token: str, new_password: str, request: Request = None
    ) -> User:
        """Reset user password using token"""
        print("📧 Password reset attempt with token")

        if not validate_password_length(new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password cannot exceed 72 characters",
            )

        user = self.db.query(User).filter(
            User.reset_token == token,
            User.reset_token_expires_at > datetime.now(timezone.utc),
            ).first()

        if not user:
            print("❌ Invalid or expired password reset token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        if not user.is_active:
            print(
                f"❌ Password reset attempted for inactive user: {user.email}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is inactive",
            )

        user.hashed_password = get_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expires_at = None
        self.db.commit()

        print(f"✅ Password reset successful for: {user.email}")

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.password.reset_success",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request,
            )

        return user

    def change_password(
            self,
            user: User,
            old_password: str,
            new_password: str,
            request: Request = None,
    ) -> None:
        """Change user password. Logs audit event."""
        # 🆕 ENHANCED: Add password strength validation and session revocation

        if not verify_password(old_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        # Validate password strength
        is_valid, error = validate_password_strength(new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error,
            )

        if not validate_password_length(new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password cannot exceed 72 characters",
            )

        user.hashed_password = get_password_hash(new_password)
        user.password_changed_at = datetime.now(
            timezone.utc
        )  # 🆕 Track password change time
        self.db.commit()

        # 🆕 CRITICAL: Revoke all sessions for security
        revoked_count = revoke_all_user_tokens(
            user_id=user.id,
            reason="password_changed",
            db=self.db,
        )

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.password.changed",
                target_type="user",
                target_id=user.id,
                metadata={
                    "email": user.email,
                    "password_changed_at": user.password_changed_at.isoformat(),
                    "sessions_revoked": revoked_count,
                },
                request=request,
            )

    def accept_invitation(self, token: str, request: Request = None) -> dict:
        """Accept organization invitation - ENTERPRISE FLOW (metadata only)"""
        print("📧 ENTERPRISE invitation acceptance attempt with token")

        membership = self.db.query(Membership).filter(
            Membership.invitation_token == token,
            Membership.invitation_expires_at > datetime.now(timezone.utc),
            Membership.status == MembershipStatus.invited,
            ).first()

        if not membership:
            print("❌ Invalid or expired invitation token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired invitation token",
            )

        org = self.db.query(Organization).filter(
            Organization.id == membership.organization_id
        ).first()
        if not org:
            print("❌ Organization not found for invitation")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid invitation",
            )

        return {
            "invitation_valid": True,
            "organization_name": org.name,
            "organization_id": org.id,
            "invited_email": membership.invited_email,
            "requires_registration": membership.user_id is None,
            "role_id": membership.role_id,
        }

    def complete_invitation_after_registration(
            self, user: User, token: str, request: Request = None
    ) -> Membership:
        """Complete invitation after user registers - ENTERPRISE FLOW"""
        print(f"📧 Completing invitation for user: {user.email}")

        try:
            membership = self.db.query(Membership).filter(
                Membership.invitation_token == token,
                Membership.invitation_expires_at > datetime.now(timezone.utc),
                Membership.status == MembershipStatus.invited,
                ).first()

            if not membership:
                print("❌ Invalid or expired invitation token")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired invitation token",
                )

            # ENTERPRISE: Strict email matching
            if (
                    membership.invited_email
                    and user.email.lower() != membership.invited_email.lower()
            ):
                print(
                    f"❌ Email mismatch. Expected: {membership.invited_email}, "
                    f"Got: {user.email}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Please register with the invited email address: "
                        f"{membership.invited_email}"
                    ),
                )

            old_status = membership.status
            membership.user_id = user.id
            membership.status = MembershipStatus.active
            membership.invitation_token = None
            membership.invitation_expires_at = None

            if not user.is_email_verified:
                user.is_email_verified = True
                user.email_verification_token = None
                user.email_verification_sent_at = None
                print(f"✅ Auto-verified email for invited user: {user.email}")

            self.db.commit()

            print(
                "✅ ENTERPRISE: Invitation completed for user: "
                f"{user.email} in org: {membership.organization_id}"
            )

            if request:
                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=membership.organization_id,
                    action="user.invite.accepted",
                    target_type="membership",
                    target_id=membership.id,
                    metadata={
                        "old_status": old_status.value,
                        "new_status": membership.status.value,
                        "user_email": user.email,
                    },
                    request=request,
                )

            return membership

        except Exception as e:
            print(f"❌ Error in complete_invitation_after_registration: {e}")
            if self.db.is_active:
                self.db.rollback()
            raise

    def accept_invitation_pre_login(
            self, token: str, request: Request = None
    ) -> dict:
        """Accept invitation without requiring login - ENTERPRISE FLOW"""
        print("📧 ENTERPRISE pre-login invitation acceptance with token")

        membership = self.db.query(Membership).filter(
            Membership.invitation_token == token,
            Membership.invitation_expires_at > datetime.now(timezone.utc),
            Membership.status == MembershipStatus.invited,
            ).first()

        if not membership:
            print("❌ Invalid or expired invitation token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired invitation token",
            )

        org = self.db.query(Organization).filter(
            Organization.id == membership.organization_id
        ).first()
        if not org:
            print("❌ Organization not found for invitation")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid invitation",
            )

        if membership.user_id is None:
            return {
                "invitation_valid": True,
                "organization_name": org.name,
                "organization_id": org.id,
                "invited_email": membership.invited_email,
                "requires_registration": True,
                "role_id": membership.role_id,
            }

        user = self.db.query(User).filter(User.id == membership.user_id).first()
        if not user:
            print("❌ User not found for membership")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid invitation",
            )

        old_status = membership.status
        membership.status = MembershipStatus.active
        membership.invitation_token = None
        membership.invitation_expires_at = None

        if not user.is_email_verified:
            user.is_email_verified = True
            user.email_verification_token = None
            user.email_verification_sent_at = None
            print(f"✅ Auto-verified email for invited user: {user.email}")

        self.db.commit()

        print(
            f"✅ Invitation accepted successfully for user: {user.email} in org: {org.id}"
        )

        if request:
            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id,
                action="user.invite.accepted",
                target_type="membership",
                target_id=membership.id,
                metadata={
                    "old_status": old_status.value,
                    "new_status": membership.status.value,
                    "user_email": user.email,
                    "pre_login": True,
                },
                request=request,
            )

        return {
            "invitation_valid": True,
            "organization_name": org.name,
            "organization_id": org.id,
            "invited_email": user.email,
            "requires_registration": False,
            "user_exists": True,
            "message": "Invitation accepted successfully. You can now log in.",
        }

    def logout_user(
            self, user: User, token: str = None, request: Request = None
    ) -> bool:
        """Logout user - revoke current session or all sessions"""
        print(f"📧 Logout request for user: {user.email}")

        try:
            from ..core.security import decode_access_token, revoke_token

            if token:
                # Revoke specific token
                payload = decode_access_token(token, self.db)
                if payload and payload.get("jti"):
                    jti = payload.get("jti")
                    expires_at = datetime.fromtimestamp(
                        payload["exp"], tz=timezone.utc
                    )
                    revoke_token(
                        jti=jti,
                        user_id=user.id,
                        expires_at=expires_at,
                        reason="user_logout",
                        db=self.db,
                    )
                    print(f"✅ Token revoked for user: {user.email}")
            else:
                # Revoke all user tokens
                revoked_count = revoke_all_user_tokens(
                    user_id=user.id,
                    reason="user_logout_all",
                    db=self.db,
                )
                print(
                    f"✅ All sessions revoked ({revoked_count}) for user: {user.email}"
                )

            if request:
                membership = self.db.query(Membership).filter(
                    Membership.user_id == user.id
                ).first()

                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=membership.organization_id if membership else None,
                    action="user.logout",
                    target_type="user",
                    target_id=user.id,
                    metadata={
                        "email": user.email,
                        "token_revoked": token is not None,
                        "all_sessions": token is None,
                    },
                    request=request,
                )

            return True

        except Exception as e:
            print(f"❌ Error during logout: {e}")
            return False

    def refresh_token(
            self, refresh_token: str, request: Request = None
    ) -> tuple[str, str]:
        """Refresh access token using refresh token"""
        print("📧 Token refresh attempt")

        from ..core.security import (
            decode_access_token,
            create_access_token,
            create_refresh_token,
        )

        payload = decode_access_token(refresh_token, self.db)
        if not payload or payload.get("type") != "refresh":
            print("❌ Invalid or expired refresh token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        user_id = payload.get("sub")
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            print("❌ User not found or inactive")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user",
            )

        # Create new access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": str(user.id)},
            expires_delta=access_token_expires,
        )

        # Create new refresh token (rotate)
        new_refresh_token = create_refresh_token(data={"sub": str(user.id)})

        print(f"✅ Token refreshed successfully for user: {user.email}")

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.token.refreshed",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request,
            )

        return new_access_token, new_refresh_token

    def get_user_by_id(self, user_id: str) -> User:
        """Get user by ID"""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user

    def get_user_by_email(self, email: str) -> User:
        """Get user by email"""
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user

    def update_user_profile(
            self, user: User, full_name: str = None, request: Request = None
    ) -> User:
        """Update user profile"""
        if full_name:
            old_name = user.full_name
            user.full_name = full_name.strip()[:255]

            self.db.commit()
            print(f"✅ Profile updated for user: {user.email}")

            if request:
                membership = self.db.query(Membership).filter(
                    Membership.user_id == user.id
                ).first()

                audit_service = AuditService(self.db)
                audit_service.log_event(
                    actor_user_id=user.id,
                    organization_id=membership.organization_id if membership else None,
                    action="user.profile.updated",
                    target_type="user",
                    target_id=user.id,
                    metadata={
                        "email": user.email,
                        "old_full_name": old_name,
                        "new_full_name": user.full_name,
                    },
                    request=request,
                )

        return user

    def deactivate_user(
            self, user: User, request: Request = None
    ) -> User:
        """Deactivate user account"""
        if not user.is_active:
            print(f"⚠️ User already deactivated: {user.email}")
            return user

        old_status = user.is_active
        user.is_active = False
        self.db.commit()

        # Revoke all active sessions
        revoked_count = revoke_all_user_tokens(
            user_id=user.id,
            reason="account_deactivated",
            db=self.db,
        )

        print(
            f"✅ User deactivated: {user.email}, sessions revoked: {revoked_count}"
        )

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.deactivated",
                target_type="user",
                target_id=user.id,
                metadata={
                    "email": user.email,
                    "old_status": old_status,
                    "new_status": user.is_active,
                    "sessions_revoked": revoked_count,
                },
                request=request,
            )

        return user

    def activate_user(
            self, user: User, request: Request = None
    ) -> User:
        """Activate user account"""
        if user.is_active:
            print(f"⚠️ User already active: {user.email}")
            return user

        old_status = user.is_active
        user.is_active = True
        self.db.commit()

        print(f"✅ User activated: {user.email}")

        if request:
            membership = self.db.query(Membership).filter(
                Membership.user_id == user.id
            ).first()

            audit_service = AuditService(self.db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id if membership else None,
                action="user.activated",
                target_type="user",
                target_id=user.id,
                metadata={
                    "email": user.email,
                    "old_status": old_status,
                    "new_status": user.is_active,
                },
                request=request,
            )

        return user

    def cleanup_expired_tokens(self) -> int:
        """Cleanup expired tokens from blacklist"""
        from ..core.security import cleanup_expired_tokens

        deleted = cleanup_expired_tokens(self.db)
        print(f"✅ Cleaned up {deleted} expired tokens")
        return deleted
