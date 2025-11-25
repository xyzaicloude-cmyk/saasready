from fastapi import APIRouter, Depends, Request, HTTPException, Query
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.dependencies import get_current_user
from ..schemas.auth import RegisterRequest, LoginRequest, TokenResponse, PasswordResetRequest, PasswordResetConfirm, EmailVerificationRequest, ResendVerificationRequest
from ..schemas.user import UserResponse
from ..services.auth_service import AuthService
from ..services.audit_service import AuditService
from ..models.user import User
from ..models.membership import Membership
from ..models.organization import Organization
import traceback

router = APIRouter()

@router.post("/register", response_model=TokenResponse)
def register(
        data: RegisterRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    print(f"📧 Registration attempt for: {data.email}")

    auth_service = AuthService(db)
    try:
        user, token = auth_service.register_user(data, request)
        print(f"✅ User registered successfully: {user.email} (ID: {user.id})")

        membership = db.query(Membership).filter(
            Membership.user_id == user.id
        ).first()

        if membership:
            print(f"✅ Membership created: {membership.id}")
            audit_service = AuditService(db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id,
                action="user.registered",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request
            )

        return TokenResponse(access_token=token)

    except HTTPException as he:
        print(f"❌ HTTP Exception during registration: {he.detail}")
        raise he
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Unexpected error during registration:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")

        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/login", response_model=TokenResponse)
def login(
        data: LoginRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    print(f"📧 Login attempt for: {data.email}")

    auth_service = AuthService(db)
    try:
        user, token = auth_service.login_user(data, request)
        print(f"✅ User logged in successfully: {user.email}")

        membership = db.query(Membership).filter(
            Membership.user_id == user.id
        ).first()

        if membership:
            audit_service = AuditService(db)
            audit_service.log_event(
                actor_user_id=user.id,
                organization_id=membership.organization_id,
                action="user.logged_in",
                target_type="user",
                target_id=user.id,
                metadata={"email": user.email},
                request=request
            )

        return TokenResponse(access_token=token)
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Login error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        raise

@router.get("/me", response_model=UserResponse)
def get_current_user_info(
        current_user: User = Depends(get_current_user)
):
    return current_user

@router.post("/password-reset/request")
def request_password_reset(
        data: PasswordResetRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    """Request a password reset email"""
    print(f"📧 Password reset request for: {data.email}")

    auth_service = AuthService(db)
    try:
        success = auth_service.request_password_reset(data.email, request)
        if success:
            return {"message": "If the email exists, a password reset link has been sent"}
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Password reset request error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        return {"message": "If the email exists, a password reset link has been sent"}

@router.post("/password-reset/confirm")
def confirm_password_reset(
        data: PasswordResetConfirm,
        request: Request,
        db: Session = Depends(get_db)
):
    """Confirm password reset with token"""
    print(f"📧 Password reset confirmation attempt")

    auth_service = AuthService(db)
    try:
        user = auth_service.reset_password(data.token, data.new_password, request)
        return {"message": "Password has been reset successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Password reset confirmation error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        raise HTTPException(
            status_code=500,
            detail="Password reset failed"
        )

@router.post("/verify-email")
def verify_email(
        data: EmailVerificationRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    """Verify user email with token"""
    print(f"📧 Email verification attempt")

    auth_service = AuthService(db)
    try:
        user = auth_service.verify_email(data.token, request)
        return {"message": "Email verified successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Email verification error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        raise HTTPException(
            status_code=500,
            detail="Email verification failed"
        )

@router.post("/resend-verification")
def resend_verification_email(
        data: ResendVerificationRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    """Resend email verification"""
    print(f"📧 Resend verification email for: {data.email}")

    auth_service = AuthService(db)
    try:
        success = auth_service.resend_verification_email(data.email, request)
        if success:
            return {"message": "If the email exists and is not verified, a verification email has been sent"}
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Resend verification error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        return {"message": "If the email exists and is not verified, a verification email has been sent"}

@router.post("/accept-invitation")
def accept_invitation(
        data: EmailVerificationRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    """Accept organization invitation - PRE-LOGIN ENTERPRISE FLOW"""
    print(f"📧 Pre-login invitation acceptance attempt")

    auth_service = AuthService(db)
    try:
        # This accepts the invitation WITHOUT requiring login
        invitation_result = auth_service.accept_invitation_pre_login(data.token, request)
        return invitation_result
    except HTTPException as he:
        raise he
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Pre-login invitation acceptance error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        raise HTTPException(
            status_code=500,
            detail="Failed to accept invitation"
        )

@router.post("/complete-invitation")
def complete_invitation(
        data: EmailVerificationRequest,
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Complete invitation after user is logged in"""
    print(f"📧 Completing invitation for user: {current_user.email}")

    auth_service = AuthService(db)
    try:
        membership = auth_service.complete_invitation_after_registration(current_user, data.token, request)

        # Get organization details for response
        org = db.query(Organization).filter(Organization.id == membership.organization_id).first()

        return {
            "message": "Invitation completed successfully",
            "organization": {
                "id": org.id,
                "name": org.name,
                "slug": org.slug
            }
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Invitation completion error:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        raise HTTPException(
            status_code=500,
            detail="Failed to complete invitation"
        )

@router.post("/register-with-invite", response_model=TokenResponse)
def register_with_invite(
        data: RegisterRequest,
        request: Request,
        invite_token: str = Query(..., description="Invitation token"),  # CRITICAL FIX: Make it required query param
        db: Session = Depends(get_db)
):
    """Register with invitation token - ENTERPRISE FLOW"""
    print(f"📧 ENTERPRISE: Registration with invitation attempt for: {data.email}")
    print(f"🎫 Invitation token received: {invite_token[:20]}..." if invite_token else "❌ NO TOKEN RECEIVED")

    auth_service = AuthService(db)
    try:
        # CRITICAL: Pass the invitation token to register_user
        user, token = auth_service.register_user(data, request, invitation_token=invite_token)
        print(f"✅ User registered with invitation successfully: {user.email} (ID: {user.id})")

        return TokenResponse(access_token=token)

    except HTTPException as he:
        print(f"❌ HTTP Exception during invitation registration: {he.detail}")
        raise he
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"❌ Unexpected error during invitation registration:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")

        raise HTTPException(
            status_code=500,
            detail=f"Registration with invitation failed: {str(e)}"
        )