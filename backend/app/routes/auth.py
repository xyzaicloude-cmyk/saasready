from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.dependencies import get_current_user
from ..schemas.auth import RegisterRequest, LoginRequest, TokenResponse
from ..schemas.user import UserResponse
from ..services.auth_service import AuthService
from ..services.audit_service import AuditService
from ..models.user import User
from ..models.membership import Membership
import traceback

router = APIRouter()

@router.post("/register", response_model=TokenResponse)
def register(
        data: RegisterRequest,
        request: Request,
        db: Session = Depends(get_db)
):
    print(f"🔧 Registration attempt for: {data.email}")

    auth_service = AuthService(db)
    try:
        user, token = auth_service.register_user(data)
        print(f"✅ User registered successfully: {user.email} (ID: {user.id})")

        # Log the registration event
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
        # Re-raise HTTP exceptions as they are
        print(f"❌ HTTP Exception during registration: {he.detail}")
        raise he
    except Exception as e:
        # Log the full error with traceback
        error_traceback = traceback.format_exc()
        print(f"❌ Unexpected error during registration:")
        print(f"Error: {str(e)}")
        print(f"Traceback: {error_traceback}")

        # Return a proper error response
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
    print(f"🔧 Login attempt for: {data.email}")

    auth_service = AuthService(db)
    try:
        user, token = auth_service.login_user(data)
        print(f"✅ User logged in successfully: {user.email}")

        # Log the login event
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