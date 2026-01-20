# backend/app/core/dependencies.py
"""
FastAPI dependencies with JWT revocation support
CRITICAL: Updated to use unified security module with token revocation
"""
from typing import Optional, Callable
from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from .database import get_db
from .security import decode_access_token  # Using unified security module
from ..models.user import User
from ..models.membership import Membership
from ..services.rbac_service import RBACService
from ..services.feature_flag_service import feature_flag_service


def get_current_user(
        authorization: Optional[str] = Header(None),
        db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user with JWT revocation check
    CRITICAL: Now includes database session for token revocation validation
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.replace("Bearer ", "")

    # CRITICAL: Pass db session for revocation check
    payload = decode_access_token(token, db)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_permission(permission_name: str):
    """
    Require specific permission for endpoint access
    """
    def permission_checker(
            org_id: str,
            current_user: User = Depends(get_current_user),
            db: Session = Depends(get_db)
    ):
        rbac_service = RBACService(db)

        membership = db.query(Membership).filter(
            Membership.user_id == current_user.id,
            Membership.organization_id == org_id
        ).first()

        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this organization"
            )

        if not rbac_service.has_permission(membership, permission_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission_name}"
            )

        return membership

    return permission_checker


def feature_flag_enabled(flag_key: str) -> Callable:
    """
    Dependency to check if a feature flag is enabled for current org.
    Returns the boolean value without blocking the request.
    """
    def _check(
            org_id: str,
            db: Session = Depends(get_db)
    ) -> bool:
        return feature_flag_service.is_feature_enabled(org_id, flag_key, db)

    return _check


def require_feature_flag(flag_key: str) -> Callable:
    """
    Dependency that blocks request if feature flag is not enabled for current org.
    Raises 403 if feature is disabled.
    """
    def _require(
            org_id: str,
            db: Session = Depends(get_db)
    ) -> bool:
        enabled = feature_flag_service.is_feature_enabled(org_id, flag_key, db)
        if not enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Feature '{flag_key}' is not enabled for this organization"
            )
        return True

    return _require