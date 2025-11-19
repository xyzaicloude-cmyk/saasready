from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.dependencies import get_current_user, require_permission
from ..schemas.feature_flag import (
    FeatureFlagCreate,
    FeatureFlagResponse,
    OrgFeatureFlagOverride,
    OrgFeatureFlagResponse
)
from ..services.feature_flag_service import FeatureFlagService
from ..services.audit_service import AuditService
from ..services.rbac_service import RBACService
from ..models.user import User
from ..models.membership import Membership

router = APIRouter()


@router.post("", response_model=FeatureFlagResponse)
def create_global_feature_flag(
        data: FeatureFlagCreate,
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Create a new global feature flag.
    Requires system admin privileges.
    """
    rbac_service = RBACService(db)

    membership = db.query(Membership).filter(
        Membership.user_id == current_user.id
    ).first()

    if not membership or not rbac_service.has_permission(membership, "feature_flags.manage_global"):
        if not membership or membership.role.name != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to create global feature flags"
            )

    ff_service = FeatureFlagService(db)
    flag = ff_service.create_global_flag(data)

    audit_service = AuditService(db)
    if membership:
        audit_service.log_event(
            actor_user_id=current_user.id,
            organization_id=membership.organization_id,
            action="feature_flag.created",
            target_type="feature_flag",
            target_id=flag.id,
            metadata={"key": flag.key, "name": flag.name, "default_enabled": flag.default_enabled},
            request=request
        )

    return flag


@router.get("", response_model=List[FeatureFlagResponse])
def list_global_feature_flags(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    List all global feature flags.
    Requires system admin privileges.
    """
    rbac_service = RBACService(db)

    membership = db.query(Membership).filter(
        Membership.user_id == current_user.id
    ).first()

    if not membership or not rbac_service.has_permission(membership, "feature_flags.manage_global"):
        if not membership or membership.role.name != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to view global feature flags"
            )

    ff_service = FeatureFlagService(db)
    flags = ff_service.get_all_global_flags()
    return flags