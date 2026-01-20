from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.dependencies import get_current_user, require_permission
from ..schemas.user import UserResponse
from ..schemas.membership import MembershipUpdate, MembershipResponse
from ..models.user import User
from ..models.membership import Membership
from ..models.role import Role
from ..services.audit_service import AuditService

router = APIRouter()


@router.get("/me", response_model=UserResponse)
def get_my_profile(
        current_user: User = Depends(get_current_user)
):
    return current_user


@router.delete("/orgs/{org_id}/members/{member_id}")
def remove_member_from_organization(
        org_id: str,
        member_id: str,
        request: Request,
        membership: Membership = Depends(require_permission("user.manage")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Remove a member from an organization. Requires user.manage permission."""

    # Find the membership to remove
    target_membership = db.query(Membership).filter(
        Membership.id == member_id,
        Membership.organization_id == org_id
    ).first()

    if not target_membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Membership not found"
        )

    # Prevent removing yourself if you're the last owner
    if target_membership.user_id == current_user.id:
        owner_count = db.query(Membership).join(Role).filter(
            Membership.organization_id == org_id,
            Role.name == "owner"
        ).count()

        if owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last owner from the organization"
            )

    target_user_id = target_membership.user_id

    # Delete the membership
    db.delete(target_membership)
    db.commit()

    # Log the audit event
    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org_id,
        action="user.removed",
        target_type="membership",
        target_id=member_id,
        metadata={
            "removed_user_id": str(target_user_id),
            "removed_by": str(current_user.id)
        },
        request=request
    )

    return {"message": "Member removed successfully"}