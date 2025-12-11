from fastapi import APIRouter, Depends, Request, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.dependencies import get_current_user, require_permission
from ..schemas.organization import OrganizationCreate, OrganizationResponse, OrganizationUpdate
from ..schemas.membership import InviteUserRequest, MembershipResponse, MembershipUpdate
from ..schemas.role import RoleResponse
from ..schemas.feature_flag import OrgFeatureFlagOverride, OrgFeatureFlagResponse
from ..services.org_service import OrgService
from ..services.audit_service import AuditService
from ..services.feature_flag_service import FeatureFlagService
from ..models.user import User
from ..models.membership import Membership
from ..models.role import Role
from ..models.organization import Organization

router = APIRouter()


@router.post("", response_model=OrganizationResponse)
def create_organization(
        data: OrganizationCreate,
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    org_service = OrgService(db)
    org = org_service.create_organization(data, current_user)

    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org.id,
        action="organization.created",
        target_type="organization",
        target_id=org.id,
        metadata={"name": org.name, "slug": org.slug},
        request=request
    )

    return org


@router.get("", response_model=List[OrganizationResponse])
def list_organizations(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    org_service = OrgService(db)
    organizations = org_service.get_user_organizations(current_user)
    return organizations


@router.patch("/{org_id}", response_model=OrganizationResponse)
def update_organization(
        org_id: str,
        data: OrganizationUpdate,
        request: Request,
        membership: Membership = Depends(require_permission("org.update")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Update organization settings. Requires org.update permission."""

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Track what changed for audit log
    changes = {}

    if data.name is not None:
        changes["name"] = {"old": org.name, "new": data.name}
        org.name = data.name

    if data.description is not None:
        changes["description"] = {"old": org.description, "new": data.description}
        org.description = data.description

    db.commit()
    db.refresh(org)

    # Log the update
    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org_id,
        action="org.updated",
        target_type="organization",
        target_id=org_id,
        metadata={"changes": changes},
        request=request
    )

    return org


@router.get("/{org_id}/members", response_model=List[MembershipResponse])
def list_organization_members(
        org_id: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Enterprise: Get organization members with proper invited user handling"""
    org_service = OrgService(db)
    members = org_service.get_organization_members(org_id)

    # Convert to proper response - remove is_pending field
    result = []
    for member_data in members:
        result.append(MembershipResponse(
            id=member_data["id"],
            user_id=member_data["user_id"],
            organization_id=member_data["organization_id"],
            role_id=member_data["role_id"],
            status=member_data["status"],
            created_at=member_data["created_at"],
            user_email=member_data["user_email"],
            user_full_name=member_data["user_full_name"],
            role_name=member_data["role_name"],
            invited_email=member_data["invited_email"],
            invitation_expires_at=member_data["invitation_expires_at"]
        ))

    return result


@router.get("/{org_id}/roles", response_model=List[RoleResponse])
def list_available_roles_for_org(
        org_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """Returns a list of assignable roles for an organization."""
    roles = db.query(Role).order_by(Role.name).all()
    return roles


@router.post("/{org_id}/invite", response_model=MembershipResponse)
def invite_user_to_organization(
        org_id: str,
        data: InviteUserRequest,
        request: Request,
        background_tasks: BackgroundTasks,
        membership: Membership = Depends(require_permission("user.invite")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Enterprise: Invite user to organization with enhanced validation"""
    org_service = OrgService(db)
    org_service.set_background_tasks(background_tasks)

    new_membership = org_service.invite_user(
        org_id,
        data,
        inviter=current_user,
        background_tasks=background_tasks
    )

    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org_id,
        action="user.invite.sent",
        target_type="membership",
        target_id=new_membership.id,
        metadata={
            "invited_email": data.email,
            "role_id": str(data.role_id),
            "inviter_id": str(current_user.id),
            "invitation_expires_at": new_membership.invitation_expires_at.isoformat() if new_membership.invitation_expires_at else None
        },
        request=request
    )

    # ENTERPRISE FIX: Proper response for both existing and new users
    user = db.query(User).filter(User.id == new_membership.user_id).first()
    role = db.query(Role).filter(Role.id == new_membership.role_id).first() if new_membership.role_id else None

    return MembershipResponse(
        id=new_membership.id,
        user_id=new_membership.user_id,
        organization_id=new_membership.organization_id,
        role_id=new_membership.role_id,
        status=new_membership.status,
        created_at=new_membership.created_at,
        user_email=user.email if user else new_membership.invited_email,
        user_full_name=user.full_name if user else None,
        role_name=role.name if role else None,
        invited_email=new_membership.invited_email,
        invitation_expires_at=new_membership.invitation_expires_at
    )


@router.patch("/{org_id}/members/{membership_id}/role", response_model=MembershipResponse)
def update_member_role(
        org_id: str,
        membership_id: str,
        data: MembershipUpdate,
        request: Request,
        membership: Membership = Depends(require_permission("user.manage")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Change a member's role. Requires user.manage permission."""

    # Get the target membership
    target_membership = db.query(Membership).filter(
        Membership.id == membership_id,
        Membership.organization_id == org_id
    ).first()

    if not target_membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Membership not found"
        )

    old_role_id = target_membership.role_id

    org_service = OrgService(db)
    updated_membership = org_service.update_member_role(membership_id, data.role_id, updater=current_user, org_id=org_id)

    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org_id,
        action="user.role.updated",
        target_type="membership",
        target_id=membership_id,
        metadata={
            "target_user_id": str(updated_membership.user_id),
            "old_role_id": str(old_role_id) if old_role_id else None,
            "new_role_id": str(data.role_id)
        },
        request=request
    )

    # Fetch user and role for response
    user = db.query(User).filter(User.id == updated_membership.user_id).first()
    role = db.query(Role).filter(Role.id == updated_membership.role_id).first() if updated_membership.role_id else None

    return MembershipResponse(
        id=updated_membership.id,
        user_id=updated_membership.user_id,
        organization_id=updated_membership.organization_id,
        role_id=updated_membership.role_id,
        status=updated_membership.status,
        created_at=updated_membership.created_at,
        user_email=user.email if user else updated_membership.invited_email,
        user_full_name=user.full_name if user else None,
        role_name=role.name if role else None,
        invited_email=updated_membership.invited_email
    )


@router.get("/", response_model=List[OrganizationResponse])
async def get_organizations(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    org_service = OrgService(db)
    organizations = org_service.get_user_organizations(current_user)
    return organizations


@router.get("/{id}/feature-flags", response_model=List[OrgFeatureFlagResponse])
def get_org_feature_flags(
        id: str,
        membership: Membership = Depends(require_permission("org.update")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Get all feature flags with their effective state for an organization."""
    ff_service = FeatureFlagService(db)
    flags = ff_service.get_org_feature_flags(id)
    return flags


@router.put("/{id}/feature-flags/{flag_key}", response_model=OrgFeatureFlagResponse)
def set_org_feature_flag(
        id: str,
        flag_key: str,
        data: OrgFeatureFlagOverride,
        request: Request,
        membership: Membership = Depends(require_permission("org.update")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Set or update a feature flag override for an organization."""
    ff_service = FeatureFlagService(db)
    result = ff_service.set_org_feature_flag(id, flag_key, data)

    audit_service = AuditService(db)
    action = "feature_flag.enabled" if data.enabled else "feature_flag.disabled"
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=id,
        action=action,
        target_type="feature_flag",
        target_id=flag_key,
        metadata={
            "key": flag_key,
            "enabled": data.enabled,
            "rollout_percent": data.rollout_percent
        },
        request=request
    )

    return result


@router.delete("/{id}/feature-flags/{flag_key}", response_model=OrgFeatureFlagResponse)
def delete_org_feature_flag(
        id: str,
        flag_key: str,
        request: Request,
        membership: Membership = Depends(require_permission("org.update")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Delete a feature flag override for an organization (revert to default)."""
    ff_service = FeatureFlagService(db)
    result = ff_service.delete_org_feature_flag(id, flag_key)

    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=id,
        action="feature_flag.reset_to_default",
        target_type="feature_flag",
        target_id=flag_key,
        metadata={
            "key": flag_key,
            "reverted_to_default": result.default_enabled
        },
        request=request
    )

    return result


@router.get("/{id}/beta-dashboard")
def get_beta_dashboard(
        id: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
        membership: Membership = Depends(require_permission("org.read"))
):
    """Example endpoint gated by the 'beta-new-ui' feature flag."""
    from ..services.feature_flag_service import FeatureFlagService

    ff_service = FeatureFlagService(db)
    if not ff_service.is_feature_enabled(id, "beta-new-ui", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Feature 'beta-new-ui' is not enabled for this organization"
        )

    return {
        "message": "Beta dashboard content",
        "features": [
            "New analytics view",
            "Improved navigation",
            "Dark mode support",
            "Advanced filters"
        ],
        "org_id": str(id),
        "enabled_features": ["beta-new-ui"]
    }