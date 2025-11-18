from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.dependencies import get_current_user, require_permission
from ..schemas.organization import OrganizationCreate, OrganizationResponse
from ..schemas.membership import InviteUserRequest, MembershipResponse, MembershipUpdate
from ..services.org_service import OrgService
from ..services.audit_service import AuditService
from ..models.user import User
from ..models.membership import Membership
from ..models.role import Role

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


@router.get("/{org_id}/members", response_model=List[MembershipResponse])
def list_organization_members(
        org_id: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    org_service = OrgService(db)
    members = org_service.get_organization_members(org_id)
    return members


@router.post("/{org_id}/invite", response_model=MembershipResponse)
def invite_user_to_organization(
        org_id: str,
        data: InviteUserRequest,
        request: Request,
        membership: Membership = Depends(require_permission("user.invite")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    org_service = OrgService(db)
    new_membership = org_service.invite_user(org_id, data)

    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org_id,
        action="user.invited",
        target_type="membership",
        target_id=new_membership.id,
        metadata={"email": data.email, "role_id": data.role_id},
        request=request
    )

    # Fetch user and role for response
    user = db.query(User).filter(User.id == new_membership.user_id).first()
    role = db.query(Role).filter(Role.id == new_membership.role_id).first() if new_membership.role_id else None

    return MembershipResponse(
        id=new_membership.id,
        user_id=new_membership.user_id,
        organization_id=new_membership.organization_id,
        role_id=new_membership.role_id,
        status=new_membership.status,
        created_at=new_membership.created_at,
        user_email=user.email if user else None,
        user_full_name=user.full_name if user else None,
        role_name=role.name if role else None
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
    org_service = OrgService(db)
    updated_membership = org_service.update_member_role(membership_id, data.role_id)

    audit_service = AuditService(db)
    audit_service.log_event(
        actor_user_id=current_user.id,
        organization_id=org_id,
        action="user.role_changed",
        target_type="membership",
        target_id=membership_id,
        metadata={"new_role_id": data.role_id},
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
        user_email=user.email if user else None,
        user_full_name=user.full_name if user else None,
        role_name=role.name if role else None
    )

@router.get("/", response_model=List[OrganizationResponse])
async def get_organizations(
        current_user: User = Depends(get_current_user),  # This should use get_current_user
        db: Session = Depends(get_db)
):
    org_service = OrgService(db)
    organizations = org_service.get_user_organizations(current_user)
    return organizations