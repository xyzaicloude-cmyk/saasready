from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from ..models.user import User
from ..models.organization import Organization
from ..models.membership import Membership, MembershipStatus
from ..models.role import Role
from ..models.org_settings import OrgSettings
from ..schemas.organization import OrganizationCreate
from ..schemas.membership import InviteUserRequest
from ..core.security import get_password_hash
import re


class OrgService:
    def __init__(self, db: Session):
        self.db = db

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

        owner_role = self.db.query(Role).filter(Role.name == "Owner").first()

        membership = Membership(
            user_id=creator_user.id,
            organization_id=org.id,
            role_id=owner_role.id if owner_role else None,
            status=MembershipStatus.ACTIVE
        )
        self.db.add(membership)
        self.db.commit()

        return org

    def get_user_organizations(self, user: User) -> list[Organization]:
        print(f"🔧 Getting organizations for user: {user.email}")

        memberships = self.db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.status == MembershipStatus.active
        ).all()
        print(f"🔧 Found {len(memberships)} memberships for user {user.email}")
        if not memberships:
            print(f"⚠️  No memberships found for user {user.email}")
            return []

        org_ids = [m.organization_id for m in memberships]
        organizations = self.db.query(Organization).filter(
            Organization.id.in_(org_ids)
        ).all()
        print(f"✅ Found {len(organizations)} organizations for user {user.email}")

        return organizations

    def get_organization_members(self, org_id: str) -> list[dict]:
        memberships = self.db.query(Membership).filter(
            Membership.organization_id == org_id
        ).all()

        result = []
        for membership in memberships:
            user = self.db.query(User).filter(User.id == membership.user_id).first()
            role = None
            if membership.role_id:
                role = self.db.query(Role).filter(Role.id == membership.role_id).first()

            result.append({
                "id": membership.id,
                "user_id": membership.user_id,
                "organization_id": membership.organization_id,
                "role_id": membership.role_id,
                "status": membership.status,
                "created_at": membership.created_at,
                "user_email": user.email if user else None,
                "user_full_name": user.full_name if user else None,
                "role_name": role.name if role else None
            })

        return result

    def invite_user(self, org_id: str, data: InviteUserRequest) -> Membership:
        user = self.db.query(User).filter(User.email == data.email).first()

        if not user:
            user = User(
                email=data.email,
                hashed_password=get_password_hash("changeme123"),
                full_name=data.full_name
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

        existing_membership = self.db.query(Membership).filter(
            Membership.user_id == user.id,
            Membership.organization_id == org_id
        ).first()

        if existing_membership:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already a member of this organization"
            )

        role = self.db.query(Role).filter(Role.id == data.role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        membership = Membership(
            user_id=user.id,
            organization_id=org_id,
            role_id=data.role_id,
            status=MembershipStatus.invited
        )
        self.db.add(membership)
        self.db.commit()
        self.db.refresh(membership)

        return membership

    def update_member_role(self, membership_id: str, new_role_id: str) -> Membership:
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

        membership.role_id = new_role_id
        self.db.commit()
        self.db.refresh(membership)

        return membership