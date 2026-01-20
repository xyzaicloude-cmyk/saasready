from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from ..models.membership import MembershipStatus


class MembershipBase(BaseModel):
    pass


class InviteUserRequest(BaseModel):
    email: EmailStr
    role_id: str
    full_name: Optional[str] = None


class MembershipUpdate(BaseModel):
    role_id: Optional[str] = None
    status: Optional[MembershipStatus] = None


class MembershipResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    organization_id: str
    role_id: Optional[str]
    status: MembershipStatus
    created_at: datetime
    user_email: Optional[str] = None
    user_full_name: Optional[str] = None
    role_name: Optional[str] = None
    invited_email: Optional[str] = None
    invitation_expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True