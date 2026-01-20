from pydantic import BaseModel, EmailStr
from uuid import UUID
from typing import Optional

class InviteUserRequest(BaseModel):
    email: EmailStr
    role_id: str  # ← Change from UUID to str
    full_name: Optional[str] = None

    class Config:
        from_attributes = True

class InvitationResponse(BaseModel):
    id: UUID
    email: str
    organization_id: UUID
    role_id: UUID
    status: str
    invited_by: UUID

    class Config:
        from_attributes = True