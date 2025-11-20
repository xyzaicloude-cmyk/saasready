from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class OrganizationBase(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    slug: str


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

    class Config:
        from_attributes = True

class OrganizationResponse(OrganizationBase):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True