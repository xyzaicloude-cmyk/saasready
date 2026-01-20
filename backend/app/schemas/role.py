from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None


class RoleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    is_system: bool
    created_at: datetime

    class Config:
        from_attributes = True