from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


class AuditLogResponse(BaseModel):
    id: str
    actor_user_id: Optional[str]
    organization_id: str
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    audit_metadata: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    actor_email: Optional[str] = None

    class Config:
        from_attributes = True