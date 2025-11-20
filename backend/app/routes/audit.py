from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.dependencies import get_current_user, require_permission
from ..schemas.audit_log import AuditLogResponse
from ..services.audit_service import AuditService
from ..models.user import User
from ..models.membership import Membership

router = APIRouter()


@router.get("/orgs/{org_id}/logs", response_model=List[AuditLogResponse])
def get_organization_audit_logs(
        org_id: str,
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        membership: Membership = Depends(require_permission("audit.read")),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Get audit logs for an organization. Requires audit.read permission."""

    audit_service = AuditService(db)
    logs = audit_service.get_organization_logs(org_id, limit, offset)

    return logs