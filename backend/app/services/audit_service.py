from sqlalchemy.orm import Session
from ..models.audit_log import AuditLog
from ..models.organization import Organization
import uuid
from datetime import datetime,timezone
from fastapi import Request

class AuditService:
    def __init__(self, db: Session):
        self.db = db
        self._system_org = None

    def _get_system_organization(self):
        """Get or create a system organization for global events"""
        if not self._system_org:
            self._system_org = self.db.query(Organization).filter(
                Organization.slug == "system"
            ).first()

            if not self._system_org:
                self._system_org = Organization(
                    name="System",
                    slug="system",
                    description="System organization for global events"
                )
                self.db.add(self._system_org)
                self.db.commit()
                self.db.refresh(self._system_org)

        return self._system_org

    def log_event(self, actor_user_id: str, organization_id: str, action: str,
                  target_type: str, target_id: str, metadata: dict, request: Request):

        # If no organization_id provided, use system organization
        if organization_id is None:
            system_org = self._get_system_organization()
            organization_id = system_org.id

        audit_log = AuditLog(
            id=str(uuid.uuid4()),
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            audit_metadata=metadata,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            created_at=datetime.now(timezone.utc)
        )

        self.db.add(audit_log)
        self.db.commit()

    def get_organization_logs(self, organization_id: str, limit: int = 100, offset: int = 0):
        return self.db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id
        ).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset).all()