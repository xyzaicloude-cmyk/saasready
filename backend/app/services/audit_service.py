from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from fastapi import Request
from ..models.audit_log import AuditLog

class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def log_event(
            self,
            actor_user_id: Optional[str],
            organization_id: str,
            action: str,
            target_type: Optional[str] = None,
            target_id: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None,  # Change from audit_metadata to metadata
            request: Optional[Request] = None
    ) -> AuditLog:
        ip_address = None
        user_agent = None

        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

        audit_log = AuditLog(
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            audit_metadata=metadata,  # Map to the correct column name
            ip_address=ip_address,
            user_agent=user_agent
        )

        self.db.add(audit_log)
        self.db.commit()
        self.db.refresh(audit_log)

        return audit_log

    def get_organization_logs(
            self,
            organization_id: str,
            limit: int = 100,
            offset: int = 0
    ) -> list[dict]:
        logs = self.db.query(AuditLog).filter(
            AuditLog.organization_id == organization_id
        ).order_by(
            AuditLog.created_at.desc()
        ).limit(limit).offset(offset).all()

        from ..models.user import User

        result = []
        for log in logs:
            actor = None
            if log.actor_user_id:
                actor = self.db.query(User).filter(User.id == log.actor_user_id).first()

            result.append({
                "id": log.id,
                "actor_user_id": log.actor_user_id,
                "organization_id": log.organization_id,
                "action": log.action,
                "target_type": log.target_type,
                "target_id": log.target_id,
                "audit_metadata": log.audit_metadata,  # Use the correct column name
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "created_at": log.created_at,
                "actor_email": actor.email if actor else None
            })

        return result