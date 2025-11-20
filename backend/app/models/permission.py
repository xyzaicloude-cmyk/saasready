from sqlalchemy import Column, String, ForeignKey, DateTime, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..core.database import Base


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key = Column(String, nullable=False, unique=True)  # Added: e.g., "org.update"
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    resource = Column(String, nullable=False)  # e.g., "org", "user", "audit"
    action = Column(String, nullable=False)    # e.g., "update", "invite", "read"
    created_at = Column(DateTime, default=datetime.utcnow)

    role_permissions = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    role_id = Column(String, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id = Column(String, ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")

    __table_args__ = (UniqueConstraint('role_id', 'permission_id', name='unique_role_permission'),)