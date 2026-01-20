from sqlalchemy import Column, String, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum
from ..core.database import Base


class MembershipStatus(str, enum.Enum):
    active = "active"
    invited = "invited"
    suspended = "suspended"


class Membership(Base):
    __tablename__ = "memberships"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)  # Nullable for pending invitations
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(String, ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    status = Column(SQLEnum(MembershipStatus), default=MembershipStatus.active)
    invitation_token = Column(String, unique=True, nullable=True)
    invitation_expires_at = Column(DateTime, nullable=True)
    invited_email = Column(String, nullable=True)  # Store invited email for users without accounts
    invited_full_name = Column(String, nullable=True)  # ENTERPRISE: Store full name for pending invitations
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="memberships")
    role = relationship("Role")