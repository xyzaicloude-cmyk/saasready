from sqlalchemy import Column, String, ForeignKey, Boolean, JSON, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..core.database import Base


class OrgSettings(Base):
    __tablename__ = "org_settings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True)
    allow_signups = Column(Boolean, default=True)
    require_email_verification = Column(Boolean, default=False)
    sso_enabled = Column(Boolean, default=False)
    custom_settings = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="settings")