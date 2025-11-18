from sqlalchemy import Column, String, ForeignKey, Boolean, Enum as SQLEnum, JSON, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum
from ..core.database import Base


class SSOProvider(str, enum.Enum):
    saml = "saml"
    oidc = "oidc"
    google = "google"
    azure = "azure"


class SSOConnection(Base):
    __tablename__ = "sso_connections"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    provider = Column(SQLEnum(SSOProvider), nullable=False)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    config = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="sso_connections")