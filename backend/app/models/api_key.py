from sqlalchemy import Column, String, ForeignKey, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import secrets
from ..core.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    prefix = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="api_keys")

    @staticmethod
    def generate_key() -> tuple[str, str]:
        key = f"sk_{secrets.token_urlsafe(32)}"
        prefix = key[:12]
        return key, prefix