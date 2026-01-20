from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from ..core.database import Base


class FeatureFlag(Base):
    __tablename__ = "feature_flags"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key = Column(Text, unique=True, nullable=False, index=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    default_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    org_overrides = relationship(
        "OrgFeatureFlag",
        back_populates="feature_flag",
        cascade="all, delete-orphan"
    )


class OrgFeatureFlag(Base):
    __tablename__ = "org_feature_flags"
    __table_args__ = (
        UniqueConstraint('org_id', 'feature_flag_id', name='uq_org_feature_flag'),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    feature_flag_id = Column(String, ForeignKey("feature_flags.id", ondelete="CASCADE"), nullable=False)
    enabled = Column(Boolean, nullable=False)
    rollout_percent = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="feature_flag_overrides")
    feature_flag = relationship("FeatureFlag", back_populates="org_overrides")