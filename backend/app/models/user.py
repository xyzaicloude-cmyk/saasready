from sqlalchemy import Column, String, Boolean, DateTime,JSON, Integer
from sqlalchemy.orm import relationship
from datetime import datetime,timezone
import uuid
from ..core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    is_email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String, unique=True, nullable=True)
    email_verification_sent_at = Column(DateTime, nullable=True)
    reset_token = Column(String, unique=True, nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    memberships = relationship("Membership", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="actor", foreign_keys="AuditLog.actor_user_id")


    # 🆕 ENTERPRISE: 2FA fields
    totp_secret = Column(String, nullable=True)  # Active TOTP secret
    totp_secret_pending = Column(String, nullable=True)  # Pending verification
    totp_enabled = Column(Boolean, default=False)
    totp_enabled_at = Column(DateTime, nullable=True)
    backup_codes = Column(JSON, nullable=True)  # Array of backup codes

    # 🆕 ENTERPRISE: Security tracking
    password_changed_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String, nullable=True)
    last_device_fingerprint = Column(String, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

