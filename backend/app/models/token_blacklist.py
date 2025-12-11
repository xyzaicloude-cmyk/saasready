# backend/app/models/token_blacklist.py
"""
Token blacklist for JWT revocation
"""
from sqlalchemy import Column, String, DateTime, Index,Boolean
from datetime import datetime
import uuid
from ..core.database import Base


class TokenBlacklist(Base):
    """Track revoked JWT tokens"""
    __tablename__ = "token_blacklist"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    jti = Column(String, unique=True, nullable=False, index=True)  # JWT ID
    user_id = Column(String, nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)  # When token naturally expires
    reason = Column(String, nullable=True)  # logout, password_change, security_breach

    __table_args__ = (
        Index('ix_token_blacklist_expires_at', 'expires_at'),
    )


class UserSession(Base):
    """Track active user sessions"""
    __tablename__ = "user_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False, index=True)
    jti = Column(String, unique=True, nullable=False, index=True)
    device_info = Column(String, nullable=True)  # User agent
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index('ix_user_sessions_user_id_active', 'user_id', 'is_active'),
    )