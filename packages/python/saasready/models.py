"""
Data models - typed response objects
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass


@dataclass
class User:
    """User model"""
    id: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    created_at: str

    # Optional security fields
    has_2fa: Optional[bool] = None
    email_verified: Optional[bool] = None
    account_active: Optional[bool] = None
    last_login: Optional[str] = None


@dataclass
class Organization:
    """Organization model"""
    id: str
    name: str
    slug: str
    description: Optional[str]
    is_active: bool
    created_at: str
    updated_at: str


@dataclass
class Role:
    """Role model"""
    id: str
    name: str
    description: Optional[str]
    is_system: bool
    created_at: str


@dataclass
class Membership:
    """Membership model"""
    id: str
    user_id: Optional[str]
    organization_id: str
    role_id: Optional[str]
    status: str  # active, invited, suspended
    created_at: str
    user_email: Optional[str] = None
    user_full_name: Optional[str] = None
    role_name: Optional[str] = None
    invited_email: Optional[str] = None
    invitation_expires_at: Optional[str] = None


@dataclass
class AuditLog:
    """Audit log model"""
    id: str
    actor_user_id: Optional[str]
    organization_id: str
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    audit_metadata: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: str
    actor_email: Optional[str] = None


@dataclass
class FeatureFlag:
    """Feature flag model"""
    key: str
    name: str
    description: Optional[str]
    default_enabled: bool
    enabled: bool
    overridden: bool
    rollout_percent: Optional[int] = None


@dataclass
class TokenResponse:
    """Token response model"""
    access_token: str
    token_type: str = "bearer"
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    requires_2fa: bool = False
    message: Optional[str] = None
    user_id: Optional[str] = None
    device_fingerprint: Optional[str] = None