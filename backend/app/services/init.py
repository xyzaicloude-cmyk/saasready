# backend/app/services/__init__.py
"""
Services package with all enterprise services
CRITICAL: Include brute force protection and email service
"""
from .auth_service import AuthService
from .org_service import OrgService
from .rbac_service import RBACService
from .audit_service import AuditService
from .feature_flag_service import FeatureFlagService
from .email_service import email_service  # Use sync version (async available but not needed for current impl)

__all__ = [
    "AuthService",
    "OrgService",
    "RBACService",
    "AuditService",
    "FeatureFlagService",
    "email_service",
]