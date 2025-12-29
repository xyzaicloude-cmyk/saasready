# backend/app/core/security.py
"""
UNIFIED Production Security Module - FIXED VERSION
Replaces: security.py, security_enhanced.py, security_production.py
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import secrets
import hashlib

from .config import settings

# ============================================================================
# PASSWORD HASHING - Use Argon2 (no 72-byte bcrypt limit)
# ============================================================================

pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__time_cost=2,
    argon2__memory_cost=65536,  # 64MB
    argon2__parallelism=4
)

def validate_password_length(password: str) -> bool:
    """
    Validate password length only (8-128 characters)

    Args:
        password: The password to validate

    Returns:
        bool: True if length is valid, False otherwise
    """
    return 8 <= len(password) <= 128

def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Enterprise password validation

    Returns:
        (is_valid, error_message)
    """
    # Length check (8-128 for Argon2)
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if len(password) > 128:
        return False, "Password cannot exceed 128 characters"

    # Complexity requirements
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase, and numbers"

    return True, None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password using Argon2"""
    return pwd_context.hash(password)


# ============================================================================
# JWT TOKEN MANAGEMENT - With Revocation Support
# ============================================================================

def create_access_token(
        data: dict,
        expires_delta: Optional[timedelta] = None,
        token_type: str = "access"
) -> str:
    """
    🔧 FIXED: Create JWT access token (returns ONLY token string)

    This is the PRIMARY function used by auth_service.py for simple token creation.
    Use this when you don't need JTI tracking.

    Args:
        data: Token payload data
        expires_delta: Optional expiration time delta
        token_type: Token type (access/refresh)

    Returns:
        str: JWT token string
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = secrets.token_urlsafe(32)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": jti,
        "type": token_type
    })

    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token  # 🔧 FIXED: Return only token string


def create_access_token_with_jti(
        data: dict,
        expires_delta: Optional[timedelta] = None,
        token_type: str = "access"
) -> Tuple[str, str, datetime]:
    """
    🔧 FIXED: Create JWT with JTI tracking (for session management)

    This is used by the ENTERPRISE auth routes that need session tracking.
    Use this when you need to track JTI for revocation.

    Returns:
        tuple: (token, jti, expires_at)
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = secrets.token_urlsafe(32)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": jti,
        "type": token_type
    })

    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, jti, expire  # 🔧 FIXED: Return tuple (token, jti, expires_at)


def create_refresh_token(data: dict) -> str:
    """
    🔧 FIXED: Create refresh token with longer expiry (returns only token string)
    """
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return create_access_token(data, expires_delta, "refresh")


def create_refresh_token_with_jti(data: dict) -> Tuple[str, str, datetime]:
    """
    🔧 FIXED: Create refresh token with JTI tracking
    Returns: (refresh_token, jti, expires_at)
    """
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return create_access_token_with_jti(data, expires_delta, "refresh")


def decode_access_token(token: str, db: Optional[Session] = None) -> Optional[dict]:
    """
    Decode and validate JWT with optional revocation check

    Args:
        token: JWT token string
        db: Database session (required for revocation check)

    Returns:
        Payload dict or None if invalid/revoked
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Check token blacklist if DB session provided
        if db:
            jti = payload.get("jti")
            if jti and is_token_revoked(jti, db):
                return None

        return payload

    except JWTError:
        return None


# ============================================================================
# TOKEN REVOCATION - JWT Blacklist
# ============================================================================

def is_token_revoked(jti: str, db: Session) -> bool:
    """Check if token JTI is blacklisted"""
    from ..models.token_blacklist import TokenBlacklist

    blacklisted = db.query(TokenBlacklist).filter(
        TokenBlacklist.jti == jti,
        TokenBlacklist.expires_at > datetime.now(timezone.utc)
    ).first()

    return blacklisted is not None


def revoke_token(
        jti: str,
        user_id: str,
        expires_at: datetime,
        reason: str,
        db: Session
) -> None:
    """Add token to blacklist"""
    from ..models.token_blacklist import TokenBlacklist

    existing = db.query(TokenBlacklist).filter(
        TokenBlacklist.jti == jti
    ).first()

    if existing:
        return

    blacklist_entry = TokenBlacklist(
        jti=jti,
        user_id=user_id,
        expires_at=expires_at,
        reason=reason
    )
    db.add(blacklist_entry)
    db.commit()


def revoke_all_user_tokens(user_id: str, reason: str, db: Session) -> int:
    """
    🔧 FIXED: Revoke all active sessions for a user

    Returns:
        int: Number of sessions revoked
    """
    from ..models.token_blacklist import UserSession,TokenBlacklist

    # Count active sessions before revoking
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.now(timezone.utc)
    ).all()

    revoked_count = len(active_sessions)

    # 🔧 CRITICAL FIX: Blacklist each token's JTI
    for session in active_sessions:
        # Add JTI to blacklist table (immediate token invalidation)
        blacklist_entry = TokenBlacklist(
            jti=session.jti,
            user_id=user_id,
            expires_at=session.expires_at,
            reason=reason
        )
        db.add(blacklist_entry)

        # Mark session as inactive (audit trail)
        session.is_active = False

    db.commit()

    return revoked_count



def cleanup_expired_tokens(db: Session) -> int:
    """
    Remove expired tokens from blacklist
    Run as cron job (see background_tasks.py)

    Returns:
        Number of tokens deleted
    """
    from ..models.token_blacklist import TokenBlacklist

    deleted = db.query(TokenBlacklist).filter(
        TokenBlacklist.expires_at < datetime.now(timezone.utc)
    ).delete()

    db.commit()
    return deleted


# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

def generate_api_key(prefix: str = "sk") -> Tuple[str, str]:
    """
    Generate API key with prefix

    Returns:
        (full_key, key_hash)
    """
    key_part = secrets.token_urlsafe(32)
    full_key = f"{prefix}_{key_part}"
    key_hash = hash_api_key(full_key)
    return full_key, key_hash


def hash_api_key(api_key: str) -> str:
    """Hash API key for secure storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Verify API key against stored hash"""
    return hash_api_key(api_key) == stored_hash


# ============================================================================
# SECURE TOKEN GENERATION
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)