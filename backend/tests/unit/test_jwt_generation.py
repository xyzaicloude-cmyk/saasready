"""
Unit Tests for JWT Token Generation
"""

def test_jwt_contains_required_claims():
    """Test JWT includes all required claims"""
    from app.core.security import create_access_token
    from jose import jwt
    from app.core.config import settings

    token = create_access_token(data={"sub": "user123"})

    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    assert "sub" in payload  # Subject (user ID)
    assert "exp" in payload  # Expiration
    assert "iat" in payload  # Issued at
    assert "jti" in payload  # JWT ID

def test_jwt_expires_after_configured_time():
    """Test JWT expiration matches configuration"""
    from app.core.security import create_access_token
    from jose import jwt
    from app.core.config import settings
    from datetime import datetime, timezone

    token = create_access_token(data={"sub": "user123"})
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    iat_time = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)

    duration_minutes = (exp_time - iat_time).total_seconds() / 60

    assert abs(duration_minutes - settings.ACCESS_TOKEN_EXPIRE_MINUTES) < 1

