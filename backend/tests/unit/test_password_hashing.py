"""
Unit Tests for Password Hashing
"""

def test_password_hash_uses_argon2():
    """Test passwords are hashed with Argon2"""
    from app.core.security import get_password_hash

    hashed = get_password_hash("TestPassword123!")

    assert hashed.startswith("$argon2")
    assert len(hashed) > 50

def test_same_password_generates_different_hashes():
    """Test password hashing includes random salt"""
    from app.core.security import get_password_hash

    hash1 = get_password_hash("SamePassword123!")
    hash2 = get_password_hash("SamePassword123!")

    assert hash1 != hash2  # Different due to random salt

def test_verify_password_works_correctly():
    """Test password verification"""
    from app.core.security import get_password_hash, verify_password

    password = "CorrectPassword123!"
    hashed = get_password_hash(password)

    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False

