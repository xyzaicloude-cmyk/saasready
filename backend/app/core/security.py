from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from .config import settings

# Use argon2 instead of bcrypt to avoid the 72-byte limit
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],  # Try argon2 first, fallback to bcrypt
    deprecated="auto"
)

def validate_password_length(password: str) -> bool:
    """Validate password length for bcrypt compatibility"""
    if len(password.encode('utf-8')) > 72:
        return False
    return True

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    # If password is too long for bcrypt, automatically use argon2
    if len(password.encode('utf-8')) > 72:
        print("⚠️  Password exceeds 72 bytes, using argon2 for hashing")
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None