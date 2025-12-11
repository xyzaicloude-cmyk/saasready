# backend/app/schemas/auth.py
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    two_factor_code: Optional[str] = None  # 🆕 ENTERPRISE: 2FA support


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None  # 🆕 ENTERPRISE: Refresh token support
    token_type: str = "bearer"
    expires_in: Optional[int] = None  # 🆕 ENTERPRISE: Token expiry
    requires_2fa: Optional[bool] = False  # 🆕 ENTERPRISE: 2FA required flag
    message: Optional[str] = None  # 🆕 ENTERPRISE: Response message
    user_id: Optional[str] = None  # 🆕 ENTERPRISE: User ID for 2FA flow
    device_fingerprint: Optional[str] = None  # 🆕 ENTERPRISE: Device tracking


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    token: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class EmailVerificationRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr