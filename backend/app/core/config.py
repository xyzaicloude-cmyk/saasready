# backend/app/core/config.py
"""
Production-grade configuration with validation
Unified from config.py and enhanced settings
"""
from pydantic_settings import BaseSettings
from typing import Optional
from pydantic import field_validator
import secrets


class Settings(BaseSettings):
    """Application settings with comprehensive validation"""

    # Database
    DATABASE_URL: str

    # Security - JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Email Configuration
    EMAIL_FROM: str = "noreply@saasready.com"
    EMAIL_SMTP_HOST: str = ""
    EMAIL_SMTP_PORT: int = 587
    EMAIL_SMTP_USERNAME: str = ""
    EMAIL_SMTP_PASSWORD: str = ""
    EMAIL_USE_TLS: bool = True
    EMAIL_USE_SSL: bool = False

    # Frontend URL
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    # Redis Configuration
    REDIS_URL: Optional[str] = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: int = 60  # requests per minute
    RATE_LIMIT_LOGIN: int = 5
    RATE_LIMIT_REGISTER: int = 3

    # Brute Force Protection
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 30

    # Connection Pooling
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600

    # Caching
    CACHE_ENABLED: bool = True
    CACHE_TTL: int = 300

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text

    # API Keys
    API_KEY_PREFIX: str = "sk"
    API_KEY_LENGTH: int = 32

    # Session Management
    MAX_SESSIONS_PER_USER: int = 5
    SESSION_CLEANUP_INTERVAL: int = 3600  # 1 hour

    # Feature Flags
    FEATURE_EMAIL_VERIFICATION: bool = True
    FEATURE_2FA: bool = False
    FEATURE_SSO: bool = False

    # Cleanup Jobs
    CLEANUP_EXPIRED_TOKENS_INTERVAL: int = 3600  # 1 hour
    CLEANUP_OLD_EMAILS_DAYS: int = 30
    CLEANUP_OLD_AUDIT_LOGS_DAYS: int = 90

    @property
    def redis_url_computed(self) -> str:
        """Compute Redis URL from components if not provided"""
        if self.REDIS_URL:
            return self.REDIS_URL

        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        else:
            return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v):
        """Validate secret key length"""
        if v and len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v):
        """Validate database URL"""
        if v and not v.startswith(("postgresql://", "sqlite://")):
            raise ValueError("Invalid database URL")
        return v

    @staticmethod
    def generate_secret_key() -> str:
        """Generate a secure SECRET_KEY"""
        return secrets.token_urlsafe(64)

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # Allow extra fields for backward compatibility


# Create global settings instance
settings = Settings()


# Standalone function for CLI usage
def generate_secret_key() -> str:
    """Generate a secure SECRET_KEY (standalone function)"""
    return secrets.token_urlsafe(64)


if __name__ == "__main__":
    # Print sample .env configuration
    print("# Sample .env configuration for production")
    print(f"SECRET_KEY={generate_secret_key()}")
    print(f"DATABASE_URL=postgresql://user:pass@localhost:5432/dbname")
    print(f"REDIS_URL=redis://localhost:6379/0")
    print(f"ACCESS_TOKEN_EXPIRE_MINUTES={settings.ACCESS_TOKEN_EXPIRE_MINUTES}")
    print(f"REFRESH_TOKEN_EXPIRE_DAYS={settings.REFRESH_TOKEN_EXPIRE_DAYS}")