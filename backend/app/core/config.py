from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10080

    # Email Configuration
    EMAIL_FROM: str = "noreply@test-2p0347zvknylzdrn.mlsender.net"
    EMAIL_SMTP_HOST: str = "smtp.mailersend.net"
    EMAIL_SMTP_PORT: int = 587
    EMAIL_SMTP_USERNAME: str = "MS_3kFcX0@test-2p0347zvknylzdrn.mlsender.net"
    EMAIL_SMTP_PASSWORD: str = "mssp.L28U8JC.vywj2lp3k8m47oqz.oE7Mpl4"
    EMAIL_USE_TLS: bool = True
    EMAIL_USE_SSL: bool = False


    # Frontend URL for email links
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()