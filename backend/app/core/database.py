# backend/app/core/database.py
"""
Enhanced database layer with connection pooling and health checks
CRITICAL: Import all models to ensure proper relationship setup
"""
from sqlalchemy import create_engine, event, pool, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import logging
import time

logger = logging.getLogger(__name__)

# Import settings with error handling
try:
    from .config import settings
except Exception as e:
    logger.error(f"Failed to load settings: {e}")
    # Fallback for migrations
    import os
    class FallbackSettings:
        DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://saasready:saasready_password@db:5432/saasready")
        DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))
        DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
        DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
        DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))
    settings = FallbackSettings()

# Create engine with production-grade connection pooling
engine = create_engine(
    settings.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE,
    pool_pre_ping=True,  # Verify connections before using
    echo=False,
    connect_args={"options": "-c timezone=utc"} if "postgresql" in settings.DATABASE_URL else {}
)

# Add connection pool event listeners
@event.listens_for(engine, "connect")
def receive_connect(dbapi_conn, connection_record):
    """Log new database connections"""
    logger.debug("New database connection established")


@event.listens_for(engine, "checkout")
def receive_checkout(dbapi_conn, connection_record, connection_proxy):
    """Log connection checkout from pool"""
    logger.debug("Connection checked out from pool")


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Session:
    """
    Get database session (FastAPI dependency)

    Usage:
        @app.get("/")
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Get database session as context manager

    Usage:
        with get_db_context() as db:
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all tables (for development)"""
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database tables created successfully")


def check_database_health() -> bool:
    """
    Check database connectivity

    Returns:
        bool: True if database is healthy
    """
    try:
        with get_db_context() as db:
            db.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def get_pool_status() -> dict:
    """
    Get connection pool status

    Returns:
        dict: Pool statistics
    """
    pool = engine.pool
    return {
        "pool_size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "total_connections": pool.size() + pool.overflow()
    }


# CRITICAL: Import all models to register with Base
def import_models():
    """
    Import all models to ensure they are registered with Base
    MUST include token_blacklist for JWT revocation
    """
    try:
        # Import all models - CRITICAL ORDER
        from ..models.user import User
        from ..models.organization import Organization
        from ..models.membership import Membership
        from ..models.role import Role
        from ..models.permission import Permission, RolePermission
        from ..models.audit_log import AuditLog
        from ..models.org_settings import OrgSettings
        from ..models.sso_connection import SSOConnection
        from ..models.feature_flag import FeatureFlag, OrgFeatureFlag
        from ..models.api_key import APIKey
        # CRITICAL: Import token revocation models
        from ..models.token_blacklist import TokenBlacklist, UserSession
        from ..services.brute_force_protection import LoginAttempt, AccountLockout

        logger.info("✅ All models imported successfully")
    except Exception as e:
        logger.warning(f"Some models could not be imported: {e}")


# Execute model import on module load
import_models()