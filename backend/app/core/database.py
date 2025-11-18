from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

# Create engine first
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Import all models AFTER Base is defined to ensure proper relationship setup
def import_models():
    """Import all models to ensure they are registered with Base"""
    from ..models import user, organization, membership, role, permission, audit_log, org_settings, sso_connection
    print("✅ All models imported successfully")

# Call this function to import models
import_models()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    """Create all tables (for development)"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully")