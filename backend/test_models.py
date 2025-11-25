#!/usr/bin/env python3
"""
Test script to check if models can be imported without circular dependency issues
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

try:
    from app.core.database import Base, engine
    from app.models import User, Organization, Membership, Role, AuditLog, OrgSettings, SSOConnection

    print("✅ All models imported successfully!")

    # Try to create tables
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()