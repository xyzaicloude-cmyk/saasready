from sqlalchemy.orm import Session
from ..models.role import Role
from ..models.permission import Permission

def seed_database(db: Session):
    """Seed the database with default data"""
    print("🌱 Seeding database...")

    # Create default roles
    default_roles = [
        {"name": "owner", "description": "Organization owner with full access"},
        {"name": "admin", "description": "Organization administrator"},
        {"name": "member", "description": "Regular organization member"},
        {"name": "viewer", "description": "Read-only access"},
    ]

    for role_data in default_roles:
        role = db.query(Role).filter(Role.name == role_data["name"]).first()
        if not role:
            role = Role(**role_data)
            db.add(role)
            print(f"✅ Created role: {role_data['name']}")
        else:
            print(f"✅ Role already exists: {role_data['name']}")

    try:
        db.commit()
        print("✅ Database seeding completed successfully")
    except Exception as e:
        db.rollback()
        print(f"❌ Database seeding failed: {e}")
        raise