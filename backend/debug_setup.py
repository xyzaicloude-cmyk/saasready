from sqlalchemy import text
from app.core.database import SessionLocal, engine
from app.core.security import get_password_hash
from app.models.user import User
from app.models.organization import Organization
from app.models.membership import Membership, MembershipStatus
from app.models.role import Role

def debug_setup():
    db = SessionLocal()
    try:
        print("🔍 Debugging SaaSReady Setup...")

        # 1. Test database connection
        print("1. Testing database connection...")
        try:
            db.execute(text("SELECT 1"))
            print("   ✅ Database connection OK")
        except Exception as e:
            print(f"   ❌ Database connection failed: {e}")
            return

        # 2. Check if tables exist
        print("2. Checking if tables exist...")
        tables = ['users', 'organizations', 'roles', 'memberships']
        for table in tables:
            try:
                db.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))
                print(f"   ✅ {table} table exists")
            except Exception as e:
                print(f"   ❌ {table} table missing: {e}")
                return

        # 3. Check if roles exist
        print("3. Checking default roles...")
        roles = db.query(Role).all()
        if roles:
            print(f"   ✅ Found {len(roles)} roles: {[r.name for r in roles]}")
        else:
            print("   ❌ No roles found - migration may have failed")
            return

        # 4. Check if default user exists
        print("4. Checking for default user...")
        user = db.query(User).filter(User.email == "admin@saasready.com").first()
        if user:
            print("   ✅ Default user exists")
            print(f"      Email: {user.email}")
            print(f"      ID: {user.id}")
            print(f"      Active: {user.is_active}")
        else:
            print("   ❌ Default user not found - creating now...")
            create_default_user_manual(db)
            return

        # 5. Check user's membership
        print("5. Checking user membership...")
        membership = db.query(Membership).filter(Membership.user_id == user.id).first()
        if membership:
            print("   ✅ User has organization membership")
            org = db.query(Organization).filter(Organization.id == membership.organization_id).first()
            if org:
                print(f"      Organization: {org.name} ({org.slug})")
            else:
                print("   ❌ Organization not found for membership")
        else:
            print("   ❌ User has no organization membership")

        # 6. Check password hash
        print("6. Verifying password...")
        from app.core.security import verify_password
        if verify_password("admin123", user.hashed_password):
            print("   ✅ Password verification OK")
        else:
            print("   ❌ Password verification failed")

        print("\n🎯 Debug Summary:")
        print("   Run these manual tests:")
        print("   1. Try: curl -X POST http://localhost:8000/api/v1/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"admin@saasready.com\",\"password\":\"admin123\"}'")
        print("   2. Check backend logs for any errors")
        print("   3. Verify frontend API URL is correct")

    except Exception as e:
        print(f"💥 Debug error: {e}")
    finally:
        db.close()

def create_default_user_manual(db):
    try:
        print("   Creating default user manually...")

        # Get or create Owner role
        owner_role = db.query(Role).filter(Role.name == "Owner").first()
        if not owner_role:
            print("   ❌ Owner role not found - cannot create user")
            return

        # Create user
        user = User(
            email="admin@saasready.com",
            hashed_password=get_password_hash("admin123"),
            full_name="System Administrator",
            is_active=True,
            is_superuser=True
        )
        db.add(user)
        db.flush()

        # Create organization
        org = Organization(
            name="Default Organization",
            slug="default-org",
            description="Default organization"
        )
        db.add(org)
        db.flush()

        # Create membership
        membership = Membership(
            user_id=user.id,
            organization_id=org.id,
            role_id=owner_role.id,
            status=MembershipStatus.active
        )
        db.add(membership)

        db.commit()
        print("   ✅ Default user created manually!")
        print("      Email: admin@saasready.com")
        print("      Password: admin123")

    except Exception as e:
        db.rollback()
        print(f"   ❌ Failed to create default user: {e}")

if __name__ == "__main__":
    debug_setup()