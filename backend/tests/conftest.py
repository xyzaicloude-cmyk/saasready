# backend/tests/conftest.py
# CRITICAL FIXES:
# 1. Import ALL models before creating tables (including email_queue)
# 2. Ensure brute force models are imported
# 3. Fix rate limiting bypass

import pytest
import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from datetime import datetime, timezone
import secrets
import uuid
import sys
import types
def mock_seed_database(db):
    """Mock seed function that does nothing"""
    print("📊 [TEST] Database seeding disabled (mock)")
    return

# Mock the seed module before anything imports it
try:
    # Try to import the seed module
    from app.core.seed import seed_database as original_seed
    # If it exists, replace it with our mock
    import app.core.seed as seed_module
    seed_module.seed_database = mock_seed_database
    print("✅ Patched app.core.seed.seed_database")
except ImportError as e:
    # If the module doesn't exist, create a mock module
    print(f"⚠️ Could not import seed module: {e}")
    print("📊 Creating mock seed module...")

    # Create a mock module
    mock_seed_module = types.ModuleType('app.core.seed')
    mock_seed_module.seed_database = mock_seed_database

    # Inject it into sys.modules
    sys.modules['app.core.seed'] = mock_seed_module

    # Also create parent modules if they don't exist
    if 'app.core' not in sys.modules:
        sys.modules['app.core'] = types.ModuleType('app.core')
    if 'app' not in sys.modules:
        sys.modules['app'] = types.ModuleType('app')

    # Link the mock module
    sys.modules['app'].core = sys.modules['app.core']
    sys.modules['app.core'].seed = mock_seed_module
# CRITICAL: Set test environment BEFORE any imports
os.environ["DATABASE_URL"] = "sqlite:///:memory:?check_same_thread=False"
os.environ["SECRET_KEY"] = "test-secret-key-min-32-chars-long-for-testing"
os.environ["ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"
os.environ["TESTING"] = "true"
os.environ["RATE_LIMIT_ENABLED"] = "false"

# Import database and models (but NOT app.main yet!)
from app.core.database import Base, get_db

# 🔧 CRITICAL FIX: Import ALL models to ensure tables are created
from app.models.user import User
from app.models.organization import Organization
from app.models.membership import Membership, MembershipStatus
from app.models.role import Role
from app.models.permission import Permission, RolePermission
from app.models.audit_log import AuditLog
from app.models.org_settings import OrgSettings
from app.models.sso_connection import SSOConnection
from app.models.feature_flag import FeatureFlag, OrgFeatureFlag
from app.models.api_key import APIKey
from app.models.token_blacklist import TokenBlacklist, UserSession

# 🔧 CRITICAL FIX: Import brute force models to create their tables
from app.services.brute_force_protection import LoginAttempt, AccountLockout

# 🔧 CRITICAL FIX: Import email queue model to create its table
from app.services.email_service import EmailQueue

from app.core.security import get_password_hash

# IN-MEMORY database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=None,
    echo=False
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=MEMORY")
    cursor.execute("PRAGMA synchronous=OFF")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.close()

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session")
def db_engine():
    """Create database engine once per test session"""
    # 🔧 CRITICAL FIX: Create ALL tables including email_queue and brute force tables
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create a fresh transaction for each test"""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection, join_transaction_mode="create_savepoint")

    yield session

    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client(db_session):
    """
    Create test client with ALL security bypassed
    CRITICAL: Patches applied BEFORE importing app.main
    """

    # =========================================================================
    # STEP 1: PATCH MODULES BEFORE IMPORTING APP
    # =========================================================================

    # Patch rate limiter
    import app.core.rate_limiter as rl_module
    original_check_rl = getattr(rl_module, 'check_rate_limit', None)

    def bypass_rate_limit(*args, **kwargs):
        return {"limit": 999999, "remaining": 999999, "reset": 9999999999}

    rl_module.check_rate_limit = bypass_rate_limit

    # 🔧 FIX: Also patch the RateLimiter class methods
    if hasattr(rl_module, 'RateLimiter'):
        def mock_check_rate_limit_method(self, key, limit, window=60, burst_multiplier=1.5):
            return (True, {"limit": 999999, "remaining": 999999, "reset": 9999999999})

        rl_module.RateLimiter.check_rate_limit = mock_check_rate_limit_method

    # Patch brute force protection
    import app.services.brute_force_protection as bf_module
    original_bf_class = bf_module.BruteForceProtection

    class TestBruteForceProtection:
        def __init__(self, db):
            self.db = db
        def check_login_allowed(self, *args, **kwargs):
            return (True, None, 0)
        def record_login_attempt(self, *args, **kwargs):
            pass
        def record_2fa_attempt(self, *args, **kwargs):
            pass
        def check_2fa_allowed(self, *args, **kwargs):
            return (True, None, 0)
        def unlock_account(self, *args, **kwargs):
            pass
        def get_login_statistics(self, *args, **kwargs):
            return {"total_attempts": 0, "failed_attempts": 0, "success_rate": 100.0, "unique_devices": 0, "period_days": 30}
        def cleanup_old_data(self, *args, **kwargs):
            return 0

    bf_module.BruteForceProtection = TestBruteForceProtection

    # Patch asyncio.sleep
    import asyncio
    original_sleep = asyncio.sleep

    async def instant_sleep(delay):
        await original_sleep(0)

    asyncio.sleep = instant_sleep

    # Patch device fingerprinting
    try:
        from app.services.device_fingerprint import DeviceFingerprinter
        DeviceFingerprinter.generate_fingerprint = lambda self: "test-device-12345"
        DeviceFingerprinter.get_device_metadata = lambda self: {
            "fingerprint": "test-device-12345",
            "user_agent": "Test Browser",
            "browser": "Chrome",
            "os": "Linux",
            "device_type": "Desktop",
            "platform": "browser",
            "ip_address": "127.0.0.1"
        }
    except ImportError:
        pass

    # Patch suspicious activity detector
    try:
        from app.services.suspicious_activity_detector import SuspiciousActivityDetector
        SuspiciousActivityDetector.analyze_login_attempt = lambda self, *args, **kwargs: {
            "risk_score": 0,
            "risk_level": "LOW",
            "recommended_action": "ALLOW",
            "indicators": [],
            "timestamp": "2025-01-01T00:00:00"
        }
    except ImportError:
        pass

    # =========================================================================
    # STEP 2: NOW IMPORT APP (after patches are in place)
    # =========================================================================

    from app.main import app

    # Override database
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    # Create test client
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client

    app.dependency_overrides.clear()

    # Restore originals
    if original_check_rl:
        rl_module.check_rate_limit = original_check_rl
    bf_module.BruteForceProtection = original_bf_class
    asyncio.sleep = original_sleep

# =========================================================================
# CLEANUP FIXTURE
# =========================================================================

@pytest.fixture(autouse=True)
def cleanup_security_data(db_session):
    """Clean security data between tests for isolation"""
    try:
        # Clean before test
        db_session.query(LoginAttempt).delete()
        db_session.query(AccountLockout).delete()
        db_session.query(UserSession).delete()
        db_session.query(TokenBlacklist).delete()

        # 🔧 FIX: Also clean email queue
        try:
            db_session.query(EmailQueue).delete()
        except:
            pass

        db_session.commit()

        yield

    except Exception as e:
        db_session.rollback()
        yield

# =========================================================================
# FACTORY FIXTURES (unchanged)
# =========================================================================

@pytest.fixture(scope="function")
def seed_roles(db_session):
    """Seed roles and permissions"""
    existing_count = db_session.query(Role).count()

    if existing_count == 0:
        permissions_data = [
            {"key": "org.read", "name": "Read Organization", "resource": "org", "action": "read"},
            {"key": "org.update", "name": "Update Organization", "resource": "org", "action": "update"},
            {"key": "user.invite", "name": "Invite Users", "resource": "user", "action": "invite"},
            {"key": "user.manage", "name": "Manage Users", "resource": "user", "action": "manage"},
            {"key": "audit.read", "name": "Read Audit Logs", "resource": "audit", "action": "read"}
        ]

        perms = {}
        for pdata in permissions_data:
            perm = Permission(**pdata)
            db_session.add(perm)
            perms[pdata["key"]] = perm

        db_session.flush()

        roles_data = [
            {"name": "owner", "description": "Organization Owner",
             "permissions": ["org.read", "org.update", "user.invite", "user.manage", "audit.read"]},
            {"name": "admin", "description": "Organization Admin",
             "permissions": ["org.read", "org.update", "user.invite", "user.manage"]},
            {"name": "member", "description": "Organization Member",
             "permissions": ["org.read"]},
            {"name": "viewer", "description": "Organization Viewer",
             "permissions": ["org.read"]}
        ]

        roles = {}
        for rdata in roles_data:
            role = Role(name=rdata["name"], description=rdata["description"], is_system=True)
            db_session.add(role)
            db_session.flush()

            for pkey in rdata["permissions"]:
                if pkey in perms:
                    rp = RolePermission(role_id=role.id, permission_id=perms[pkey].id)
                    db_session.add(rp)

            roles[rdata["name"]] = role

        db_session.commit()
    else:
        roles = {r.name: r for r in db_session.query(Role).all()}

    return roles

@pytest.fixture
def create_user(db_session):
    """Factory fixture to create users"""
    _counter = {"value": 0}

    def _create(email=None, password="Test123!", full_name="Test User", is_verified=True, commit=False):
        if email is None:
            _counter["value"] += 1
            email = f"testuser{_counter['value']}_{secrets.token_hex(4)}@test.com"

        user = User(
            email=email,
            hashed_password=get_password_hash(password),
            full_name=full_name,
            is_active=True,
            is_email_verified=is_verified,
            is_superuser=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db_session.add(user)
        if commit:
            db_session.commit()
        else:
            db_session.flush()

        return user

    return _create

@pytest.fixture
def create_org(db_session):
    """Factory fixture to create organizations"""
    _counter = {"value": 0}

    def _create(name=None, slug=None, commit=False):
        if name is None or slug is None:
            _counter["value"] += 1
            name = f"Test Org {_counter['value']}"
            slug = f"test-org-{_counter['value']}-{secrets.token_hex(4)}"

        org = Organization(
            name=name,
            slug=slug,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db_session.add(org)
        if commit:
            db_session.commit()
        else:
            db_session.flush()

        return org

    return _create

@pytest.fixture
def create_membership(db_session):
    """Factory fixture to create memberships"""
    def _create(user, org, role, status=MembershipStatus.active, commit=False):
        membership = Membership(
            user_id=user.id,
            organization_id=org.id,
            role_id=role.id if role else None,
            status=status,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db_session.add(membership)
        if commit:
            db_session.commit()
        else:
            db_session.flush()

        return membership

    return _create

@pytest.fixture
def auth_headers(client, db_session, seed_roles):
    """Create authenticated user and return auth headers"""

    def _get(role_name="owner", email=None, org_name=None):
        if email is None:
            email = f"{role_name}-{secrets.token_hex(8)}@test.com"

        role = seed_roles[role_name]

        user = User(
            email=email,
            hashed_password=get_password_hash("Test123!"),
            full_name=f"{role_name.title()} User",
            is_active=True,
            is_email_verified=True,
            is_superuser=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db_session.add(user)
        db_session.flush()

        if org_name:
            slug = org_name.lower().replace(" ", "-")
            org = Organization(name=org_name, slug=slug, created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
        else:
            org = Organization(
                name=f"{role_name.title()}'s Organization",
                slug=f"{role_name}-org-{secrets.token_hex(4)}",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
        db_session.add(org)
        db_session.flush()

        settings = OrgSettings(organization_id=org.id)
        db_session.add(settings)

        membership = Membership(
            user_id=user.id,
            organization_id=org.id,
            role_id=role.id,
            status=MembershipStatus.active,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db_session.add(membership)
        db_session.commit()

        response = client.post("/api/v1/auth/login", json={
            "email": email,
            "password": "Test123!"
        })

        if response.status_code != 200:
            error_detail = response.json() if response.content else "No response content"
            raise Exception(f"Login failed with status {response.status_code}: {error_detail}")

        token = response.json()["access_token"]

        db_session.refresh(user)
        db_session.refresh(org)

        return ({"Authorization": f"Bearer {token}"}, user, org)

    return _get

@pytest.fixture
def test_user(create_user, db_session):
    """Create a test user with verified email"""
    unique_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    user = create_user(email=unique_email, password="password123", full_name="Test User", is_verified=True)
    db_session.commit()
    return user

@pytest.fixture
def test_org(create_org, db_session):
    org = create_org()
    db_session.commit()
    return org

def as_utc_naive(dt):
    if dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt

def login_user(client, email, password):
    """Helper to login a user and return headers"""
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    if response.status_code != 200:
        raise Exception(f"Login failed: {response.json()}")
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

# Add this fixture to conftest.py, before the client fixture

@pytest.fixture(autouse=True)
def disable_rate_limit_globally():
    """Disable rate limiting for ALL tests"""
    # Store original rate limit setting
    import os
    original_rate_limit_enabled = os.environ.get("RATE_LIMIT_ENABLED", "true")
    os.environ["RATE_LIMIT_ENABLED"] = "false"

    # Also set a very high rate limit
    os.environ["RATE_LIMIT_PER_MINUTE"] = "9999"
    os.environ["RATE_LIMIT_PER_HOUR"] = "99999"

    yield

    # Restore original
    os.environ["RATE_LIMIT_ENABLED"] = original_rate_limit_enabled