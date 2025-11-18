import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.core.database import Base, get_db
from app.models import User, Organization, Membership, Role, Permission, RolePermission
from app.core.security import get_password_hash
import uuid

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    owner_role = Role(
        id=str(uuid.uuid4()),
        name="Owner",
        description="Full access",
        is_system=True
    )
    db.add(owner_role)

    user_manage_perm = Permission(
        id=str(uuid.uuid4()),
        name="user.manage",
        resource="user",
        action="manage"
    )
    db.add(user_manage_perm)

    user_invite_perm = Permission(
        id=str(uuid.uuid4()),
        name="user.invite",
        resource="user",
        action="invite"
    )
    db.add(user_invite_perm)

    db.commit()

    role_perm1 = RolePermission(
        id=str(uuid.uuid4()),
        role_id=owner_role.id,
        permission_id=user_manage_perm.id
    )
    role_perm2 = RolePermission(
        id=str(uuid.uuid4()),
        role_id=owner_role.id,
        permission_id=user_invite_perm.id
    )
    db.add(role_perm1)
    db.add(role_perm2)
    db.commit()

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db):
    user = User(
        id=str(uuid.uuid4()),
        email="test@example.com",
        hashed_password=get_password_hash("password123"),
        full_name="Test User",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_org(db, test_user):
    org = Organization(
        id=str(uuid.uuid4()),
        name="Test Organization",
        slug="test-org"
    )
    db.add(org)
    db.commit()
    db.refresh(org)

    owner_role = db.query(Role).filter(Role.name == "Owner").first()

    membership = Membership(
        id=str(uuid.uuid4()),
        user_id=test_user.id,
        organization_id=org.id,
        role_id=owner_role.id if owner_role else None
    )
    db.add(membership)
    db.commit()

    return org