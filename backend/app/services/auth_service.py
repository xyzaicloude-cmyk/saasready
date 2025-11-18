from sqlalchemy.orm import Session
from datetime import timedelta
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from ..models.user import User
from ..models.organization import Organization
from ..models.membership import Membership, MembershipStatus
from ..models.role import Role
from ..core.security import verify_password, get_password_hash, validate_password_length,create_access_token
from ..core.config import settings
from ..schemas.auth import RegisterRequest, LoginRequest
import re
import traceback


class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def register_user(self, data: RegisterRequest) -> tuple[User, str]:
        print(f"🔧 Starting registration process for: {data.email}")

        # Validate password length
        if not validate_password_length(data.password):
            print(f"❌ Password too long for user: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password cannot exceed 72 characters. Please use a shorter password."
            )

        # Check if user already exists
        existing_user = self.db.query(User).filter(User.email == data.email).first()
        if existing_user:
            print(f"❌ User already exists: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        try:
            print("🔧 Creating user...")
            # Create user first
            user = User(
                email=data.email,
                hashed_password=get_password_hash(data.password),
                full_name=data.full_name
            )
            self.db.add(user)
            self.db.flush()  # Get user ID without commit
            print(f"✅ User created with ID: {user.id}")

            # Generate unique organization slug
            base_name = data.full_name or data.email.split('@')[0]
            base_slug = re.sub(r'[^a-z0-9]+', '-', base_name.lower()).strip('-')
            slug = base_slug
            counter = 1

            # Ensure slug is unique
            while self.db.query(Organization).filter(Organization.slug == slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1

            print(f"🔧 Creating organization with slug: {slug}")
            # Create organization
            org = Organization(
                name=f"{base_name}'s Organization",
                slug=slug,
                description="Personal workspace"
            )
            self.db.add(org)
            self.db.flush()  # Get org ID without commit
            print(f"✅ Organization created with ID: {org.id}")

            print("🔧 Looking for owner role...")
            # Get or create owner role
            owner_role = self.db.query(Role).filter(Role.name == "owner").first()
            if not owner_role:
                print("❌ Owner role not found, creating...")
                owner_role = Role(name="owner", description="Organization owner")
                self.db.add(owner_role)
                self.db.flush()
                print(f"✅ Created owner role with ID: {owner_role.id}")
            else:
                print(f"✅ Found owner role with ID: {owner_role.id}")

            print("🔧 Creating membership...")
            # Create membership
            membership = Membership(
                user_id=user.id,
                organization_id=org.id,
                role_id=owner_role.id,
                status=MembershipStatus.active
            )
            self.db.add(membership)

            # Commit everything
            print("🔧 Committing transaction...")
            self.db.commit()
            self.db.refresh(user)
            print("✅ Transaction committed successfully")

        except IntegrityError as e:
            self.db.rollback()
            print(f"❌ Database integrity error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed due to database constraints"
            )
        except SQLAlchemyError as e:
            self.db.rollback()
            print(f"❌ Database error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error during registration"
            )
        except Exception as e:
            self.db.rollback()
            print(f"❌ Unexpected error: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Registration failed: {str(e)}"
            )

        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)},  # Use user ID as subject
            expires_delta=access_token_expires
        )
        print(f"✅ Access token created for user: {user.id}")

        return user, access_token

    def login_user(self, data: LoginRequest) -> tuple[User, str]:
        print(f"🔧 Login attempt for: {data.email}")

        user = self.db.query(User).filter(User.email == data.email).first()
        if not user:
            print(f"❌ User not found: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        if not verify_password(data.password, user.hashed_password):
            print(f"❌ Invalid password for: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        if not user.is_active:
            print(f"❌ User inactive: {data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)},  # Use user ID as subject
            expires_delta=access_token_expires
        )
        print(f"✅ Login successful for: {data.email}")

        return user, access_token

    def _generate_org_slug(self, base: str) -> str:
        slug = re.sub(r'[^a-z0-9]+', '-', base.lower()).strip('-')
        original_slug = slug
        counter = 1

        while self.db.query(Organization).filter(Organization.slug == slug).first():
            slug = f"{original_slug}-{counter}"
            counter += 1

        return slug