"""initial schema

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('full_name', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=True, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Create organizations table
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('slug', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)

    # Create roles table
    op.create_table(
        'roles',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system', sa.Boolean(), nullable=True, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create permissions table
    op.create_table(
        'permissions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(), nullable=False),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create memberships table
    op.create_table(
        'memberships',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('role_id', sa.String(), nullable=True),
        sa.Column('status', sa.Enum('active', 'invited', 'suspended', name='membershipstatus'), nullable=True, default='active'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create role_permissions table
    op.create_table(
        'role_permissions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('role_id', sa.String(), nullable=False),
        sa.Column('permission_id', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('role_id', 'permission_id', name='unique_role_permission')
    )

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('actor_user_id', sa.String(), nullable=True),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('target_type', sa.String(), nullable=True),
        sa.Column('target_id', sa.String(), nullable=True),
        sa.Column('audit_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_created_at'), 'audit_logs', ['created_at'], unique=False)

    # Create org_settings table
    op.create_table(
        'org_settings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('allow_signups', sa.Boolean(), nullable=True, default=True),
        sa.Column('require_email_verification', sa.Boolean(), nullable=True, default=False),
        sa.Column('sso_enabled', sa.Boolean(), nullable=True, default=False),
        sa.Column('custom_settings', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id')
    )

    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('key_hash', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('prefix', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash')
    )

    # Create sso_connections table
    op.create_table(
        'sso_connections',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('provider', sa.Enum('saml', 'oidc', 'google', 'azure', name='ssoprovider'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Seed default roles and permissions
    seed_default_roles_and_permissions()


def seed_default_roles_and_permissions():
    """Seed default roles and permissions"""
    import uuid
    from datetime import datetime

    bind = op.get_bind()

    # Define permissions
    permissions_data = [
        {"name": "user.read", "resource": "user", "action": "read", "description": "View user information"},
        {"name": "user.create", "resource": "user", "action": "create", "description": "Create new users"},
        {"name": "user.update", "resource": "user", "action": "update", "description": "Update user information"},
        {"name": "user.delete", "resource": "user", "action": "delete", "description": "Delete users"},
        {"name": "user.invite", "resource": "user", "action": "invite", "description": "Invite users to organization"},
        {"name": "user.manage", "resource": "user", "action": "manage", "description": "Full user management"},
        {"name": "org.read", "resource": "organization", "action": "read", "description": "View organization"},
        {"name": "org.update", "resource": "organization", "action": "update", "description": "Update organization"},
        {"name": "org.delete", "resource": "organization", "action": "delete", "description": "Delete organization"},
        {"name": "org.settings", "resource": "organization", "action": "settings", "description": "Manage organization settings"},
        {"name": "role.read", "resource": "role", "action": "read", "description": "View roles"},
        {"name": "role.manage", "resource": "role", "action": "manage", "description": "Manage roles and permissions"},
        {"name": "audit.read", "resource": "audit", "action": "read", "description": "View audit logs"},
    ]

    # Insert permissions
    permission_map = {}
    for perm_data in permissions_data:
        perm_id = str(uuid.uuid4())
        bind.execute(
            sa.text("""
                INSERT INTO permissions (id, name, description, resource, action, created_at)
                VALUES (:id, :name, :description, :resource, :action, :created_at)
            """),
            {
                "id": perm_id,
                "name": perm_data["name"],
                "description": perm_data["description"],
                "resource": perm_data["resource"],
                "action": perm_data["action"],
                "created_at": datetime.utcnow()
            }
        )
        permission_map[perm_data["name"]] = perm_id

    # Define roles
    roles_data = [
        {
            "name": "Owner",
            "description": "Full access to organization",
            "is_system": True,
            "permissions": [
                "user.read", "user.create", "user.update", "user.delete", "user.invite", "user.manage",
                "org.read", "org.update", "org.delete", "org.settings",
                "role.read", "role.manage",
                "audit.read"
            ]
        },
        {
            "name": "Admin",
            "description": "Administrative access",
            "is_system": True,
            "permissions": [
                "user.read", "user.invite", "user.manage",
                "org.read", "org.update", "org.settings",
                "role.read",
                "audit.read"
            ]
        },
        {
            "name": "Member",
            "description": "Standard member access",
            "is_system": True,
            "permissions": [
                "user.read",
                "org.read",
                "audit.read"
            ]
        },
        {
            "name": "Viewer",
            "description": "Read-only access",
            "is_system": True,
            "permissions": [
                "user.read",
                "org.read"
            ]
        }
    ]

    # Insert roles and role_permissions
    for role_data in roles_data:
        role_id = str(uuid.uuid4())
        bind.execute(
            sa.text("""
                INSERT INTO roles (id, name, description, is_system, created_at, updated_at)
                VALUES (:id, :name, :description, :is_system, :created_at, :updated_at)
            """),
            {
                "id": role_id,
                "name": role_data["name"],
                "description": role_data["description"],
                "is_system": role_data["is_system"],
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
        )

        # Assign permissions to role
        for perm_name in role_data["permissions"]:
            if perm_name in permission_map:
                bind.execute(
                    sa.text("""
                        INSERT INTO role_permissions (id, role_id, permission_id, created_at)
                        VALUES (:id, :role_id, :permission_id, :created_at)
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "role_id": role_id,
                        "permission_id": permission_map[perm_name],
                        "created_at": datetime.utcnow()
                    }
                )


def downgrade() -> None:
    op.drop_table('sso_connections')
    op.drop_table('api_keys')
    op.drop_table('org_settings')
    op.drop_index(op.f('ix_audit_logs_created_at'), table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_table('role_permissions')
    op.drop_table('memberships')
    op.drop_table('permissions')
    op.drop_table('roles')
    op.drop_index(op.f('ix_organizations_slug'), table_name='organizations')
    op.drop_table('organizations')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')

    op.execute('DROP TYPE IF EXISTS membershipstatus')
    op.execute('DROP TYPE IF EXISTS ssoprovider')