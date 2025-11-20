from sqlalchemy.orm import Session
from ..models.role import Role
from ..models.permission import Permission, RolePermission


def seed_database(db: Session) -> None:
    """
    Seed the database with default roles and permissions.
    This function is idempotent - safe to run multiple times.
    """

    print("🌱 Starting database seeding...")

    # Define default permissions with key, name, resource, and action
    default_permissions = [
        {
            "key": "org.read",
            "name": "Read Organization",
            "description": "View organization details",
            "resource": "org",
            "action": "read"
        },
        {
            "key": "org.update",
            "name": "Update Organization",
            "description": "Modify organization settings",
            "resource": "org",
            "action": "update"
        },
        {
            "key": "user.invite",
            "name": "Invite Users",
            "description": "Invite new users to the organization",
            "resource": "user",
            "action": "invite"
        },
        {
            "key": "user.manage",
            "name": "Manage Users",
            "description": "Change user roles and remove users",
            "resource": "user",
            "action": "manage"
        },
        {
            "key": "audit.read",
            "name": "Read Audit Logs",
            "description": "View audit logs",
            "resource": "audit",
            "action": "read"
        },
        {
            "key": "api_key.manage",
            "name": "Manage API Keys",
            "description": "Create and delete API keys",
            "resource": "api_key",
            "action": "manage"
        },
        {
            "key": "settings.read",
            "name": "Read Settings",
            "description": "View organization settings",
            "resource": "settings",
            "action": "read"
        },
        {
            "key": "settings.update",
            "name": "Update Settings",
            "description": "Modify organization settings",
            "resource": "settings",
            "action": "update"
        },
    ]

    # Seed permissions
    print("📋 Seeding permissions...")
    permissions_map = {}

    for perm_data in default_permissions:
        permission = db.query(Permission).filter(Permission.key == perm_data["key"]).first()

        if not permission:
            permission = Permission(
                key=perm_data["key"],
                name=perm_data["name"],
                description=perm_data["description"],
                resource=perm_data["resource"],
                action=perm_data["action"]
            )
            db.add(permission)
            db.flush()
            print(f"  ✅ Created permission: {perm_data['key']}")
        else:
            print(f"  ℹ️  Permission already exists: {perm_data['key']}")

        permissions_map[perm_data["key"]] = permission

    db.commit()

    # Define default roles
    default_roles = [
        {
            "name": "owner",
            "description": "Organization owner with full access",
            "permissions": ["org.read", "org.update", "user.invite", "user.manage", "audit.read", "api_key.manage", "settings.read", "settings.update"]
        },
        {
            "name": "admin",
            "description": "Administrator with management permissions",
            "permissions": ["org.read", "org.update", "user.invite", "user.manage", "audit.read", "settings.read", "settings.update"]
        },
        {
            "name": "member",
            "description": "Regular member with basic access",
            "permissions": ["org.read", "settings.read"]
        },
        {
            "name": "viewer",
            "description": "Read-only access",
            "permissions": ["org.read"]
        }
    ]

    # Seed roles and role-permission mappings
    print("👥 Seeding roles...")

    for role_data in default_roles:
        role = db.query(Role).filter(Role.name == role_data["name"]).first()

        if not role:
            role = Role(
                name=role_data["name"],
                description=role_data["description"]
            )
            db.add(role)
            db.flush()
            print(f"  ✅ Created role: {role_data['name']}")
        else:
            print(f"  ℹ️  Role already exists: {role_data['name']}")

        # Assign permissions to role
        print(f"  🔗 Assigning permissions to {role_data['name']}...")

        for perm_key in role_data["permissions"]:
            permission = permissions_map.get(perm_key)

            if permission:
                # Check if role-permission link already exists
                existing_link = db.query(RolePermission).filter(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id
                ).first()

                if not existing_link:
                    role_permission = RolePermission(
                        role_id=role.id,
                        permission_id=permission.id
                    )
                    db.add(role_permission)
                    print(f"    ✅ Linked {role_data['name']} -> {perm_key}")
                else:
                    print(f"    ℹ️  Link already exists: {role_data['name']} -> {perm_key}")

    db.commit()
    print("🎉 Database seeding completed successfully!")


def seed_initial_data(db: Session) -> None:
    """Alias for backward compatibility"""
    seed_database(db)