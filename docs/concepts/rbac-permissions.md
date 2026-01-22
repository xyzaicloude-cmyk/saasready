---
title: RBAC & Permissions System
description: Understanding the Role-Based Access Control (RBAC) model in SaaSReady. Learn about granular permissions, built-in roles, and security enforcement.
keywords: [RBAC SaaS, role based access control, fastapi permissions, hierarchical roles, B2B auth permissions]
---

# RBAC & Permissions

SaaSReady uses a robust **Role-Based Access Control (RBAC)** model to manage what users can and cannot do within an organization. This system is designed to be both "set and forget" for standard needs and highly customizable for complex enterprise workflows.

## The RBAC Model

The system is built on three pillars:

1. **Permissions**: Granular "atoms" of access (e.g., `org.update`, `user.invite`). These are the lowest level of checks.
2. **Roles**: Collections of permissions (e.g., "Admin" has 10 permissions, "Viewer" has 2).
3. **Memberships**: The association of a user to an organization with a specific role.

## Built-in Roles

Out of the box, SaaSReady provides four standard roles that cover 95% of B2B SaaS use cases:

| Role | Hierarchy Level | Description |
|------|-----------------|-------------|
| **Owner** | 4 | Full control. Can delete the organization, manage billing, and assign any role. |
| **Admin** | 3 | Can manage users, organization settings, and view audit logs. Cannot delete the org. |
| **Member** | 2 | Normal user. Can perform core application tasks and view organization details. |
| **Viewer** | 1 | Read-only access. Useful for audits or external stakeholders. |

## Role Hierarchy

SaaSReady enforces a **Role Hierarchy**. This means a user can only manage users or assign roles that are *lower* than their own in the hierarchy. An Admin cannot promote someone to Owner, but they can invite a Member or Viewer.

## Permission Enforcement

Permissions are enforced at the API layer using FastAPI dependency injection. This ensures that security is checked before any business logic executes.

```python
@router.patch("/{org_id}")
async def update_organization(
    org_id: str,
    # This dependency ensures the user has 'org.update' in this specific org
    current_membership: Membership = Depends(require_permission("org.update"))
):
    ...
```

## Custom Roles

While the system provides defaults, you can define organization-specific custom roles. This is critical for enterprise customers who need specific "Compliance Officer" or "Billing Admin" roles that don't fit into the standard tiers.

## Security Best Practices

- **Principle of Least Privilege**: Always start users as Viewers or Members and promote them only when necessary.
- **Regular Audits**: Use the [Audit Logs](./audit-logging.md) to track who is changing roles and when permissions are being used.
