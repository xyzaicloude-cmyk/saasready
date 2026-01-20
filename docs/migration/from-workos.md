# Migration from WorkOS

> ⏱️ **Estimated time**: 10-15 minutes with SaaSReady SDK

## Overview

SaaSReady provides similar organization and user management features to WorkOS. Migration involves swapping the SDK and mapping your existing data.

## Quick Migration (SDK Swap)

```python
# Before (WorkOS)
from workos import WorkOS
workos = WorkOS(api_key="sk_...")

# After (SaaSReady)
from saasready import SaaSReady
client = SaaSReady(base_url="https://your-saasready-instance.com")
```

## Concept Mapping

| WorkOS Concept | SaaSReady Equivalent |
|----------------|---------------------|
| Organization | Organization |
| Organization Membership | Membership |
| Directory Sync | Manual user import (extensible) |
| SSO Connection | 🔜 Coming soon |
| Admin Portal | Built-in admin UI |
| Audit Logs | Audit Logs |
| User Management | User Management |
| Roles | Roles (Owner, Admin, Member, Viewer) |

## Migration Steps

### 1. Export Data from WorkOS

```python
from workos import WorkOS

workos = WorkOS(api_key="sk_...")

# Get organizations
orgs = workos.organizations.list_organizations()

# Get users
users = workos.user_management.list_users()
```

### 2. Create Organizations in SaaSReady

```python
from saasready import SaaSReady

client = SaaSReady(base_url="https://your-instance.com")

# Login as admin first
response = client.auth.login("admin@example.com", "password")
client.set_token(response.access_token)

for org in workos_orgs:
    # Create a URL-friendly slug from the org name
    slug = org.name.lower().replace(" ", "-")
    
    client.orgs.create(
        name=org.name,
        slug=slug,
        description=f"Migrated from WorkOS: {org.id}"
    )
```

### 3. Send Password Reset Emails

Since password hashes can't be migrated, users need to reset:

```python
for user in workos_users:
    client.auth.request_password_reset(user.email)
```

### 4. Invite Users to Organizations

```python
# Get roles
roles = client.orgs.list_roles(org_id)
member_role = next(r for r in roles if r.name == "member")

for user in workos_users:
    client.orgs.invite_member(
        org_id=org_id,
        email=user.email,
        role_id=member_role.id,
        full_name=f"{user.first_name} {user.last_name}"
    )
```

### 5. Update Application Code

```python
# Before (WorkOS)
user = workos.user_management.get_user(user_id)
orgs = workos.organizations.list_organizations()

# After (SaaSReady)
user = client.auth.me()
orgs = client.orgs.list()
```

### 6. Update Environment Variables

```bash
# Remove
WORKOS_API_KEY=...
WORKOS_CLIENT_ID=...

# Add
SAASREADY_BASE_URL=https://your-instance.com
```

## Feature Differences

| Feature | WorkOS | SaaSReady |
|---------|--------|-----------|
| SSO/SAML | ✅ | 🔜 Roadmap |
| Directory Sync | ✅ | Manual import |
| Magic Links | ✅ | 🔜 Roadmap |
| Email/Password | ✅ | ✅ |
| Organizations | ✅ | ✅ |
| Audit Logs | ✅ | ✅ |
| Admin Portal | ✅ | ✅ |
| Self-Hosted | ❌ | ✅ |
| Open Source | ❌ | ✅ |
| Feature Flags | ❌ | ✅ |

## Need Help?

- [GitHub Discussions](https://github.com/ramprag/saasready/discussions)
- [Report Issues](https://github.com/ramprag/saasready/issues)
