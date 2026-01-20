# Migration from Auth0

> ⏱️ **Estimated time**: 10-15 minutes with SaaSReady SDK

## Overview

SaaSReady uses the same concepts as Auth0, making migration straightforward. In most cases, it's just an SDK import swap.

## Quick Migration (SDK Swap)

```python
# Before (Auth0)
from auth0 import Auth0Client
client = Auth0Client(domain="your-tenant.auth0.com", client_id="...")

# After (SaaSReady) - Just change the import and URL!
from saasready import SaaSReady
client = SaaSReady(base_url="https://your-saasready-instance.com")
```

## Concept Mapping

| Auth0 Concept | SaaSReady Equivalent |
|---------------|---------------------|
| Tenant | Organization |
| Connection | Built-in email/password |
| Rules/Actions | Customize `auth_service.py` |
| Roles | Roles (Owner, Admin, Member, Viewer) |
| Permissions | Permissions (org.read, user.invite, etc.) |
| User Metadata | Extend User model |
| Organizations | Organizations (multi-tenant) |
| Invitations | Member invitations |

## Migration Steps

### 1. Export Users from Auth0

Use the Auth0 Management API to export your users:

```python
from auth0.management import Auth0

auth0 = Auth0(domain, token)
auth0_users = auth0.users.list()
```

### 2. Import Users to SaaSReady

For each user, they need to register fresh (password hashes can't be migrated):

```python
from saasready import SaaSReady

client = SaaSReady(base_url="https://your-instance.com")

# Option 1: Users self-register via your app
# Option 2: Send password reset emails to imported emails
for user in auth0_users:
    # Request password reset - user will set new password
    client.auth.request_password_reset(user['email'])
```

### 3. Create Organizations

```python
# Authenticate as admin
response = client.auth.login("admin@example.com", "password")
client.set_token(response.access_token)

# Create organization
org = client.orgs.create(
    name="Acme Corp",
    slug="acme-corp",
    description="Migrated from Auth0"
)
```

### 4. Invite Members to Organization

```python
# Get available roles
roles = client.orgs.list_roles(org.id)
member_role = next(r for r in roles if r.name == "member")

# Invite users to organization
for user in auth0_users:
    client.orgs.invite_member(
        org_id=org.id,
        email=user['email'],
        role_id=member_role.id,
        full_name=user.get('name')
    )
```

### 5. Update Your Application

Replace Auth0 SDK calls with SaaSReady SDK:

```python
# Login
response = client.auth.login(email, password)
token = response.access_token

# Get user
user = client.auth.me()

# Check organization membership
orgs = client.orgs.list()
```

### 6. Update Environment Variables

```bash
# Remove
AUTH0_DOMAIN=...
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...

# Add
SAASREADY_BASE_URL=https://your-instance.com
```

## Feature Differences

| Feature | Auth0 | SaaSReady |
|---------|-------|-----------|
| Social Login | ✅ | 🔜 Roadmap |
| Magic Links | ✅ | 🔜 Roadmap |
| SSO/SAML | ✅ | 🔜 Roadmap |
| Email/Password | ✅ | ✅ |
| 2FA/TOTP | ✅ | ✅ |
| Organizations | ✅ | ✅ |
| RBAC | ✅ | ✅ |
| Audit Logs | ✅ | ✅ |
| Self-Hosted | ❌ | ✅ |
| Open Source | ❌ | ✅ |

## Need Help?

- [GitHub Discussions](https://github.com/ramprag/saasready/discussions)
- [Report Issues](https://github.com/ramprag/saasready/issues)
