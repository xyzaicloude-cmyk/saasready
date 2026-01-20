# Migration from Clerk

> ⏱️ **Estimated time**: 10-15 minutes with SaaSReady SDK

## Overview

SaaSReady provides similar authentication and organization features to Clerk. The SDK patterns are similar, making migration straightforward.

## Quick Migration (SDK Swap)

```python
# Before (Clerk)
from clerk import Clerk
clerk = Clerk(api_key="sk_...")

# After (SaaSReady)
from saasready import SaaSReady
client = SaaSReady(base_url="https://your-saasready-instance.com")
```

## Concept Mapping

| Clerk Concept | SaaSReady Equivalent |
|---------------|---------------------|
| User | User |
| Organization | Organization |
| Membership | Membership |
| Roles | Roles (Owner, Admin, Member, Viewer) |
| Session | Session (JWT + tracking) |
| Webhooks | Extend with custom routes |
| Sign-in | Login |
| Sign-up | Register |

## Migration Steps

### 1. Export Users from Clerk

```python
from clerk import Clerk

clerk = Clerk(api_key="sk_...")
clerk_users = clerk.users.list()
orgs = clerk.organizations.list()
```

### 2. Create Organizations in SaaSReady

```python
from saasready import SaaSReady

client = SaaSReady(base_url="https://your-instance.com")

# Login as admin
response = client.auth.login("admin@example.com", "password")
client.set_token(response.access_token)

# Create organizations
for org in clerk_orgs:
    client.orgs.create(
        name=org.name,
        slug=org.slug,
        description="Migrated from Clerk"
    )
```

### 3. Send Password Reset Emails

Since password hashes can't be migrated:

```python
for user in clerk_users:
    email = user.email_addresses[0].email_address
    client.auth.request_password_reset(email)
```

### 4. Invite Users to Organizations

```python
# Get roles
roles = client.orgs.list_roles(org_id)
member_role = next(r for r in roles if r.name == "member")

for user in clerk_users:
    client.orgs.invite_member(
        org_id=org_id,
        email=user.email_addresses[0].email_address,
        role_id=member_role.id,
        full_name=f"{user.first_name} {user.last_name}"
    )
```

### 5. Update Frontend Code

```javascript
// Before (Clerk React)
import { useUser, useOrganization } from '@clerk/nextjs';
const { user } = useUser();
const { organization } = useOrganization();

// After (SaaSReady)
// Create your own auth hook that calls the SaaSReady API
// Example implementation:
import { useState, useEffect } from 'react';

function useSaaSReady() {
  const [user, setUser] = useState(null);
  
  useEffect(() => {
    const token = localStorage.getItem('saasready_token');
    if (token) {
      fetch('/api/auth/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      .then(res => res.json())
      .then(setUser);
    }
  }, []);
  
  return { user };
}
```

### 6. Update Backend Token Validation

```python
# Before (Clerk)
from clerk import Clerk
clerk = Clerk(api_key="...")
user = clerk.verify_token(token)

# After (SaaSReady)
from saasready import SaaSReady
client = SaaSReady(base_url="...")
client.set_token(token)
user = client.auth.me()
```

## Feature Differences

| Feature | Clerk | SaaSReady |
|---------|-------|-----------|
| Pre-built UI Components | ✅ | Basic (customizable) |
| Social Login | ✅ | 🔜 Roadmap |
| Magic Links | ✅ | 🔜 Roadmap |
| Email/Password | ✅ | ✅ |
| 2FA/TOTP | ✅ | ✅ |
| Organizations | ✅ | ✅ |
| RBAC | ✅ | ✅ |
| Session Management | ✅ | ✅ |
| Self-Hosted | ❌ | ✅ |
| Open Source | ❌ | ✅ |
| Feature Flags | ❌ | ✅ |

## Need Help?

- [GitHub Discussions](https://github.com/ramprag/saasready/discussions)
- [Report Issues](https://github.com/ramprag/saasready/issues)
