# Migration from Firebase Auth

> ⏱️ **Estimated time**: 1-2 hours

## Overview

Firebase Auth uses a different paradigm (Firebase-managed tokens), so migration requires a bit more work than SDK-based providers. However, the core concepts map well.

## Concept Mapping

| Firebase Concept | SaaSReady Equivalent |
|-----------------|---------------------|
| Firebase Project | Self-hosted instance |
| Custom Claims | Role permissions |
| ID Token | JWT access token |
| Refresh Token | Refresh token |
| User UID | User ID (UUID) |
| Auth State | Session management |

## Migration Steps

### 1. Export Users from Firebase

```python
import firebase_admin
from firebase_admin import auth

# Initialize Firebase Admin
firebase_admin.initialize_app()

# Export all users
users = []
page = auth.list_users()
while page:
    for user in page.users:
        users.append({
            'uid': user.uid,
            'email': user.email,
            'display_name': user.display_name,
            'email_verified': user.email_verified,
        })
    page = page.get_next_page()
```

### 2. Send Password Reset Emails

Firebase password hashes aren't exportable, so users need to reset:

```python
from saasready import SaaSReady

client = SaaSReady(base_url="https://your-instance.com")

for user in firebase_users:
    if user['email']:
        client.auth.request_password_reset(user['email'])
```

### 3. Create Organizations (if using multi-tenancy)

```python
# Login as admin
response = client.auth.login("admin@example.com", "password")
client.set_token(response.access_token)

# Create organization
org = client.orgs.create(
    name="My Organization",
    slug="my-org",
    description="Migrated from Firebase"
)
```

### 4. Invite Users to Organization

```python
# Get roles
roles = client.orgs.list_roles(org.id)
member_role = next(r for r in roles if r.name == "member")

for user in firebase_users:
    if user['email']:
        client.orgs.invite_member(
            org_id=org.id,
            email=user['email'],
            role_id=member_role.id,
            full_name=user.get('display_name')
        )
```

### 5. Migrate Custom Claims to Roles

```python
# If you used Firebase custom claims for roles
# Map them to SaaSReady role assignments

firebase_to_saasready_role = {
    'admin': 'admin',
    'moderator': 'member',
    'user': 'member',
}

# Get roles mapping
roles = client.orgs.list_roles(org_id)
role_map = {r.name: r.id for r in roles}

for user in users:
    claims = user.get('custom_claims', {})
    role_name = firebase_to_saasready_role.get(claims.get('role'), 'member')
    
    # When inviting, use the appropriate role
    client.orgs.invite_member(
        org_id=org_id,
        email=user['email'],
        role_id=role_map[role_name]
    )
```

### 6. Update Frontend Code

```javascript
// Before (Firebase)
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth';
const auth = getAuth();
const result = await signInWithEmailAndPassword(auth, email, password);
const token = await result.user.getIdToken();

// After (SaaSReady)
const response = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
const { access_token } = await response.json();
localStorage.setItem('saasready_token', access_token);
```

### 7. Update Backend Token Validation

```python
# Before (Firebase)
from firebase_admin import auth
decoded = auth.verify_id_token(token)
uid = decoded['uid']

# After (SaaSReady)
from saasready import SaaSReady
client = SaaSReady(base_url="...")
client.set_token(token)
user = client.auth.me()
```

### 8. Update Environment Variables

```bash
# Remove Firebase config
FIREBASE_API_KEY=...
FIREBASE_AUTH_DOMAIN=...
FIREBASE_PROJECT_ID=...

# Add SaaSReady config
SAASREADY_BASE_URL=https://your-instance.com
```

## Feature Differences

| Feature | Firebase Auth | SaaSReady |
|---------|--------------|-----------|
| Social Login | ✅ | 🔜 Roadmap |
| Phone Auth | ✅ | 🔜 Roadmap |
| Anonymous Auth | ✅ | ❌ |
| Email/Password | ✅ | ✅ |
| Email Verification | ✅ | ✅ |
| Password Reset | ✅ | ✅ |
| 2FA/TOTP | ✅ | ✅ |
| Organizations | ❌ | ✅ |
| RBAC | Via Custom Claims | ✅ Native |
| Audit Logs | ❌ | ✅ |
| Feature Flags | Via Remote Config | ✅ Native |
| Self-Hosted | ❌ | ✅ |

## Need Help?

- [GitHub Discussions](https://github.com/ramprag/saasready/discussions)
- [Report Issues](https://github.com/ramprag/saasready/issues)
