---
title: How to Add Multi-Tenant Authentication to Your SaaS App
description: Step-by-step guide to implementing multi-tenant auth, organizations, RBAC, and team invitations in Python. Complete tutorial with code examples.
keywords: [multi-tenant authentication, saas authentication, rbac implementation, team invitations, organization management, python auth tutorial]
---

# How to Add Multi-Tenant Authentication to Your SaaS App

Building a B2B SaaS application? You need more than just user login - you need **multi-tenancy**, **organizations**, **role-based access control (RBAC)**, and **team invitations**.

This guide shows you how to implement all of these features in **under 30 minutes** using SaaSReady.

---

## What You'll Build

By the end of this tutorial, your app will have:

✅ **User authentication** (email/password, JWT tokens)  
✅ **Organizations** (multi-tenant isolation)  
✅ **RBAC** (Owner, Admin, Member, Viewer roles)  
✅ **Team invitations** (email-based onboarding)  
✅ **Audit logging** (compliance-ready)  
✅ **2FA/TOTP** (security hardening)

---

## Step 1: Set Up SaaSReady (5 minutes)

### Prerequisites
- Docker & Docker Compose installed
- Git installed
- Python 3.11+ (for SDK usage)

### Deploy SaaSReady

```bash
# Clone the repository
git clone https://github.com/ramprag/saasready.git
cd saasready

# Configure environment
cp backend/.env.example .env

# Generate secure secret key
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# Copy output to SECRET_KEY in .env

# Start all services
docker-compose up --build
```

**Services now running:**
- 🌐 Frontend: http://localhost:3000
- 🔌 API: http://localhost:8000
- 📊 API Docs: http://localhost:8000/docs

---

## Step 2: Install the Python SDK

```bash
pip install saasready
```

Or add to `requirements.txt`:
```txt
saasready>=1.0.0
```

---

## Step 3: User Registration & Login (5 minutes)

### Register a New User

```python
from saasready import SaaSReady

# Initialize client
client = SaaSReady(base_url="http://localhost:8000")

# Register new user
response = client.auth.register(
    email="founder@acme.com",
    password="SecurePass123!",
    full_name="Jane Founder"
)

print(f"User created: {response.user.email}")
print(f"Access token: {response.access_token}")
# Personal organization auto-created!
```

**What happened:**
1. ✅ User account created
2. ✅ Password securely hashed (bcrypt)
3. ✅ Personal organization created (user is Owner)
4. ✅ JWT tokens generated
5. ✅ Audit log entry created

### Login Existing User

```python
# Login
response = client.auth.login(
    email="founder@acme.com",
    password="SecurePass123!"
)

# Tokens automatically stored in client
user = client.auth.me()
print(f"Logged in as: {user.full_name}")
```

---

## Step 4: Create an Organization (5 minutes)

Organizations are the foundation of multi-tenancy. Each org has its own members, data, and permissions.

### Create Organization

```python
# Create a company organization
org = client.orgs.create(
    name="Acme Corporation",
    slug="acme-corp"  # Unique identifier
)

print(f"Organization created!")
print(f"ID: {org.id}")
print(f"Slug: {org.slug}")
print(f"You are: {org.your_role}")  # Owner
```

### List User's Organizations

```python
# Get all organizations user belongs to
orgs = client.orgs.list()

for org in orgs:
    print(f"{org.name} - Role: {org.your_role}")
```

---

## Step 5: Implement RBAC (5 minutes)

SaaSReady includes built-in roles with granular permissions:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Owner** | Full control | Founders, billing owners |
| **Admin** | Manage team, settings | Team leads |
| **Member** | Read org data, basic actions | Regular employees |
| **Viewer** | Read-only access | Auditors, contractors |

### List Available Roles

```python
roles = client.orgs.list_roles(org_id=org.id)

for role in roles:
    print(f"{role.name}: {role.permissions}")
```

### Check User Permissions

```python
# Check if user can perform an action
user = client.auth.me()

if "org.update" in user.permissions:
    print("User can update organization settings")

if "user.invite" in user.permissions:
    print("User can invite team members")
```

### Protect API Endpoints (FastAPI Example)

```python
from fastapi import Depends, HTTPException, Header
from saasready import SaaSReady

client = SaaSReady(base_url="http://localhost:8000")

def require_permission(permission: str):
    async def check_permission(authorization: str = Header()):
        token = authorization.replace("Bearer ", "")
        # Set the token and fetch user details
        client.set_token(token)
        try:
            user = client.auth.me()
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        if permission not in user.permissions:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        return user
    
    return check_permission

# Usage
@app.delete("/organizations/{org_id}")
async def delete_org(
    org_id: str,
    user = Depends(require_permission("org.delete"))
):
    # Only Owners can reach this endpoint
    client.orgs.delete(org_id)
    return {"status": "deleted"}
```

---

## Step 6: Invite Team Members (5 minutes)

### Send Invitation

```python
# Get admin role
roles = client.orgs.list_roles(org_id=org.id)
admin_role = next(r for r in roles if r.name == "Admin")

# Invite team member
invitation = client.orgs.invite_member(
    org_id=org.id,
    email="alice@acme.com",
    role_id=admin_role.id
)

print(f"Invitation sent to {invitation.email}")
print(f"Token: {invitation.token}")
print(f"Expires: {invitation.expires_at}")
```

**What happened:**
1. ✅ Invitation created in database
2. ✅ Email queued (sent via background worker)
3. ✅ Expiry set (7 days by default)
4. ✅ Audit log entry created

### Accept Invitation (Pre-Login)

New users can accept invitations **before creating an account**:

```python
# User clicks invitation link with token
invite_token = "inv_abc123..."

# Register and accept in one step
response = client.auth.register(
    email="alice@acme.com",
    password="AlicePass123!",
    full_name="Alice Admin",
    invitation_token=invite_token  # Auto-joins org!
)

print(f"User joined organization: {response.organization.name}")
print(f"Role: {response.role}")
```

### List Pending Invitations

```python
# View all pending invitations for an org
invitations = client.orgs.list_invitations(org_id=org.id)

for inv in invitations:
    print(f"{inv.email} - {inv.role_name} - {inv.status}")
```

---

## Step 7: Add 2FA/TOTP (Optional, 5 minutes)

### Enable 2FA for User

```python
# Generate TOTP secret
totp_response = client.auth.enable_2fa()

print(f"Secret: {totp_response.secret}")
print(f"QR Code URL: {totp_response.qr_code_url}")
print(f"Backup codes: {totp_response.backup_codes}")

# User scans QR code with authenticator app (Google Authenticator, Authy)

# Verify TOTP code
client.auth.verify_2fa(code="123456")
print("2FA enabled!")
```

### Login with 2FA

```python
# Login with 2FA code from authenticator app
response = client.auth.login(
    email="founder@acme.com",
    password="SecurePass123!",
    two_factor_code="123456"  # Code from authenticator app
)

print("Logged in with 2FA!")
print(f"Access token: {response.access_token}")
```

> **Note:** If the user has 2FA enabled but doesn't provide the code, the login will fail. 
> For initial 2FA setup, use `client.auth.setup_2fa()` followed by `client.auth.verify_2fa(code)`.

---

## Step 8: Audit Logging (Built-in)

All sensitive actions are automatically logged:

```python
# List audit logs for organization
logs = client.orgs.list_audit_logs(
    org_id=org.id,
    limit=50
)

for log in logs:
    print(f"{log.timestamp} - {log.user_email}")
    print(f"  Action: {log.action}")
    print(f"  IP: {log.ip_address}")
    print(f"  User Agent: {log.user_agent}")
```

**Automatically logged actions:**
- User login/logout
- Organization created/updated/deleted
- Member invited/removed
- Role changed
- Permissions modified
- 2FA enabled/disabled
- Password changed

---

## Step 9: Feature Flags (Bonus)

Control feature rollouts per organization:

```python
# Enable feature for specific org
client.features.set_flag(
    org_id=org.id,
    flag_name="advanced_analytics",
    enabled=True
)

# Check feature in your app
if client.features.is_enabled("advanced_analytics", org_id=org.id):
    # Show advanced analytics dashboard
    pass
```

---

## Complete Integration Example

### FastAPI Application

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from saasready import SaaSReady
from pydantic import BaseModel

app = FastAPI()
client = SaaSReady(base_url="http://localhost:8000")

# Models
class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str

class LoginRequest(BaseModel):
    email: str
    password: str

# Dependency: Get current user
async def get_current_user(authorization: str = Header()):
    token = authorization.replace("Bearer ", "")
    client.set_token(token)
    try:
        user = client.auth.me()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# Routes
@app.post("/auth/register")
async def register(data: RegisterRequest):
    response = client.auth.register(
        email=data.email,
        password=data.password,
        full_name=data.full_name
    )
    return {
        "access_token": response.access_token,
        "user": response.user
    }

@app.post("/auth/login")
async def login(data: LoginRequest):
    response = client.auth.login(
        email=data.email,
        password=data.password
    )
    return {
        "access_token": response.access_token,
        "user": response.user
    }

@app.get("/me")
async def get_me(user = Depends(get_current_user)):
    return user

@app.get("/organizations")
async def list_orgs(user = Depends(get_current_user)):
    return client.orgs.list()

@app.post("/organizations")
async def create_org(
    name: str,
    slug: str,
    user = Depends(get_current_user)
):
    org = client.orgs.create(name=name, slug=slug)
    return org
```

---

## Next Steps

Now that you have multi-tenant auth set up:

1. **Customize roles** - [RBAC Guide](../features.md#rbac)
2. **Deploy to production** - [Deployment Guide](../deployment.md)
3. **Configure email** - [Setup Guide](../setup-guide.md#email-configuration)
4. **Add SSO** (roadmap) - [Track progress](https://github.com/ramprag/saasready/issues)

---

## Common Questions

**Q: How do I isolate data per organization?**  
A: Add `org_id` to your database tables and filter by `user.current_org_id`:

```python
# Get user's current organization
user = client.auth.me()
org_id = user.current_org_id

# Query your database
projects = db.query(Project).filter(Project.org_id == org_id).all()
```

**Q: Can users belong to multiple organizations?**  
A: Yes! Users can be members of multiple orgs with different roles in each.

**Q: How do I handle billing per organization?**  
A: Store Stripe customer ID in organization metadata:

```python
org = client.orgs.update(
    org_id=org.id,
    metadata={"stripe_customer_id": "cus_abc123"}
)
```

**Q: Is this production-ready?**  
A: Yes! SaaSReady includes:
- Connection pooling
- Rate limiting
- Brute force protection
- Token revocation
- Audit logging
- Background job processing

---

## Resources

- [📖 Full Documentation](../index.md)
- [🔌 API Reference](../api-reference.md)
- [🐍 Python SDK Reference](../../SDK_README.md)
- [🚀 Deployment Guide](../deployment.md)
- [💬 Community Support](https://github.com/ramprag/saasready/discussions)

---

**Ready to build your B2B SaaS?** Star us on [GitHub](https://github.com/ramprag/saasready) and join our community!
