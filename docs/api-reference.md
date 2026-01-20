# API Reference

> **Base URL**: `http://localhost:8000/api/v1`  
> **OpenAPI Docs**: `http://localhost:8000/docs` (Swagger UI)  
> **ReDoc**: `http://localhost:8000/redoc`

---

## Authentication

All authenticated endpoints require the `Authorization` header:

```
Authorization: Bearer <access_token>
```

---

## Endpoints

### Authentication

#### POST `/auth/register`

Register a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "requires_2fa": false,
  "message": "Registration successful",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

#### POST `/auth/login`

Authenticate a user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "two_factor_code": "123456"  // Optional, required if 2FA enabled
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "requires_2fa": false,
  "device_fingerprint": "abc123"
}
```

**Response (200 - 2FA Required):**
```json
{
  "access_token": null,
  "token_type": "bearer",
  "requires_2fa": true,
  "message": "Two-factor authentication required",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

#### GET `/auth/me`

Get current authenticated user.

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "full_name": "John Doe",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

#### POST `/auth/logout`

Logout current user (revokes token).

**Response (200):**
```json
{
  "message": "Successfully logged out"
}
```

---

#### POST `/auth/password-reset/request`

Request password reset email.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

---

#### POST `/auth/password-reset/confirm`

Complete password reset with token.

**Request:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "message": "Password reset successful"
}
```

---

#### POST `/auth/verify-email`

Verify email address with token.

**Request:**
```json
{
  "token": "verification-token-from-email"
}
```

**Response (200):**
```json
{
  "message": "Email verified successfully"
}
```

---

#### POST `/auth/resend-verification`

Resend email verification.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "Verification email sent"
}
```

---

### Two-Factor Authentication

#### POST `/auth/2fa/setup`

Generate 2FA setup (requires authentication).

**Response (200):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0...",
  "provisioning_uri": "otpauth://totp/SaaSReady:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=SaaSReady"
}
```

---

#### POST `/auth/2fa/verify`

Verify and activate 2FA.

**Query Params:** `verification_code=123456`

**Response (200):**
```json
{
  "message": "2FA enabled successfully",
  "backup_codes": [
    "abc12345",
    "def67890",
    "ghi11223",
    "jkl44556",
    "mno77889"
  ]
}
```

---

#### POST `/auth/2fa/disable`

Disable 2FA (requires password confirmation).

**Query Params:** `password=CurrentPassword123!`

**Response (200):**
```json
{
  "message": "2FA disabled successfully"
}
```

---

### Organizations

#### POST `/orgs`

Create a new organization.

**Request:**
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "description": "Our main workspace"
}
```

**Response (200):**
```json
{
  "id": "org-550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "description": "Our main workspace",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

---

#### GET `/orgs`

List user's organizations.

**Response (200):**
```json
[
  {
    "id": "org-550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "description": "Our main workspace",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
]
```

---

#### GET `/orgs/{org_id}/members`

List organization members.

**Response (200):**
```json
[
  {
    "id": "mem-550e8400-e29b-41d4-a716-446655440000",
    "user_id": "user-123",
    "organization_id": "org-123",
    "role_id": "role-owner",
    "status": "active",
    "created_at": "2024-01-15T10:30:00Z",
    "user_email": "owner@example.com",
    "user_full_name": "John Doe",
    "role_name": "owner"
  }
]
```

---

#### POST `/orgs/{org_id}/invite`

Invite a user to the organization.

**Request:**
```json
{
  "email": "newuser@example.com",
  "role_id": "role-member-id",
  "full_name": "Jane Smith"
}
```

**Response (200):**
```json
{
  "id": "mem-550e8400-e29b-41d4-a716-446655440000",
  "user_id": null,
  "organization_id": "org-123",
  "role_id": "role-member-id",
  "status": "pending",
  "created_at": "2024-01-15T10:30:00Z",
  "invited_email": "newuser@example.com",
  "invitation_expires_at": "2024-01-22T10:30:00Z",
  "role_name": "member"
}
```

---

#### GET `/orgs/{org_id}/roles`

List available roles.

**Response (200):**
```json
[
  {
    "id": "role-owner-id",
    "name": "owner",
    "description": "Full access to organization",
    "is_system": true,
    "created_at": "2024-01-01T00:00:00Z"
  },
  {
    "id": "role-admin-id",
    "name": "admin",
    "description": "Administrative access",
    "is_system": true,
    "created_at": "2024-01-01T00:00:00Z"
  },
  {
    "id": "role-member-id",
    "name": "member",
    "description": "Standard member access",
    "is_system": true,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

---

### Audit Logs

#### GET `/orgs/{org_id}/audit-logs`

Get organization audit logs.

**Query Params:** `limit=100&offset=0`

**Response (200):**
```json
[
  {
    "id": "log-550e8400-e29b-41d4-a716-446655440000",
    "actor_user_id": "user-123",
    "organization_id": "org-123",
    "action": "user.login",
    "target_type": "user",
    "target_id": "user-123",
    "audit_metadata": {
      "ip_address": "192.168.1.1",
      "device": "Chrome on Windows"
    },
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "created_at": "2024-01-15T10:30:00Z",
    "actor_email": "user@example.com"
  }
]
```

---

### Feature Flags

#### GET `/orgs/{org_id}/feature-flags`

List feature flags for organization.

**Response (200):**
```json
[
  {
    "key": "new-dashboard",
    "name": "New Dashboard UI",
    "description": "Enable the redesigned dashboard",
    "default_enabled": false,
    "enabled": true,
    "overridden": true,
    "rollout_percent": 50
  }
]
```

---

#### PUT `/orgs/{org_id}/feature-flags/{flag_key}`

Set feature flag for organization.

**Request:**
```json
{
  "enabled": true,
  "rollout_percent": 100
}
```

**Response (200):**
```json
{
  "key": "new-dashboard",
  "name": "New Dashboard UI",
  "description": "Enable the redesigned dashboard",
  "default_enabled": false,
  "enabled": true,
  "overridden": true,
  "rollout_percent": 100
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message description"
}
```

### Error Codes

| HTTP Code | Error Type | Description |
|-----------|------------|-------------|
| 400 | Bad Request | Invalid request body or parameters |
| 401 | Unauthorized | Missing or invalid authentication token |
| 403 | Forbidden | Insufficient permissions for this action |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | Resource already exists (e.g., duplicate email) |
| 422 | Validation Error | Request body validation failed |
| 429 | Rate Limited | Too many requests, retry after delay |
| 500 | Internal Error | Server-side error |

### Common Error Examples

**401 Unauthorized:**
```json
{
  "detail": "Could not validate credentials"
}
```

**403 Forbidden:**
```json
{
  "detail": "You don't have permission to perform this action"
}
```

**422 Validation Error:**
```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "type": "value_error.email"
    }
  ]
}
```

**429 Rate Limited:**
```json
{
  "detail": "Rate limit exceeded. Retry after 60 seconds."
}
```

---

## Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Login attempts | 5 | per minute |
| Registration | 3 | per minute |
| Password reset | 3 | per hour |
| API calls (authenticated) | 1000 | per hour |
| API calls (unauthenticated) | 100 | per hour |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1705312200
```

---

## Data Retention

| Data Type | Retention Period |
|-----------|-----------------|
| Audit Logs | 90 days (configurable) |
| Session Data | Until logout or expiry |
| Revoked Tokens | Until token expiry |
| Failed Login Attempts | 24 hours |

---

## Webhooks

> ⚠️ **Not Currently Supported**
>
> Webhook functionality is on the roadmap. Currently, you can extend the backend to add custom webhook triggers in `auth_service.py`.

---

## SDK Quick Reference

```python
from saasready import SaaSReady

client = SaaSReady(base_url="https://your-instance.com")

# Login
response = client.auth.login("user@example.com", "password")
client.set_token(response.access_token)

# Get user
user = client.auth.me()

# List organizations
orgs = client.orgs.list()

# Create organization
org = client.orgs.create("Acme Corp", "acme-corp")

# Invite member
roles = client.orgs.list_roles(org.id)
member_role = next(r for r in roles if r.name == "member")
client.orgs.invite_member(org.id, "new@example.com", member_role.id)
```
