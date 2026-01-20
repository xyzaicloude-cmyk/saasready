# Feature Documentation

This document provides detailed information about SaaSReady's security and authentication features.

---

## Email Verification

### How It Works

1. **On Registration**: User registers → Verification email sent automatically
2. **Email Contains**: Verification link with time-limited token
3. **On Click**: Token validated → `is_email_verified` set to `true`

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/verify-email` | POST | Verify email with token |
| `/auth/resend-verification` | POST | Resend verification email |

### Configuration

```env
# frontend/.env.local
NEXT_PUBLIC_API_URL=http://localhost:8000

# backend/.env
EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=apikey
EMAIL_SMTP_PASSWORD=your-sendgrid-api-key
EMAIL_FROM=noreply@yourdomain.com
FRONTEND_BASE_URL=https://yourdomain.com  # For email links
```

### Verification Email Template

The email includes:
- Verification link: `{FRONTEND_BASE_URL}/verify-email?token={token}`
- Token expires in 24 hours
- One-time use (invalidated after verification)

---

## Invitation-Based Registration

When a user is invited to an organization, they can register using a special flow that skips personal organization creation.

### How It Works

1. **Admin invites user**: `POST /orgs/{org_id}/invite` with email and role
2. **Email sent**: Contains registration link with `invitation_token`
3. **User registers**: `POST /auth/register` with `invitation_token` query param
4. **Auto-joined**: User is directly added to the organization with the assigned role

### Registration with Invitation Token

```bash
# Register with invitation token
curl -X POST "http://localhost:8000/api/v1/auth/register?invitation_token=abc123" \
  -H "Content-Type: application/json" \
  -d '{"email": "invited@example.com", "password": "SecurePass123!", "full_name": "Jane Doe"}'
```

> [!IMPORTANT]
> The email used during registration **must match** the invited email address. The system enforces strict email matching for security.

### SDK Usage

```python
from saasready import SaaSReady

client = SaaSReady(base_url="http://localhost:8000")

# Register with invitation token
response = client.auth.register(
    email="invited@example.com",
    password="SecurePass123!",
    full_name="Jane Doe",
    invitation_token="abc123"  # From invitation email
)

# User is now logged in and part of the organization
orgs = client.orgs.list()  # Will include the invited org
```

### Key Differences from Normal Registration

| Aspect | Normal Registration | Invitation Registration |
|--------|---------------------|------------------------|
| Personal org created | ✅ Yes | ❌ No |
| Email verification | Required | Auto-verified |
| Organization membership | None initially | Immediate with role |

---

## API Key Authentication

### Overview

API keys enable service-to-service authentication without user credentials. Useful for backend integrations, CI/CD pipelines, and automated scripts.

### Usage

```python
from saasready import SaaSReady

# Initialize with API key (no login required)
client = SaaSReady(
    base_url="https://your-instance.com",
    api_key="sk_live_your_api_key_here"
)

# Make authenticated requests directly
orgs = client.orgs.list()
```

### Configuration

```env
# backend/.env
ENABLE_API_KEY_VALIDATION=true  # Enable API key auth
```

### Security Notes

- API keys should be treated like passwords
- Store in environment variables, never commit to code
- Rotate keys periodically
- API keys bypass 2FA (by design, for automation)

---

## Refresh Token Rotation

### How It Works

1. **On Login**: Both `access_token` and `refresh_token` issued
2. **Access Token**: Short-lived (default: 60 minutes)
3. **Refresh Token**: Long-lived (default: 30 days)
4. **On Refresh**: New access token issued, refresh token remains valid

### Token Lifetimes

| Token Type | Default Lifetime | Configurable |
|------------|------------------|--------------|
| Access Token | 60 minutes | `ACCESS_TOKEN_EXPIRE_MINUTES` |
| Refresh Token | 30 days | `REFRESH_TOKEN_EXPIRE_DAYS` |

### Security Benefits

- **Short access tokens**: Minimize window if token is compromised
- **Long refresh tokens**: Better UX, users don't re-login frequently
- **Token revocation**: Both tokens revokable on logout or password change

### SDK Usage

```python
# Login returns both tokens
response = client.auth.login(email, password)
access_token = response.access_token
refresh_token = response.refresh_token

# Set both for auto-refresh
client.set_token(access_token, refresh_token)

# SDK handles refresh automatically on 401 errors
```

---

## Session Management

### Per-Device Session Tracking

SaaSReady tracks active sessions per device, enabling:

- **Multi-device login**: See all active sessions
- **Remote logout**: Revoke specific sessions
- **Device fingerprinting**: Detect suspicious logins

### Session Data Tracked

| Field | Description |
|-------|-------------|
| `jti` | Unique session/token ID |
| `device_info` | Browser/app identifier |
| `ip_address` | Login IP address |
| `user_agent` | Full user agent string |
| `created_at` | Session start time |
| `last_activity` | Last API request time |
| `is_active` | Whether session is valid |

### Maximum Sessions per User

```env
# backend/.env
MAX_SESSIONS_PER_USER=5  # Oldest session revoked when exceeded
```

When limit reached:
1. New login succeeds
2. Oldest active session is revoked
3. Security alert logged

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/sessions/current` | GET | Get current session details |
| `/auth/security/activity` | GET | Get login history and alerts |

---

## Password Reset Flow

### Flow Diagram

```
User clicks "Forgot Password"
         │
         ▼
POST /auth/password-reset/request
    body: { "email": "user@example.com" }
         │
         ▼
System sends email with reset link
    Link: {FRONTEND_BASE_URL}/reset-password?token={token}
         │
         ▼
User clicks link → Opens reset form
         │
         ▼
POST /auth/password-reset/confirm
    body: { "token": "...", "new_password": "..." }
         │
         ▼
Password updated, ALL sessions revoked
```

### Security Features

- **Token expiry**: Reset tokens valid for 1 hour
- **One-time use**: Token invalidated after use
- **Session revocation**: All active sessions revoked on password change
- **Rate limited**: 3 reset requests per hour per email

---

## Brute Force Protection

### Protection Mechanisms

| Mechanism | Threshold | Action |
|-----------|-----------|--------|
| Failed login count | 5 attempts | Account locked |
| Progressive delays | Each failure | +exponential delay |
| IP-based tracking | 10 attempts | IP blocked |
| Device ID tracking | 5 attempts | Device blocked |

### Configuration

```env
# backend/.env
MAX_LOGIN_ATTEMPTS=5           # Before lockout
ACCOUNT_LOCKOUT_MINUTES=30     # Lockout duration
RATE_LIMIT_LOGIN=5             # Per minute
```

### Lockout Behavior

1. After 5 failed attempts → 30-minute lockout
2. Successful login → Counter reset
3. Admin can manually unlock accounts
4. Security event logged for audit

---

## Two-Factor Authentication (TOTP)

### Setup Flow

```
User enables 2FA
         │
         ▼
POST /auth/2fa/setup (authenticated)
    Returns: { secret, qr_code, provisioning_uri }
         │
         ▼
User scans QR code in authenticator app
         │
         ▼
POST /auth/2fa/verify?verification_code=123456
    Returns: { backup_codes: [...] }
         │
         ▼
2FA is now enabled for this user
```

### Backup Codes

- 5 backup codes generated on 2FA enable
- Each code is one-time use
- Store securely offline
- Can regenerate by disabling/enabling 2FA

### Login with 2FA

```python
# First attempt returns 2FA required
response = client.auth.login(email, password)
if response.requires_2fa:
    # Second attempt with TOTP code
    response = client.auth.login(email, password, two_factor_code="123456")
```

### Supported Authenticator Apps

- Google Authenticator
- Authy
- 1Password
- Microsoft Authenticator
- Any TOTP-compatible app

---

## Security Headers

All responses include security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | XSS filter |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Content-Security-Policy` | `default-src 'self'` | Limit resource loading |

---

## Audit Logging

### Events Logged

| Action | Description |
|--------|-------------|
| `user.login` | Successful login |
| `user.login.failed` | Failed login attempt |
| `user.logout` | User logout |
| `user.register` | New user registration |
| `user.password.change` | Password changed |
| `user.password.reset` | Password reset completed |
| `user.2fa.enable` | 2FA enabled |
| `user.2fa.disable` | 2FA disabled |
| `org.create` | Organization created |
| `org.update` | Organization updated |
| `member.invite` | Member invited |
| `member.join` | Member accepted invite |
| `member.remove` | Member removed |
| `member.role.change` | Member role changed |

### Log Retention

- Default: 90 days
- Configurable via environment variable
- Automatic cleanup via background worker
