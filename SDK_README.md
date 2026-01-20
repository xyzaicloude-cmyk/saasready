# SaaSReady Python SDK

[![PyPI version](https://badge.fury.io/py/saasready.svg)](https://badge.fury.io/py/saasready)
[![Python Versions](https://img.shields.io/pypi/pyversions/saasready.svg)](https://pypi.org/project/saasready/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://docs.saasready.com)

**Enterprise-grade authentication and multi-tenancy SDK for Python applications.** Drop-in infrastructure for B2B SaaS authentication, similar to Auth0, WorkOS, and Clerk.

---

## 🚀 **Features**

- **🔐 Authentication** - JWT-based user authentication with email/password
- **🏢 Multi-Tenancy** - Organization-based tenant isolation
- **👥 RBAC** - Role-based access control with granular permissions
- **📧 Member Invitations** - Invite users to organizations
- **📊 Audit Logging** - Track all user actions and security events
- **🎯 Feature Flags** - Gradual rollouts and A/B testing
- **🔄 Session Management** - Token lifecycle and refresh
- **🛡️ Security** - Brute force protection, rate limiting, 2FA support

---

## 📦 **Installation**

```bash
# Install via pip
pip install saasready

# Install with async support
pip install saasready[async]

# Install development dependencies
pip install saasready[dev]
```

### Requirements

- Python 3.8+
- requests >= 2.25.0
- pydantic >= 2.0.0

---

## ⚡ **Quick Start**

### 1. Initialize the Client

```python
from saasready import SaaSReady

# Initialize with your SaaSReady instance URL
client = SaaSReady(
    base_url="https://api.yourdomain.com",
    timeout=30.0
)
```

### 2. Authenticate a User

```python
# Register a new user
response = client.auth.register(
    email="user@company.com",
    password="SecurePassword123",
    full_name="John Doe"
)

print(f"Access Token: {response.access_token}")

# Or login existing user
response = client.auth.login(
    email="user@company.com",
    password="SecurePassword123"
)

# Set token for authenticated requests
client.set_token(response.access_token)
```

### 3. Work with Organizations

```python
# Create organization
org = client.orgs.create(
    name="Acme Corp",
    slug="acme-corp",
    description="Our main workspace"
)

# List user's organizations
orgs = client.orgs.list()

# Get organization members
members = client.orgs.list_members(org.id)
```

### 4. Invite Team Members

```python
# Get available roles
roles = client.orgs.list_roles(org_id)
admin_role = next(r for r in roles if r.name == "admin")

# Invite user
membership = client.orgs.invite_member(
    org_id=org.id,
    email="newuser@company.com",
    role_id=admin_role.id,
    full_name="Jane Smith"
)

print(f"Invitation sent to {membership.user_email}")
```

### 5. Check Permissions

```python
# Get current user
user = client.auth.me()

# Check feature flag
if client.flags.is_enabled(org_id, "beta-new-ui"):
    print("New UI enabled!")
```

---

## 📖 **Usage Examples**

### Context Manager Pattern

```python
# Automatically close connections
with SaaSReady(base_url="https://api.yourdomain.com") as client:
    response = client.auth.login("user@company.com", "password")
    client.set_token(response.access_token)
    
    orgs = client.orgs.list()
    print(f"Found {len(orgs)} organizations")
```

### Error Handling

```python
from saasready import (
    SaaSReady,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    RateLimitError
)

client = SaaSReady(base_url="https://api.yourdomain.com")

try:
    response = client.auth.login("user@company.com", "wrong-password")
except AuthenticationError as e:
    print(f"Login failed: {e.message}")
    print(f"Status code: {e.status_code}")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
except ValidationError as e:
    print(f"Validation error: {e.response}")
```

### Token Refresh

```python
# Store refresh token
response = client.auth.login("user@company.com", "password")
access_token = response.access_token
refresh_token = response.refresh_token

# Later, refresh the token
client.set_token(access_token, refresh_token)

# SDK will automatically handle token refresh on 401 errors
orgs = client.orgs.list()  # Works even with expired token
```

### Audit Logging

```python
# Get audit logs for organization
logs = client.audit.get_logs(
    org_id="org-uuid",
    limit=50,
    offset=0
)

for log in logs:
    print(f"{log.action} by {log.actor_email} at {log.created_at}")
```

### Feature Flags

```python
# List feature flags for organization
flags = client.orgs.list_feature_flags(org_id)

for flag in flags:
    print(f"{flag.name}: {'Enabled' if flag.enabled else 'Disabled'}")

# Toggle feature flag
client.orgs.set_feature_flag(
    org_id=org_id,
    flag_key="beta-new-ui",
    enabled=True,
    rollout_percent=50  # Gradual rollout
)
```

### Update Member Roles

```python
# Get organization members
members = client.orgs.list_members(org_id)

# Find member to update
member = next(m for m in members if m.user_email == "user@company.com")

# Get available roles
roles = client.orgs.list_roles(org_id)
new_role = next(r for r in roles if r.name == "owner")

# Update role
updated_member = client.orgs.update_member_role(
    org_id=org_id,
    membership_id=member.id,
    role_id=new_role.id
)

print(f"Updated {member.user_email} to {new_role.name}")
```

---

## 🔧 **Advanced Configuration**

### Custom Timeout and Retries

```python
client = SaaSReady(
    base_url="https://api.yourdomain.com",
    timeout=60.0,         # 60 second timeout
    max_retries=5,        # Retry up to 5 times
    verify_ssl=True       # SSL verification (default: True)
)
```

### API Key Authentication

```python
# For service-to-service authentication
client = SaaSReady(
    base_url="https://api.yourdomain.com",
    api_key="sk_live_your_api_key_here"
)

# No need to login - API key is used automatically
orgs = client.orgs.list()
```

### Custom Headers

```python
# Add custom headers to all requests
client._http.session.headers.update({
    "X-Custom-Header": "value",
    "X-Request-ID": "unique-id-123"
})
```

---

## 🧪 **Testing**

### Mock Responses

```python
import responses
from saasready import SaaSReady

@responses.activate
def test_login():
    # Mock the login endpoint
    responses.add(
        responses.POST,
        "https://api.test.com/api/v1/auth/login",
        json={"access_token": "test-token", "token_type": "bearer"},
        status=200
    )
    
    client = SaaSReady(base_url="https://api.test.com")
    response = client.auth.login("test@example.com", "password")
    
    assert response.access_token == "test-token"
```

### Pytest Fixtures

```python
import pytest
from saasready import SaaSReady

@pytest.fixture
def client():
    """Create test client"""
    return SaaSReady(
        base_url="https://api.test.com",
        timeout=5.0
    )

@pytest.fixture
def authenticated_client(client):
    """Create authenticated test client"""
    client.set_token("test-access-token")
    return client

def test_list_orgs(authenticated_client):
    orgs = authenticated_client.orgs.list()
    assert isinstance(orgs, list)
```

---

## 📚 **API Reference**

### Authentication (`client.auth`)

| Method | Description |
|--------|-------------|
| `register(email, password, full_name)` | Register new user |
| `login(email, password, two_factor_code=None)` | Login user |
| `me()` | Get current user profile |
| `logout()` | Logout current user |
| `request_password_reset(email)` | Request password reset |
| `confirm_password_reset(token, new_password)` | Confirm password reset |
| `verify_email(token)` | Verify email address |
| `resend_verification(email)` | Resend verification email |
| `setup_2fa()` | Setup two-factor authentication |
| `verify_2fa(code)` | Verify and activate 2FA |
| `disable_2fa(password)` | Disable 2FA |

### Organizations (`client.orgs`)

| Method | Description |
|--------|-------------|
| `create(name, slug, description=None)` | Create organization |
| `list()` | List user's organizations |
| `update(org_id, name=None, description=None)` | Update organization |
| `list_members(org_id)` | List organization members |
| `list_roles(org_id)` | List available roles |
| `invite_member(org_id, email, role_id, full_name=None)` | Invite member |
| `update_member_role(org_id, membership_id, role_id)` | Update member role |
| `list_feature_flags(org_id)` | List feature flags |
| `set_feature_flag(org_id, flag_key, enabled, rollout_percent=None)` | Set flag |
| `delete_feature_flag(org_id, flag_key)` | Delete flag override |

### Users (`client.users`)

| Method | Description |
|--------|-------------|
| `me()` | Get current user profile |
| `remove_member(org_id, member_id)` | Remove organization member |

### Audit Logs (`client.audit`)

| Method | Description |
|--------|-------------|
| `get_logs(org_id, limit=100, offset=0)` | Get organization audit logs |

### Feature Flags (`client.flags`)

| Method | Description |
|--------|-------------|
| `create_global(key, name, description=None, default_enabled=False)` | Create global flag (admin) |
| `list_global()` | List all global flags (admin) |
| `is_enabled(org_id, flag_key)` | Check if flag is enabled |

---

## 🔒 **Security Best Practices**

### 1. Store Tokens Securely

```python
import os
from saasready import SaaSReady

# Never hardcode tokens
client = SaaSReady(
    base_url=os.getenv("SAASREADY_BASE_URL"),
    api_key=os.getenv("SAASREADY_API_KEY")  # From environment
)
```

### 2. Use HTTPS in Production

```python
# Always use HTTPS in production
client = SaaSReady(
    base_url="https://api.yourdomain.com",  # HTTPS
    verify_ssl=True  # Verify SSL certificates
)
```

### 3. Handle Token Expiry

```python
from saasready import AuthenticationError

try:
    orgs = client.orgs.list()
except AuthenticationError:
    # Token expired - refresh or re-login
    response = client.auth.login(email, password)
    client.set_token(response.access_token)
    orgs = client.orgs.list()
```

### 4. Rate Limiting

```python
from saasready import RateLimitError
import time

def safe_api_call(func, *args, **kwargs):
    """Wrapper with rate limit handling"""
    try:
        return func(*args, **kwargs)
    except RateLimitError as e:
        if e.retry_after:
            time.sleep(e.retry_after)
            return func(*args, **kwargs)
        raise
```

---

## 🐛 **Troubleshooting**

### "No authentication token set"

```python
# Solution: Set token before making authenticated requests
client.set_token(access_token)
```

### Connection Timeout

```python
# Increase timeout for slow networks
client = SaaSReady(base_url="...", timeout=60.0)
```

### SSL Certificate Verification Failed

```python
# For development only - disable SSL verification
client = SaaSReady(base_url="...", verify_ssl=False)
```

### Rate Limit Exceeded

```python
# Respect retry_after header
try:
    response = client.auth.login(email, password)
except RateLimitError as e:
    time.sleep(e.retry_after)
    response = client.auth.login(email, password)
```

---

## 🤝 **Contributing**

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone repository
git clone https://github.com/ramprag/saasready.git
cd saasready

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black .
isort .

# Type check
mypy saasready
```

---

## 📄 **License**

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🔗 **Links**

- **Documentation**: https://docs.saasready.com
- **GitHub**: https://github.com/ramprag/saasready
- **PyPI**: https://pypi.org/project/saasready/
- **Issues**: https://github.com/ramprag/saasready/issues
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

## 📞 **Support**

- 📧 Email: support@saasready.com
- 💬 GitHub Discussions: https://github.com/ramprag/saasready/discussions
- 🐛 Report Bug: https://github.com/ramprag/saasready/issues

---

**Made with ❤️ for the SaaS community**