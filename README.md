# 🚀 SaaSReady - Enterprise-Grade Multi-Tenant Auth Platform

> **Open-source alternative to Auth0, WorkOS, and Clerk**  
> Drop-in authentication infrastructure for B2B SaaS applications - **self-hosted**, **fully customizable**, and **free**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)
[![SDK Version](https://img.shields.io/badge/SDK-v1.0.0-orange.svg)](SDK_README.md)

---

## 📖 Table of Contents

- [Why SaaSReady?](#-why-saasready)
- [Features](#-features)
- [Quick Start](#-quick-start-5-minutes)
- [Python SDK](#-python-sdk)
- [Migration](#-migration-from-other-providers)
- [Architecture](#-architecture)
- [Documentation](#-documentation)
- [Contributing](#-contributing)

---

## 🎯 Why SaaSReady?

Building multi-tenant B2B SaaS requires authentication, organizations, RBAC, invitations, and audit logs. **SaaSReady gives you all of this out of the box** — no vendor lock-in, full control over your data.

### Comparison to Auth Providers

| Feature | SaaSReady | Auth0 | WorkOS | Clerk |
|---------|-----------|-------|--------|-------|
| **Self-Hosted** | ✅ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ | ❌ |
| **Multi-Tenancy (Orgs)** | ✅ | ✅ | ✅ | ✅ |
| **RBAC with Permissions** | ✅ | ✅ | ✅ | ✅ |
| **Audit Logs** | ✅ | ✅ | ✅ | ✅ |
| **Email/Password Auth** | ✅ | ✅ | ✅ | ✅ |
| **2FA (TOTP)** | ✅ | ✅ | ✅ | ✅ |
| **Admin UI** | ✅ | ✅ | ✅ | ✅ |
| **Python SDK** | ✅ | ✅ | ✅ | ❌ |
| **Feature Flags** | ✅ | ❌ | ❌ | ❌ |
| **Social Login** | 🔜 | ✅ | ✅ | ✅ |
| **SSO/SAML** | 🔜 | ✅ | ✅ | ✅ |
| **Cost** | **$0** | Paid | Paid | Paid |

> **Note**: SaaSReady provides 2FA via TOTP. Social login and SSO are on the roadmap.

---

## ⚡ Features

### Authentication & Security
- 🔐 JWT-based auth with refresh tokens
- 🛡️ Token revocation (instant logout)
- 🔒 Brute force protection with lockouts
- 📱 2FA/TOTP with backup codes
- 🎭 Device fingerprinting
- 📊 **Security Analytics** - Risk scoring and anomaly detection


### Multi-Tenancy
- 🏢 Organizations with unique slugs
- 👥 Team member invitations with role assignment
- 📧 Async email queue with retry
- 🔄 **Automatic Onboarding** - Pre-login invitation acceptance


### Authorization (RBAC)
- 🎭 Pre-built roles: Owner, Admin, Member, Viewer
- 🔑 15+ granular permissions
- 🛡️ Privilege escalation prevention
- 🛡️ **Endpoint Protection** - Decorator-based permission checks
- 📊 **Role Hierarchy** - Prevent privilege escalation
- 🎯 **Custom Roles** - Create organization-specific roles


### **Feature Management**
- 🎯 **Feature Flags** - Global + organization-level overrides
- 📊 **Percentage Rollouts** - A/B testing support
- 🔄 **Runtime Toggles** - No code deployments needed

### **Developer Experience**
- 📚 **Python SDK** - Type-safe client library
- 🔌 **REST API** - Comprehensive OpenAPI docs
- 🐳 **Docker-Ready** - One-command deployment
- ⚡ **Production-Grade** - Connection pooling, rate limiting, caching

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Docker & Docker Compose
- Git

### 1. Clone and Configure

```bash
git clone https://github.com/ramprag/saasready.git
cd saasready

# Copy environment file to root (docker-compose reads from here)
cp backend/.env.example .env

# Generate secure secret key
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# Add output to SECRET_KEY in .env
```

### 2. Start Services

```bash
docker-compose up --build
```

### 3. Access

| Service | URL |
|---------|-----|
| **Frontend** | http://localhost:3000 |
| **API Docs** | http://localhost:8000/docs |
| **ReDoc** | http://localhost:8000/redoc |
| **PostgreSQL** | http://localhost:5432 |
| **Redis** | http://localhost:6379 |

### 4. Try It

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "Test123!", "full_name": "Test User"}'
```

**🎉 That's it! You now have:**
- ✅ Personal organization (you're the Owner)
- ✅ JWT authentication working
- ✅ RBAC with full permissions
- ✅ Audit logging enabled
- ✅ Feature flags system ready


---

## 🐍 Python SDK

```bash
pip install saasready
```

```python
from saasready import SaaSReady

# Initialize
client = SaaSReady(base_url="https://your-instance.com")

# Login
response = client.auth.login("user@example.com", "password")

# Tokens auto-stored, make authenticated requests
user = client.auth.me()
orgs = client.orgs.list()

# Create organization
org = client.orgs.create("Acme Corp", "acme-corp")

# Invite member
roles = client.orgs.list_roles(org.id)
client.orgs.invite_member(
    org_id=org.id,
    email="teammate@example.com",
    role_id=roles[1].id  # admin role
)
```

**📚 [Complete SDK Documentation →](SDK_README.md)**

---

## ⏱️ Integration Time

| Scenario | Time | Guide |
|----------|------|-------|
| **New project** (Docker) | 5-10 min | [Quick Start](#-quick-start-5-minutes) |
| **Existing Python app** | 5-10 min | [Framework Examples](docs/framework-examples.md) |
| **Migration from Auth0** | 10-15 min | [Auth0 Guide](docs/migration/from-auth0.md) |
| **Migration from WorkOS** | 10-15 min | [WorkOS Guide](docs/migration/from-workos.md) |
| **Migration from Clerk** | 10-15 min | [Clerk Guide](docs/migration/from-clerk.md) |
| **Migration from Firebase** | 1-2 hours | [Firebase Guide](docs/migration/from-firebase.md) |

---

## 🔄 Migration from Other Providers

SaaSReady uses familiar patterns — usually just a 1-line SDK swap:

```python
# Before (Auth0 / WorkOS / Clerk)
from auth0 import Auth0Client
client = Auth0Client(domain="...", client_id="...")

# After (SaaSReady)
from saasready import SaaSReady
client = SaaSReady(base_url="https://your-instance.com")
```

**📚 [Full Migration Guides →](docs/migration/)**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLIENT APPLICATIONS                      │
│  (Web App, Mobile App, API Consumers)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │ REST API (JWT)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   SAASREADY PLATFORM                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Frontend   │  │   Backend    │  │   Worker     │     │
│  │   Next.js    │  │   FastAPI    │  │  Background  │     │
│  │  Port 3000   │  │  Port 8000   │  │    Tasks     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────┬───────────────────────┬───────────────┘
                      │                       │
        ┌─────────────┴─────────┐    ┌───────┴────────┐
        ▼                       ▼    ▼                │
┌──────────────┐      ┌──────────────┐     ┌──────────────┐
│  PostgreSQL  │      │    Redis     │     │ SMTP Service │
│   Database   │      │   Cache +    │     │  (SendGrid/  │
│  Port 5432   │      │ Rate Limit   │     │   AWS SES)   │
└──────────────┘      └──────────────┘     └──────────────┘
```

**📚 [Full Architecture →](docs/Architecture.md)**


### Permission Matrix

| Role | org.* | user.invite | user.manage | audit.read | api_key.manage |
|------|-------|-------------|-------------|------------|----------------|
| **Owner** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Admin** | ✅ (read/update) | ✅ | ✅ | ✅ | ❌ |
| **Member** | ✅ (read only) | ❌ | ❌ | ✅ | ❌ |
| **Viewer** | ✅ (read only) | ❌ | ❌ | ❌ | ❌ |


---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [**Comparisons**](docs/comparisons/) | Compare with Auth0, WorkOS, Clerk, Firebase |
| [**Setup Guide**](docs/setup-guide.md) | Environment, email, database, Redis |
| [**API Reference**](docs/api-reference.md) | All endpoints with examples |
| [**Features Guide**](docs/features.md) | 2FA, sessions, email verification |
| [**Framework Examples**](docs/framework-examples.md) | FastAPI, Django, Flask |
| [**Deployment**](docs/deployment.md) | Production deployment guide |
| [**Troubleshooting**](docs/troubleshooting.md) | Common issues and fixes |
| [**Security**](SECURITY.md) | Security policy and best practices |
| [**SDK Reference**](SDK_README.md) | Complete Python SDK docs |

### Interactive API Docs

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Quick start
git clone https://github.com/ramprag/saasready.git
git checkout -b feature/my-feature
docker-compose up --build
# Make changes, test, commit, push
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## 🙏 Acknowledgments

Built with [FastAPI](https://fastapi.tiangolo.com/), [SQLAlchemy](https://www.sqlalchemy.org/), [PostgreSQL](https://www.postgresql.org/), [Next.js](https://nextjs.org/), [Redis](https://redis.io/).

Inspired by [Auth0](https://auth0.com/), [WorkOS](https://workos.com/), and [Clerk](https://clerk.com/).

---

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Report Bug](https://github.com/ramprag/saasready/issues)
- 💡 [Request Feature](https://github.com/ramprag/saasready/discussions)
- 📧 Email: support@saasready.com

---

**⭐ Star us on GitHub if SaaSReady helped you!**