# 🚀 SaaSReady - Enterprise-Grade Multi-Tenant Auth Platform

> **Drop-in authentication infrastructure for B2B SaaS applications**  
> Similar to Auth0, WorkOS, or Clerk, but **self-hosted** and **fully customizable**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)

---

## 📖 **Table of Contents**

- [Why SaaSReady?](#why-saasready)
- [Features](#features)
- [Quick Start (5 Minutes)](#quick-start)
- [Architecture](#architecture)
- [Complete Setup Guide](#complete-setup-guide)
- [API Documentation](#api-documentation)
- [Security & Best Practices](#security)
- [Production Deployment](#production-deployment)
- [Python SDK](#python-sdk)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## 🎯 **Why SaaSReady?**

Building multi-tenant B2B SaaS requires:
- ✅ User authentication with JWT
- ✅ Organization/workspace isolation
- ✅ Role-based permissions (RBAC)
- ✅ Team member invitations
- ✅ Audit logging for compliance
- ✅ Feature flags for gradual rollouts

**SaaSReady gives you all of this out of the box** - no vendor lock-in, full control over your data.

### **Comparison to Auth Providers**

| Feature | SaaSReady | Auth0 | WorkOS | Clerk |
|---------|-----------|-------|--------|-------|
| **Self-Hosted** | ✅ | ❌ | ❌ | ❌ |
| **Multi-Tenancy (Orgs)** | ✅ | ✅ | ✅ | ✅ |
| **RBAC with Permissions** | ✅ | ✅ | ✅ | ✅ |
| **Audit Logs** | ✅ | ✅ | ✅ | ✅ |
| **Feature Flags** | ✅ | ❌ | ❌ | ❌ |
| **Email Invitations** | ✅ | ✅ | ✅ | ✅ |
| **2FA/MFA** | ✅ | ✅ | ✅ | ✅ |
| **Admin UI** | ✅ | ✅ | ✅ | ✅ |
| **Python SDK** | ✅ | ✅ | ✅ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ | ❌ |
| **Cost** | **$0** | Paid | Paid | Paid |

---

## ⚡ **Features**

### **Authentication & Security**
- 🔐 **JWT-Based Auth** - Secure token-based authentication with refresh tokens
- 🛡️ **Token Revocation** - Instant logout across all devices
- 🔒 **Brute Force Protection** - Progressive delays + account lockouts
- 📱 **2FA/TOTP Support** - Time-based one-time passwords with backup codes
- 🎭 **Device Fingerprinting** - Track suspicious login patterns
- 📊 **Security Analytics** - Risk scoring and anomaly detection

### **Multi-Tenancy**
- 🏢 **Organizations** - Workspace isolation with unique slugs
- 👥 **Team Management** - Invite members with role assignment
- 📧 **Email Invitations** - Async queue with retry mechanism
- ✉️ **SMTP Integration** - SendGrid/AWS SES/Custom SMTP support
- 🔄 **Automatic Onboarding** - Pre-login invitation acceptance

### **Authorization (RBAC)**
- 🎭 **Pre-Built Roles** - Owner, Admin, Member, Viewer
- 🔑 **Granular Permissions** - 15+ permission types
- 🛡️ **Endpoint Protection** - Decorator-based permission checks
- 📊 **Role Hierarchy** - Prevent privilege escalation
- 🎯 **Custom Roles** - Create organization-specific roles

### **Compliance & Auditing**
- 📝 **Audit Logs** - Track all user actions with metadata
- 🌍 **IP + User Agent Logging** - Full request context
- 📊 **Queryable Logs** - Pagination + filtering support
- 🔍 **90-Day Retention** - Automatic cleanup (configurable)

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

## 🚀 **Quick Start (5 Minutes)**

### **Prerequisites**
- Docker & Docker Compose
- Git

### **Step 1: Clone & Setup**

```bash
git clone https://github.com/yourusername/saasready.git
cd saasready

# Copy environment files
cp backend/.env.example backend/.env
cp frontend/.env.local.example frontend/.env.local
```

### **Step 2: Generate Secure Keys**

```bash
# Generate SECRET_KEY (must be 32+ characters)
python3 -c "import secrets; print(secrets.token_urlsafe(64))"

# Copy output to backend/.env:
# SECRET_KEY=<your-generated-key>
```

### **Step 3: Start Services**

```bash
docker-compose up --build
```

**Services will be available at:**
- 🌐 **Frontend**: http://localhost:3000
- 🔌 **Backend API**: http://localhost:8000
- 📚 **API Docs**: http://localhost:8000/docs
- 🐘 **PostgreSQL**: localhost:5432
- 🔴 **Redis**: localhost:6379

### **Step 4: Create Your First Account**

1. Visit http://localhost:3000/register
2. Sign up with email/password
3. You'll auto-login and see your personal organization

**🎉 That's it! You now have:**
- ✅ Personal organization (you're the Owner)
- ✅ JWT authentication working
- ✅ RBAC with full permissions
- ✅ Audit logging enabled
- ✅ Feature flags system ready

---

## 🏗️ **Architecture**

### **System Overview**

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

### **Authentication Flow**

```
┌────────┐                                    ┌────────┐
│ Client │                                    │  API   │
└───┬────┘                                    └───┬────┘
    │                                             │
    │  POST /auth/login                           │
    │  {email, password, 2fa_code?}              │
    │────────────────────────────────────────────>│
    │                                             │
    │         1. Validate Credentials             │
    │         2. Check Brute Force                │
    │         3. Verify 2FA (if enabled)          │
    │         4. Generate JWT + Session           │
    │                                             │
    │  200 OK                                     │
    │  {access_token, refresh_token}             │
    │<────────────────────────────────────────────│
    │                                             │
    │  Store tokens                               │
    │                                             │
    │  GET /orgs (with JWT)                       │
    │  Authorization: Bearer <token>              │
    │────────────────────────────────────────────>│
    │                                             │
    │         1. Decode JWT                       │
    │         2. Check token_blacklist            │
    │         3. Load user + permissions          │
    │         4. Authorize request                │
    │                                             │
    │  200 OK                                     │
    │  [organizations]                            │
    │<────────────────────────────────────────────│
```

### **Data Model**

```
User ──1:N──> Membership ──N:1──> Organization
                │                      │
                │                      │
                ▼                      ▼
              Role               OrgSettings
                │
                │
                ▼
           Permission
```

### **Permission Matrix**

| Role | org.* | user.invite | user.manage | audit.read | api_key.manage |
|------|-------|-------------|-------------|------------|----------------|
| **Owner** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Admin** | ✅ (read/update) | ✅ | ✅ | ✅ | ❌ |
| **Member** | ✅ (read only) | ❌ | ❌ | ✅ | ❌ |
| **Viewer** | ✅ (read only) | ❌ | ❌ | ❌ | ❌ |

---

## 📚 **Complete Setup Guide**

### **Environment Configuration**

#### **Backend (.env)**

```bash
# Database (Required)
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Security (Required - CHANGE THIS!)
SECRET_KEY=<generate-with-command-below>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080  # 7 days

# Frontend URL
FRONTEND_BASE_URL=http://localhost:3000

# Redis (Optional but recommended for production)
REDIS_URL=redis://:password@localhost:6379/0

# Email Service (Required for invitations)
EMAIL_FROM=noreply@yourdomain.com
EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=apikey
EMAIL_SMTP_PASSWORD=<your-sendgrid-api-key>
EMAIL_USE_TLS=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_LOGIN=5
RATE_LIMIT_REGISTER=3

# Brute Force Protection
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_MINUTES=30
```

#### **Generate SECRET_KEY**

```bash
# Option 1: Python
python3 -c "import secrets; print(secrets.token_urlsafe(64))"

# Option 2: OpenSSL
openssl rand -base64 64 | tr -d '\n'

# Option 3: Using the app
cd backend
python -c "from app.core.config import generate_secret_key; print(generate_secret_key())"
```

#### **Frontend (.env.local)**

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

---

### **Email Service Setup**

SaaSReady has a **production-ready email service** with async queue and retry mechanism.

#### **Supported Providers**

1. **SendGrid** (Recommended)
2. **AWS SES**
3. **Custom SMTP**

#### **SendGrid Setup**

```bash
# 1. Sign up at https://sendgrid.com
# 2. Create API Key with "Mail Send" permission
# 3. Add to backend/.env:

EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=apikey
EMAIL_SMTP_PASSWORD=SG.your-api-key-here
EMAIL_FROM=noreply@yourdomain.com
```

#### **AWS SES Setup**

```bash
EMAIL_SMTP_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=<your-smtp-username>
EMAIL_SMTP_PASSWORD=<your-smtp-password>
EMAIL_FROM=noreply@yourdomain.com
```

#### **Testing Email Service**

```bash
# From backend directory
python3 << EOF
from app.services.email_service import email_service
import asyncio

async def test():
    await email_service.send_verification_email(
        to_email="test@example.com",
        verify_link="https://app.example.com/verify?token=test"
    )
    print("✅ Email queued successfully")

asyncio.run(test())
EOF
```

---

### **Database Migrations**

SaaSReady uses **Alembic** for database migrations.

```bash
cd backend

# Run all migrations
alembic upgrade head

# Check current version
alembic current

# View migration history
alembic history

# Create new migration (after model changes)
alembic revision --autogenerate -m "Add new table"

# Rollback last migration
alembic downgrade -1
```

---

### **Redis Setup (Production)**

Redis is used for:
- Rate limiting (distributed)
- Session management
- Email queue

#### **Local Redis**

```bash
# Using Docker
docker run -d --name redis \
  -p 6379:6379 \
  redis:7-alpine redis-server --requirepass your-password

# Using Homebrew (Mac)
brew install redis
redis-server
```

#### **Managed Redis (Production)**

- **AWS ElastiCache**
- **Redis Cloud**
- **DigitalOcean Managed Redis**

```bash
# Update backend/.env
REDIS_URL=redis://:password@your-redis-host:6379/0
```

---

## 📖 **API Documentation**

### **Authentication**

#### **Register User**

```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}

# Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 604800
}
```

#### **Login**

```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "two_factor_code": "123456"  # Optional, only if 2FA enabled
}

# Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 604800,
  "requires_2fa": false
}
```

#### **Get Current User**

```bash
GET /api/v1/auth/me
Authorization: Bearer <token>

# Response
{
  "id": "uuid",
  "email": "user@example.com",
  "full_name": "John Doe",
  "is_active": true,
  "is_email_verified": true,
  "created_at": "2025-01-20T10:30:00Z"
}
```

### **Organizations**

#### **Create Organization**

```bash
POST /api/v1/orgs
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Acme Corp",
  "slug": "acme-corp",
  "description": "Our main workspace"
}

# Response
{
  "id": "org-uuid",
  "name": "Acme Corp",
  "slug": "acme-corp",
  "description": "Our main workspace",
  "is_active": true,
  "created_at": "2025-01-20T10:30:00Z"
}
```

#### **Invite Member**

```bash
POST /api/v1/orgs/{org_id}/invite
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "newuser@example.com",
  "role_id": "role-uuid",
  "full_name": "Jane Smith"
}

# Response
{
  "id": "membership-uuid",
  "user_id": "user-uuid",
  "organization_id": "org-uuid",
  "role_id": "role-uuid",
  "status": "invited",
  "invited_email": "newuser@example.com",
  "invitation_expires_at": "2025-01-27T10:30:00Z"
}
```

**📧 Email Sent Automatically:**
- ✅ Invitation email queued with retry mechanism
- ✅ Contains unique invitation link
- ✅ Expires in 7 days
- ✅ Works for existing AND new users

---

### **Full API Reference**

Visit http://localhost:8000/docs for **interactive API documentation** (Swagger UI).

---

## 🐍 **Python SDK**

### **Installation**

```bash
pip install saasready
```

### **Quick Start**

```python
from saasready import SaaSReady

# Initialize client
client = SaaSReady(
    base_url="https://api.yourdomain.com",
    timeout=30.0
)

# Register user
response = client.auth.register(
    email="user@example.com",
    password="SecurePassword123!",
    full_name="John Doe"
)

# Auto-authenticated after register
print(f"Token: {response.access_token}")

# List organizations
orgs = client.orgs.list()

# Invite team member
admin_role = client.orgs.list_roles(org.id)[0]
membership = client.orgs.invite_member(
    org_id=org.id,
    email="newuser@example.com",
    role_id=admin_role.id,
    full_name="Jane Smith"
)
```

### **Error Handling**

```python
from saasready import (
    AuthenticationError,
    AuthorizationError,
    RateLimitError
)

try:
    response = client.auth.login("user@example.com", "wrong-password")
except AuthenticationError as e:
    print(f"Login failed: {e.message}")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
```

**📚 [Complete SDK Documentation](./SDK_README.md)**

---

## 🔒 **Security & Best Practices**

### **What's Included**

✅ **JWT with Revocation** - Instant logout across all devices  
✅ **Argon2 Password Hashing** - No 72-byte bcrypt limit  
✅ **Brute Force Protection** - Progressive delays + lockouts  
✅ **2FA/TOTP Support** - Time-based one-time passwords  
✅ **Device Fingerprinting** - Track suspicious patterns  
✅ **Rate Limiting** - Redis-backed distributed limiting  
✅ **CORS Protection** - Configurable origins  
✅ **SQL Injection Prevention** - SQLAlchemy ORM  
✅ **Audit Logging** - Track all security events

### **Production Checklist**

#### **Before Deploying:**

```bash
# 1. Change SECRET_KEY
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")

# 2. Use managed PostgreSQL
DATABASE_URL=postgresql://user:pass@production-host:5432/saasready

# 3. Use managed Redis
REDIS_URL=redis://:password@production-redis:6379/0

# 4. Configure email service
EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PASSWORD=<production-api-key>

# 5. Enable HTTPS
FRONTEND_BASE_URL=https://app.yourdomain.com

# 6. Set proper CORS
# Edit backend/app/main.py
allow_origins=["https://app.yourdomain.com"]
```

#### **Security Headers**

Already configured in `SecurityHeadersMiddleware`:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`

#### **Token Storage**

⚠️ **Current**: Tokens stored in `localStorage`  
✅ **Recommended**: Use `httpOnly` cookies for production

```typescript
// frontend/lib/api.ts
// TODO: Update to use httpOnly cookies instead of localStorage
```

---

## 🚢 **Production Deployment**

### **Docker Deployment (Recommended)**

```bash
# 1. Update environment files
cp backend/.env.production.example backend/.env
cp frontend/.env.production.example frontend/.env.local

# 2. Build images
docker-compose -f docker-compose.prod.yml build

# 3. Start services
docker-compose -f docker-compose.prod.yml up -d

# 4. Run migrations
docker-compose exec backend alembic upgrade head

# 5. Check logs
docker-compose logs -f backend
```

### **Manual Deployment**

#### **Backend**

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start with Gunicorn (production WSGI)
gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
```

#### **Frontend**

```bash
cd frontend

# Install dependencies
npm ci

# Build
npm run build

# Start production server
npm start
```

### **Hosting Options**

- **AWS**: EC2 + RDS + ElastiCache
- **DigitalOcean**: App Platform + Managed Postgres
- **Railway**: One-click deploy
- **Render**: Auto-deploy from GitHub
- **Heroku**: Container deployment

---

## 🐛 **Troubleshooting**

### **"Organization not found" after registration**

**Cause**: Database transaction timing  
**Fix**: Refresh page or navigate to `/orgs`

### **"Failed to invite user"**

**Check**:
1. User has `user.invite` permission ✅
2. Role ID exists (call `GET /orgs/{org_id}/roles`) ✅
3. Email is valid ✅
4. Email service configured ✅

```bash
# Test email service
docker-compose logs backend | grep "Email"
```

### **"403 Forbidden" on protected endpoints**

**Cause**: Missing permissions  
**Fix**: Check user's role has required permission

```bash
# View permissions for role
GET /api/v1/orgs/{org_id}/roles
```

### **Database connection errors**

```bash
# Check PostgreSQL
docker-compose ps db

# View logs
docker-compose logs db

# Restart
docker-compose restart db
```

### **Frontend can't connect to backend**

**Check**:
1. `NEXT_PUBLIC_API_URL` in `frontend/.env.local`
2. Backend is running on port 8000
3. CORS is configured correctly

---

## 🤝 **Contributing**

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick Start:**
```bash
# Fork the repo
git clone https://github.com/yourusername/saasready.git
cd saasready

# Create feature branch
git checkout -b feature/my-feature

# Make changes and test
docker-compose up --build

# Commit
git commit -m "feat: add my feature"

# Push and create PR
git push origin feature/my-feature
```

---

## 📄 **License**

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) - SQL toolkit
- [PostgreSQL](https://www.postgresql.org/) - Database
- [Next.js](https://nextjs.org/) - React framework
- [Tailwind CSS](https://tailwindcss.com/) - CSS framework
- [Redis](https://redis.io/) - Caching & rate limiting

Inspired by [Auth0](https://auth0.com/), [WorkOS](https://workos.com/), and [Clerk](https://clerk.com/).

---

## 📞 **Support & Community**

- 📖 **Documentation**: https://docs.saasready.com
- 💬 **Discord**: https://discord.gg/saasready
- 🐛 **Report Bug**: [GitHub Issues](https://github.com/yourusername/saasready/issues)
- 💡 **Request Feature**: [GitHub Discussions](https://github.com/yourusername/saasready/discussions)
- 📧 **Email**: support@saasready.com

---

**⭐ Star us on GitHub if SaaSReady helped you!**

Made with ❤️ for the SaaS community