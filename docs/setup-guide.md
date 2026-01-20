# Setup Guide

Complete configuration guide for SaaSReady platform.

---

## Environment Configuration

### Backend Configuration

Create `.env` at repo root from the example (docker-compose reads from here):

```bash
cp backend/.env.example .env
```

#### Required Variables

```env
# Database (Required)
DATABASE_URL=postgresql://user:password@host:5432/saasready

# Security (Required - MUST CHANGE)
# Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(64))"
SECRET_KEY=<your-generated-secret-key>
ALGORITHM=HS256

# Frontend URL (Required for email links)
FRONTEND_BASE_URL=http://localhost:3000
```

#### Optional Variables

```env
# Token Expiry (Recommended to configure)
ACCESS_TOKEN_EXPIRE_MINUTES=60   # Default: 60 (1 hour)
REFRESH_TOKEN_EXPIRE_DAYS=30     # Default: 30 days

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_LOGIN=5               # Per minute
RATE_LIMIT_REGISTER=3            # Per minute

# Brute Force Protection
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_MINUTES=30

# Redis (Recommended for production)
REDIS_URL=redis://:password@localhost:6379/0
```

> [!TIP]
> Configure `ACCESS_TOKEN_EXPIRE_MINUTES` and `REFRESH_TOKEN_EXPIRE_DAYS` based on your security requirements. Shorter token lifetimes are more secure but require more frequent re-authentication.

### Frontend Configuration

Create `frontend/.env.local`:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

---

## Email Service Setup

Email is required for invitations, password resets, and verification.

### Supported Providers

| Provider | Difficulty | Best For |
|----------|------------|----------|
| SendGrid | Easy | Most users |
| AWS SES | Medium | AWS users |
| Custom SMTP | Varies | Self-hosted |

### SendGrid Setup

1. Sign up at [sendgrid.com](https://sendgrid.com)
2. Create API Key with "Mail Send" permission
3. Configure:

```env
EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=apikey
EMAIL_SMTP_PASSWORD=SG.your-api-key-here
EMAIL_FROM=noreply@yourdomain.com
EMAIL_USE_TLS=true
```

### AWS SES Setup

```env
EMAIL_SMTP_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=<your-smtp-username>
EMAIL_SMTP_PASSWORD=<your-smtp-password>
EMAIL_FROM=noreply@yourdomain.com
EMAIL_USE_TLS=true
```

### Testing Email

```python
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

## Database Setup

### PostgreSQL

SaaSReady requires PostgreSQL 13+.

#### Local Development (Docker)

```bash
docker run -d \
  --name saasready-postgres \
  -e POSTGRES_USER=saasready \
  -e POSTGRES_PASSWORD=your-password \
  -e POSTGRES_DB=saasready \
  -p 5432:5432 \
  postgres:15-alpine
```

#### Managed PostgreSQL (Production)

Recommended providers:
- **AWS RDS**
- **DigitalOcean Managed Databases**
- **Supabase**
- **Railway**

Connection string format:
```env
DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
```

### Database Migrations

SaaSReady uses Alembic for migrations.

```bash
cd backend

# Run all pending migrations
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

## Redis Setup

Redis is used for:
- Distributed rate limiting
- Session management
- Email queue

### Local Development

```bash
# Docker
docker run -d \
  --name saasready-redis \
  -p 6379:6379 \
  redis:7-alpine redis-server --requirepass your-password
```

### Managed Redis (Production)

Recommended providers:
- **AWS ElastiCache**
- **Redis Cloud**
- **DigitalOcean Managed Redis**
- **Upstash** (serverless)

Configuration:
```env
REDIS_URL=redis://:password@your-redis-host:6379/0
```

### Fallback Behavior

If Redis is unavailable, SaaSReady falls back to:
- In-memory rate limiting (not distributed)
- Synchronous email sending

> ⚠️ For production, always use Redis.

---

## Docker Compose Setup

### Development

```bash
# Start all services
docker-compose up --build

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down
```

### Services Started

| Service | Port | Description |
|---------|------|-------------|
| frontend | 3000 | Next.js admin UI |
| backend | 8000 | FastAPI server |
| worker | - | Background task processor |
| db | 5432 | PostgreSQL |
| redis | 6379 | Redis cache |

---

## Verification Steps

After setup, verify everything works:

### 1. Check Backend Health

```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

### 2. Check API Docs

Open http://localhost:8000/docs in browser.

### 3. Test Registration

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "Test123!", "full_name": "Test User"}'
```

### 4. Check Frontend

Open http://localhost:3000 and try to register.

---

## Next Steps

- [API Reference](./api-reference.md) - Complete API documentation
- [Features Guide](./features.md) - 2FA, sessions, email verification
- [Deployment Guide](./deployment.md) - Production deployment
