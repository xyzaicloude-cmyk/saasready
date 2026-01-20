# Production Deployment

Guide for deploying SaaSReady to production environments.

---

## Pre-Deployment Checklist

Before deploying, ensure you have:

- [ ] Generated unique `SECRET_KEY` (64+ characters)
- [ ] Configured managed PostgreSQL
- [ ] Configured managed Redis
- [ ] Set up email service (SendGrid/SES)
- [ ] Configured HTTPS domain
- [ ] Set proper CORS origins
- [ ] Tested locally with production-like config

---

## Environment Variables (Production)

```env
# Security
SECRET_KEY=<64-char-generated-key>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=30

# Database
DATABASE_URL=postgresql://user:pass@production-db:5432/saasready?sslmode=require

# Redis
REDIS_URL=redis://:password@production-redis:6379/0

# Frontend
FRONTEND_BASE_URL=https://app.yourdomain.com

# Email
EMAIL_SMTP_HOST=smtp.sendgrid.net
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=apikey
EMAIL_SMTP_PASSWORD=<production-api-key>
EMAIL_FROM=noreply@yourdomain.com
EMAIL_USE_TLS=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_LOGIN=5
RATE_LIMIT_REGISTER=3

# Brute Force
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_MINUTES=30
```

---

## Deployment Options

### Docker Compose (Self-Managed)

```bash
# 1. Clone repository
git clone https://github.com/ramprag/saasready.git
cd saasready

# 2. Configure environment (docker-compose reads .env from root)
cp backend/.env.example .env
# Edit with production values

# 3. Build and start
docker-compose up -d --build

# 4. Run migrations
docker-compose exec backend alembic upgrade head

# 5. Verify
curl https://your-domain.com/health
```

### Manual Deployment

#### Backend (Gunicorn + Uvicorn)

```bash
cd backend
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start production server
gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
```

#### Frontend (Next.js)

```bash
cd frontend
npm ci
npm run build
npm start
```

---

## Hosting Providers

### Recommended Platforms

| Provider | Ease | Cost | Best For |
|----------|------|------|----------|
| **Railway** | ⭐⭐⭐⭐⭐ | $$ | Quick deploy |
| **Render** | ⭐⭐⭐⭐⭐ | $$ | Auto-deploy from GitHub |
| **DigitalOcean App Platform** | ⭐⭐⭐⭐ | $$ | Managed infrastructure |
| **AWS (ECS/EC2)** | ⭐⭐⭐ | $$$ | Enterprise scale |
| **GCP (Cloud Run)** | ⭐⭐⭐ | $$$ | Serverless |
| **Heroku** | ⭐⭐⭐⭐ | $$$ | Simple container deploy |

### Database Providers

| Provider | Type | Best For |
|----------|------|----------|
| **Supabase** | Managed Postgres | Quick setup |
| **AWS RDS** | Managed Postgres | Enterprise |
| **DigitalOcean** | Managed Postgres | Mid-size |
| **Railway** | Managed Postgres | Simplicity |

### Redis Providers

| Provider | Type | Best For |
|----------|------|----------|
| **Upstash** | Serverless Redis | Low traffic |
| **Redis Cloud** | Managed Redis | All sizes |
| **AWS ElastiCache** | Managed Redis | Enterprise |

---

## HTTPS & SSL

### Using a Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Let's Encrypt (Free SSL)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d api.yourdomain.com -d app.yourdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

---

## CORS Configuration

For production, restrict CORS origins:

```python
# backend/app/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.yourdomain.com"],  # NOT "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

## Monitoring & Logging

### Recommended Tools

| Category | Tool | Purpose |
|----------|------|---------|
| **Error Tracking** | Sentry | Exception monitoring |
| **Logs** | DataDog, Logtail | Centralized logging |
| **Uptime** | UptimeRobot, Pingdom | Health monitoring |
| **APM** | DataDog, New Relic | Performance |

### Sentry Integration

```bash
pip install sentry-sdk[fastapi]
```

```python
# backend/app/main.py
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

sentry_sdk.init(
    dsn="https://your-sentry-dsn",
    integrations=[FastApiIntegration()],
    traces_sample_rate=0.1,
)
```

---

## Scaling

### Horizontal Scaling

```yaml
# docker-compose.yml
services:
  backend:
    deploy:
      replicas: 3
    # ... rest of config
```

### Load Balancer

Use nginx, HAProxy, or cloud load balancers to distribute traffic across backend replicas.

### Database Connection Pooling

SaaSReady uses SQLAlchemy with connection pooling configured. For high-traffic:

```python
# Increase pool size
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
)
```

---

## Backup Strategy

### Database Backups

```bash
# Manual backup
pg_dump -h host -U user -d saasready > backup_$(date +%Y%m%d).sql

# Automated (cron)
0 2 * * * pg_dump -h host -U user -d saasready | gzip > /backups/$(date +\%Y\%m\%d).sql.gz
```

### Redis Backups

Redis persistence is enabled by default (`appendonly yes`). For additional safety:
- Use Redis Cloud or managed Redis with automatic backups
- Or configure RDB snapshots

---

## Health Checks

```bash
# Backend health
GET /health

# Response
{"status": "healthy", "database": "connected", "redis": "connected"}
```

Configure your orchestrator/load balancer to use these endpoints.

---

## Security Hardening

See [SECURITY.md](../SECURITY.md) for complete security guidelines including:
- Security headers
- Token storage recommendations
- Compliance notes
