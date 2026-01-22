---
title: Troubleshooting & FAQs
description: Solutions to common issues when setting up or running SaaSReady. Find answers to frequently asked questions about authentication and multi-tenancy.
keywords: [SaaSReady troubleshooting, auth error fixes, multi-tenant auth faqs, self-hosted auth help]
---
# Troubleshooting

Common issues and solutions for SaaSReady platform.

---

## Authentication Issues

### "Could not validate credentials"

**Causes:**
- Token expired
- Token malformed
- Token on blacklist (logged out)

**Solutions:**
1. Check token expiry with [jwt.io](https://jwt.io)
2. Login again to get fresh token
3. Ensure `Authorization: Bearer <token>` header is correct

---

### "Organization not found" after registration

**Cause:** Database transaction timing

**Solution:** Refresh page or navigate to `/orgs`

---

### "Failed to invite user"

**Checklist:**
1. ✅ User has `user.invite` permission
2. ✅ Role ID exists (`GET /orgs/{org_id}/roles`)
3. ✅ Email is valid format
4. ✅ Email service is configured

**Debug:**
```bash
docker-compose logs backend | grep "Email"
```

---

### "403 Forbidden" on protected endpoints

**Cause:** Missing permissions

**Solution:** Check user's role has required permission

```bash
# View roles and permissions
GET /api/v1/orgs/{org_id}/roles
```

---

## Database Issues

### Connection refused

**Cause:** PostgreSQL not running

**Solution:**
```bash
# Check status
docker-compose ps db

# View logs
docker-compose logs db

# Restart
docker-compose restart db
```

---

### Migration errors

**Common fixes:**
```bash
cd backend

# Check current state
alembic current

# Try upgrade again
alembic upgrade head

# If stuck, stamp current
alembic stamp head
```

---

## Redis Issues

### Rate limiter not working

**Cause:** Redis not connected

**Check:**
```bash
# Test connection
redis-cli -h localhost -p 6379 -a your-password ping

# Should return: PONG
```

**Fallback:** Without Redis, rate limiting uses in-memory (not distributed)

---

## Email Issues

### Invitation emails not sending

**Checklist:**
1. SMTP variables configured in `.env`
2. EMAIL_FROM is verified with provider
3. Check worker logs: `docker-compose logs worker`

**Test email manually:**
```python
python3 << EOF
from app.services.email_service import email_service
import asyncio

asyncio.run(email_service.send_verification_email(
    "test@example.com",
    "https://example.com/verify"
))
EOF
```

---

## Frontend Issues

### "Network Error" or CORS errors

**Checklist:**
1. `NEXT_PUBLIC_API_URL` set correctly
2. Backend running on port 8000
3. CORS configured for frontend origin

**Check CORS in `backend/app/main.py`:**
```python
allow_origins=["http://localhost:3000"]  # Add your frontend URL
```

---

### "Hydration mismatch" in Next.js

**Cause:** Server/client HTML mismatch

**Solution:** Ensure localStorage access is client-side only:
```typescript
const [token, setToken] = useState<string | null>(null);
useEffect(() => {
    setToken(localStorage.getItem('token'));
}, []);
```

---

## Docker Issues

### Container won't start

**Check logs:**
```bash
docker-compose logs backend
docker-compose logs frontend
```

**Common causes:**
- Missing environment variables
- Port already in use
- Volume permission issues

**Reset:**
```bash
docker-compose down -v
docker-compose up --build
```

---

### "Secret key not set" error

Your `SECRET_KEY` is empty or a placeholder.

**Fix:**
```bash
# Generate key
python3 -c "import secrets; print(secrets.token_urlsafe(64))"

# Add to backend/.env
SECRET_KEY=<paste-generated-key>
```

---

## Performance Issues

### Slow API responses

**Check:**
1. Database connection pooling
2. N+1 queries in logs
3. Redis connection

**Quick fix:**
```bash
# Increase workers
gunicorn app.main:app --workers 4
```

---

## Getting Help

- **GitHub Issues**: [github.com/ramprag/saasready/issues](https://github.com/ramprag/saasready/issues)
- **Discussions**: [github.com/ramprag/saasready/discussions](https://github.com/ramprag/saasready/discussions)
- **API Docs**: http://localhost:8000/docs
