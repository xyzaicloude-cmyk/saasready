# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: [security@saasready.dev](mailto:security@saasready.dev)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to understand and resolve the issue.

---

## Security Architecture

### Authentication
- **JWT-based authentication** with JTI (JWT ID) tracking for revocation
- **Argon2** password hashing (with bcrypt fallback)
- **2FA/TOTP** support with backup codes
- **Session management** with per-device tracking and max session limits

### Authorization
- **Role-based access control (RBAC)** with role hierarchy
- **Permission-based endpoint protection**
- **Multi-tenant isolation** - organization-scoped data access

### Security Controls
- **Brute force protection** - progressive delays, device-aware lockouts
- **Rate limiting** - Redis-backed sliding window algorithm
- **Audit logging** - comprehensive action tracking with IP/User-Agent

---

## ⚠️ Known Security Considerations

### Token Storage (Frontend)

> **Important**: JWT tokens are stored in `localStorage` in the default frontend implementation.

**Implications:**
- Tokens are accessible to JavaScript (XSS vulnerability risk)
- Suitable for internal tools, MVPs, and applications with strong XSS protections
- For high-security applications, consider migrating to `httpOnly` cookies

**Mitigations in place:**
- Short token expiry (configurable, default 60 minutes)
- Token revocation via JTI blacklist
- Session tracking and maximum session limits

### Rate Limiting Fallback
- In-memory fallback when Redis is unavailable
- For production, always use Redis for distributed rate limiting

---

## Security Best Practices

When deploying SaaSReady in production:

### 1. Secrets Management
```bash
# Generate a secure SECRET_KEY (REQUIRED)
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```
- Never use default or placeholder secrets
- Use environment variables for all sensitive configuration
- Rotate secrets periodically

### 2. Enable HTTPS
- Use SSL/TLS certificates (Let's Encrypt recommended)
- Set `Strict-Transport-Security` header (already configured)
- Redirect all HTTP traffic to HTTPS

### 3. Database Security
- Use strong, unique passwords
- Enable SSL for database connections
- Regular automated backups
- Restrict network access to database

### 4. Redis Security
- Enable authentication (`requirepass`)
- Use TLS for Redis connections in production
- Restrict network access

### 5. CORS Configuration
- Restrict `allow_origins` to your specific domains
- Never use `allow_origins=["*"]` in production

### 6. Monitoring & Alerting
- Set up error tracking (Sentry, Datadog)
- Monitor failed login attempts
- Alert on suspicious activity patterns
- Review audit logs regularly

### 7. Dependency Management
- Keep dependencies updated
- Use `pip-audit` or Snyk for vulnerability scanning
- Subscribe to security advisories for key dependencies

---

## Security Headers

The following security headers are automatically set:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

---

## Compliance Notes

SaaSReady provides building blocks for compliance but is **not certified**:

- **SOC 2**: Audit logging, access controls, encryption in transit
- **GDPR**: Audit trails present; data export/deletion endpoints need implementation
- **HIPAA**: Not suitable without additional encryption at rest

---

## Security Updates

We actively monitor and patch security vulnerabilities. Subscribe to:
- GitHub Security Advisories
- Release notes for security patches

Last security review: January 2026