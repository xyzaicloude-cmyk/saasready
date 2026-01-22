---
title: SaaSReady Documentation
description: Self-hosted authentication, multi-tenancy, and RBAC backend for B2B SaaS applications. Own your auth infrastructure with an open-source alternative to Auth0 and WorkOS.
keywords: [self-hosted auth, multi-tenancy, RBAC, B2B SaaS, open source auth, FastAPI auth]
---

# SaaSReady

SaaSReady is an open-source, self-hosted authentication and multi-tenancy backend designed for B2B SaaS applications. It provides the core infrastructure you need to manage users, organizations, permissions, and security logs without vendor lock-in.

## Core Pillars

- **Drop-in Python SDK**: Integrate auth, multi-tenancy, and RBAC into your app with minimal code changes. Similar to Auth0 or Clerk, but running on your rails.
- **Self-Hosted Ownership**: Deploy on your own infrastructure (Docker-based). Your data stays with you.
- **Multi-Tenant First**: Built from the ground up for B2B. Organizations are first-class citizens.
- **Granular RBAC**: Complex permission sets and hierarchical roles (Owner, Admin, Member, Viewer).
- **Security Compliance**: Audit logs, brute-force protection, and 2FA/TOTP out of the box.

## The 2-Line Integration

```python
from saasready import SaaSReady
client = SaaSReady(base_url="https://auth.yourdomain.com")
```

## Who is it for?

- **Early-stage SaaS founders** who want to avoid high per-user costs of hosted auth providers.
- **Indie developers** building B2B tools who want full control over auth infrastructure.
- **Enterprise teams** requiring full control over user data and security infrastructure for compliance.

## Who is it NOT for?

- Developers seeking a fully managed "no-ops" service (use Auth0, WorkOS, Clerk).
- Consumer apps with millions of users (SaaSReady is designed for B2B scale).
- Projects requiring deep social login/SSO support *today* (on our roadmap).

## Next Steps

→ [Quick Start](./quickstart.md) — Get it running in 5 minutes  
→ [Architecture](./Architecture.md) — System design and data model  
→ [Setup Guide](./setup-guide.md) — Configure your production environment  
→ [API Reference](./api-reference.md) — All endpoints with examples
