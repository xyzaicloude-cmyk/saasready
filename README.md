# SaaSReady - Enterprise Multi-Tenant Authentication & Authorization

**Drop-in authentication and authorization infrastructure for B2B SaaS applications.** Similar to WorkOS, Auth0, or Clerk, but self-hosted and fully customizable.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)

---

## 🚀 **What is SaaSReady?**

SaaSReady is a production-ready authentication and multi-tenancy backend that handles:
- **User Authentication** (JWT-based)
- **Multi-Tenant Organizations** (workspace isolation)
- **Role-Based Access Control (RBAC)** (permissions & roles)
- **Member Invitations** (database-ready, email integration needed)
- **Audit Logging** (track all user actions)
- **Feature Flags** (gradual rollouts & A/B testing)
- **Authentication** Secure JWT-based auth with email/password
- **Admin Dashboard** Beautiful Next.js UI for managing organizations, members, and permissions
- **Database Migrations** Alembic-powered schema versioning
- **Docker Ready** Complete containerization with docker-compose
- **MIT Licensed** Free to use for personal and commercial projects
- **Perfect for B2B SaaS startups that need enterprise-grade auth without building from scratch**

---

## 📋 **Features**

### ✅ **Core Authentication**
- JWT-based user authentication
- Secure password hashing (Argon2 + Bcrypt)
- Session management with configurable token expiry
- Protected endpoints with Bearer token auth

### ✅ **Multi-Tenancy**
- Organization-based tenant isolation
- Unique organization slugs (e.g., `acme-corp`)
- Auto-creation of personal workspace on signup
- Member management per organization

### ✅ **RBAC (Role-Based Access Control)**
- Pre-built roles: `Owner`, `Admin`, `Member`, `Viewer`
- Granular permissions: `org.update`, `user.invite`, `audit.read`, etc.
- Permission-based endpoint protection
- Custom role creation support

### ✅ **Member Invitations**
- Invite users by email
- Automatic account creation for new users
- Membership status tracking (`active`, `invited`, `suspended`)
- Role assignment during invitation

### ✅ **Audit Logging**
- Track all user actions (login, invite, role changes, etc.)
- Store IP address, user agent, metadata
- Organization-scoped logs
- Queryable with pagination

### ✅ **Feature Flags**
- Global feature flags with default states
- Organization-level overrides
- Gradual rollout with percentage-based targeting
- Toggle features without code deployments

### 🛠️ **Admin UI Included**
- React/Next.js frontend
- Organization switcher
- Member management with role assignment
- Audit log viewer
- Feature flag dashboard

---

## 🏗️ **Architecture**

```
┌─────────────────┐
│   Frontend      │ Next.js (React) + Tailwind CSS
│   (Port 3000)   │ → Authentication, Org Management, Member Invites
└────────┬────────┘
         │ REST API (JWT)
         ▼
┌─────────────────┐
│   Backend       │ FastAPI (Python) + SQLAlchemy
│   (Port 8000)   │ → Auth, RBAC, Multi-Tenancy, Audit Logs
└────────┬────────┘
         │ PostgreSQL
         ▼
┌─────────────────┐
│   Database      │ PostgreSQL 15
│   (Port 5432)   │ → Users, Orgs, Roles, Permissions, Audit Logs
└─────────────────┘
```

---

## 🚀 **Quick Start (5 minutes)**

### **Prerequisites**
- Docker & Docker Compose
- Git

### **1. Clone the Repository**
```bash
git clone https://github.com/ramprag/saasready.git
cd saasready
```

### **2. Configure Environment**
```bash
# Backend
cp backend/.env.example backend/.env

# Frontend
cp frontend/.env.local.example frontend/.env.local
```

**Edit `backend/.env`** and change the secret key:
```env
SECRET_KEY=your-super-secret-key-min-32-chars-change-this-now
```

### **3. Start the Stack**
```bash
docker-compose up --build
```

**Services will start:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- PostgreSQL: localhost:5432

### **4. Create Your First Account**
1. Visit http://localhost:3000/register
2. Sign up with email/password
3. You'll auto-login and see your personal organization

**Default seeded roles:**
- `Owner` - Full access
- `Admin` - Manage users & settings
- `Member` - Read organization data
- `Viewer` - Read-only access

---

## 🔌 **API Integration Guide**

### **Authentication Flow**

#### **1. Register a New User**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "password": "SecurePassword123",
    "full_name": "John Doe"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**What happens:**
- User account created
- Personal organization auto-created (`john-doe-org`)
- User assigned `Owner` role in their org
- Returns JWT token (expires in 7 days by default)

---

#### **2. Login**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "password": "SecurePassword123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

---

#### **3. Get Current User**
```bash
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "id": "uuid-here",
  "email": "user@company.com",
  "full_name": "John Doe",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2025-01-20T10:30:00"
}
```

---

### **Organization Management**

#### **4. List User's Organizations**
```bash
curl -X GET http://localhost:8000/api/v1/orgs \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
[
  {
    "id": "org-uuid",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "description": "Our main workspace",
    "is_active": true,
    "created_at": "2025-01-20T10:30:00",
    "updated_at": "2025-01-20T10:30:00"
  }
]
```

---

#### **5. Create Organization**
```bash
curl -X POST http://localhost:8000/api/v1/orgs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering Team",
    "slug": "engineering-team",
    "description": "Development workspace"
  }'
```

**Response:**
```json
{
  "id": "new-org-uuid",
  "name": "Engineering Team",
  "slug": "engineering-team",
  "description": "Development workspace",
  "is_active": true,
  "created_at": "2025-01-20T11:00:00",
  "updated_at": "2025-01-20T11:00:00"
}
```

**Note:** Creator automatically becomes `Owner` of the new org.

---

### **Member Invitations**

#### **6. Get Available Roles**
```bash
curl -X GET http://localhost:8000/api/v1/orgs/{org_id}/roles \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
[
  {
    "id": "role-uuid-1",
    "name": "Owner",
    "description": "Full access to organization",
    "is_system": true,
    "created_at": "2025-01-20T10:00:00"
  },
  {
    "id": "role-uuid-2",
    "name": "Admin",
    "description": "Administrative access",
    "is_system": true,
    "created_at": "2025-01-20T10:00:00"
  }
]
```

---

#### **7. Invite User to Organization**
```bash
curl -X POST http://localhost:8000/api/v1/orgs/{org_id}/invite \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@company.com",
    "role_id": "role-uuid-2",
    "full_name": "Jane Smith"
  }'
```

**Response:**
```json
{
  "id": "membership-uuid",
  "user_id": "new-user-uuid",
  "organization_id": "org-uuid",
  "role_id": "role-uuid-2",
  "status": "invited",
  "created_at": "2025-01-20T11:30:00",
  "user_email": "newuser@company.com",
  "user_full_name": "Jane Smith",
  "role_name": "Admin"
}
```

**⚠️ Current Limitation:**
- Creates membership with `invited` status
- **No email is sent** (email service integration required)
- User can login immediately with default password `changeme123`

**To enable emails:** Integrate SendGrid/AWS SES in `org_service.py`

---

#### **8. List Organization Members**
```bash
curl -X GET http://localhost:8000/api/v1/orgs/{org_id}/members \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
[
  {
    "id": "membership-uuid",
    "user_id": "user-uuid",
    "organization_id": "org-uuid",
    "role_id": "role-uuid",
    "status": "active",
    "created_at": "2025-01-20T10:30:00",
    "user_email": "user@company.com",
    "user_full_name": "John Doe",
    "role_name": "Owner"
  }
]
```

---

#### **9. Update Member Role**
```bash
curl -X PATCH http://localhost:8000/api/v1/orgs/{org_id}/members/{membership_id}/role \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "new-role-uuid"
  }'
```

**Required Permission:** `user.manage`

---

### **Permission-Protected Endpoints**

#### **10. Update Organization (Requires `org.update`)**
```bash
curl -X PATCH http://localhost:8000/api/v1/orgs/{org_id} \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Org Name",
    "description": "New description"
  }'
```

**Response:**
```json
{
  "id": "org-uuid",
  "name": "Updated Org Name",
  "slug": "acme-corp",
  "description": "New description",
  "is_active": true,
  "created_at": "2025-01-20T10:30:00",
  "updated_at": "2025-01-20T12:00:00"
}
```

**Permission Check:**
- Endpoint requires `org.update` permission
- Only `Owner` and `Admin` roles have this by default
- Returns `403 Forbidden` if user lacks permission

---

### **Audit Logs**

#### **11. Get Organization Audit Logs**
```bash
curl -X GET "http://localhost:8000/api/v1/audit/orgs/{org_id}/logs?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
[
  {
    "id": "log-uuid",
    "actor_user_id": "user-uuid",
    "organization_id": "org-uuid",
    "action": "user.invite.sent",
    "target_type": "membership",
    "target_id": "membership-uuid",
    "audit_metadata": {
      "invited_email": "newuser@company.com",
      "role_id": "role-uuid",
      "inviter_id": "user-uuid"
    },
    "ip_address": "192.168.1.1",
    "user_agent": "curl/7.81.0",
    "created_at": "2025-01-20T11:30:00",
    "actor_email": "admin@company.com"
  }
]
```

**Tracked Events:**
- `user.registered`, `user.logged_in`, `user.invite.sent`
- `user.role.updated`, `user.removed`
- `org.created`, `org.updated`
- `feature_flag.enabled`, `feature_flag.disabled`

---

### **Feature Flags**

#### **12. Get Organization Feature Flags**
```bash
curl -X GET http://localhost:8000/api/v1/orgs/{org_id}/feature-flags \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
[
  {
    "key": "beta-new-ui",
    "name": "Beta New UI",
    "description": "Enable the new redesigned user interface",
    "default_enabled": false,
    "enabled": true,
    "overridden": true,
    "rollout_percent": null
  },
  {
    "key": "ai-insights",
    "name": "AI Insights",
    "description": "Enable AI-powered analytics",
    "default_enabled": false,
    "enabled": false,
    "overridden": false,
    "rollout_percent": null
  }
]
```

---

#### **13. Toggle Feature Flag for Organization**
```bash
curl -X PUT http://localhost:8000/api/v1/orgs/{org_id}/feature-flags/beta-new-ui \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "rollout_percent": null
  }'
```

**Response:**
```json
{
  "key": "beta-new-ui",
  "name": "Beta New UI",
  "description": "Enable the new redesigned user interface",
  "default_enabled": false,
  "enabled": true,
  "overridden": true,
  "rollout_percent": null
}
```

---

#### **14. Reset Feature Flag to Default**
```bash
curl -X DELETE http://localhost:8000/api/v1/orgs/{org_id}/feature-flags/beta-new-ui \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "key": "beta-new-ui",
  "name": "Beta New UI",
  "description": "Enable the new redesigned user interface",
  "default_enabled": false,
  "enabled": false,
  "overridden": false,
  "rollout_percent": null
}
```

---

## 🛡️ **RBAC Implementation Guide**

### **How Permissions Work**

SaaSReady uses a **Role → Permission** mapping system:

```
User → Membership (in Org) → Role → Permissions
```

### **Default Roles & Permissions**

| Role    | Permissions                                                                                     |
|---------|-------------------------------------------------------------------------------------------------|
| Owner   | `org.*`, `user.*`, `role.*`, `audit.read`, `feature_flags.*`                                   |
| Admin   | `org.read`, `org.update`, `user.invite`, `user.manage`, `audit.read`                          |
| Member  | `org.read`, `audit.read`                                                                        |
| Viewer  | `org.read`                                                                                      |

### **Protecting Endpoints**

```python
from app.core.dependencies import require_permission

@router.patch("/{org_id}")
def update_organization(
    org_id: str,
    data: OrganizationUpdate,
    membership: Membership = Depends(require_permission("org.update")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Only users with org.update permission can access this
    org = db.query(Organization).filter(Organization.id == org_id).first()
    # ... update logic
```

### **Available Permissions**

```python
# Organization
"org.read"        # View organization details
"org.update"      # Modify organization settings
"org.delete"      # Delete organization
"org.settings"    # Manage organization settings

# Users
"user.read"       # View user information
"user.invite"     # Invite users to organization
"user.manage"     # Change roles, remove users
"user.create"     # Create new users
"user.update"     # Update user information
"user.delete"     # Delete users

# Roles
"role.read"       # View roles
"role.manage"     # Create/edit roles and permissions

# Audit
"audit.read"      # View audit logs

# API Keys (model exists, not implemented)
"api_key.manage"  # Create/delete API keys

# Settings
"settings.read"   # View settings
"settings.update" # Modify settings
```

---

## 🔧 **Development**

### **Project Structure**
```
saasready/
├── backend/
│   ├── alembic/              # Database migrations
│   ├── app/
│   │   ├── core/             # Config, database, security
│   │   ├── models/           # SQLAlchemy models
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── routes/           # API endpoints
│   │   ├── services/         # Business logic
│   │   └── main.py           # FastAPI app
│   ├── tests/                # Pytest tests
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── app/                  # Next.js pages
│   ├── components/           # React components
│   ├── lib/                  # API client, types
│   └── .env.local
├── docker-compose.yml
└── README.md
```

### **Local Development**

#### **Backend**
```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### **Frontend**
```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

### **Database Migrations**

```bash
# Create new migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

### **Run Tests**

```bash
cd backend
pytest -v
```

---

## 📦 **Production Deployment**

### **Environment Variables**

**Backend (`backend/.env`):**
```env
DATABASE_URL=postgresql://user:pass@host:5432/dbname
SECRET_KEY=your-super-secret-key-min-32-chars-long
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080  # 7 days
```

**Frontend (`frontend/.env.local`):**
```env
NEXT_PUBLIC_API_URL=https://api.yourapp.com/api/v1
```

### **Deployment Checklist**

- [ ] Change `SECRET_KEY` to a strong random value (32+ chars)
- [ ] Use managed PostgreSQL (AWS RDS, DigitalOcean, etc.)
- [ ] Enable HTTPS/SSL for API and frontend
- [ ] Set `ALGORITHM=HS256` (or RS256 for asymmetric JWT)
- [ ] Configure CORS origins in `app/main.py`
- [ ] Set up error tracking (Sentry)
- [ ] Enable database backups
- [ ] Review `SECURITY.md` for production hardening
- [ ] Implement rate limiting (Redis-based)
- [ ] Add email service (SendGrid, AWS SES)

### **Docker Production**

```bash
# Build images
docker-compose -f docker-compose.prod.yml build

# Run in detached mode
docker-compose -f docker-compose.prod.yml up -d
```

---

## 🔐 **Security**

### **Best Practices Implemented**
✅ JWT-based authentication with expiry  
✅ Argon2 password hashing (72-byte limit safe)  
✅ CORS protection  
✅ SQL injection prevention (SQLAlchemy ORM)  
✅ Audit logging with IP tracking  
✅ Permission-based endpoint protection

### **Security Considerations**
⚠️ JWT tokens stored in localStorage (consider httpOnly cookies)  
⚠️ Rate limiting is in-memory (use Redis for production)  
⚠️ Email verification not enforced (flag exists)  
⚠️ 2FA not implemented  
⚠️ No email sending (invitation emails)

**See `SECURITY.md` for detailed security guidelines.**

---

## 🤝 **Comparison to Auth Providers**

| Feature                     | SaaSReady | WorkOS | Auth0 | Clerk |
|-----------------------------|-----------|--------|-------|-------|
| Self-Hosted                 | ✅        | ❌     | ❌    | ❌    |
| Multi-Tenancy (Orgs)        | ✅        | ✅     | ✅    | ✅    |
| RBAC                        | ✅        | ✅     | ✅    | ✅    |
| Audit Logs                  | ✅        | ✅     | ✅    | ✅    |
| Feature Flags               | ✅        | ❌     | ❌    | ❌    |
| SSO (SAML/OIDC)             | 🚧        | ✅     | ✅    | ✅    |
| Email Invitations           | 🚧        | ✅     | ✅    | ✅    |
| Admin UI Included           | ✅        | ✅     | ✅    | ✅    |
| Open Source                 | ✅        | ❌     | ❌    | ❌    |
| Free Tier                   | ✅ (Full) | ✅     | ✅    | ✅    |

**Legend:** ✅ Available | ❌ Not Available | 🚧 Partial (DB-ready, needs email)

---

## 🛣️ **Roadmap**

### **Phase 1: Current MVP** ✅
- [x] User authentication (JWT)
- [x] Multi-tenant organizations
- [x] RBAC with permissions
- [x] Member invitations (DB-only)
- [x] Audit logging
- [x] Feature flags
- [x] Admin UI

### **Phase 2: Email & Invitations**
- [ ] Email service integration (SendGrid/AWS SES)
- [ ] Secure invitation tokens
- [ ] Email templates (invite, password reset)
- [ ] Password reset flow
- [ ] Email verification enforcement

### **Phase 3: SSO & Advanced Auth**
- [ ] SAML 2.0 authentication
- [ ] OIDC/OAuth2 providers
- [ ] Google Workspace integration
- [ ] Azure AD integration
- [ ] 2FA/MFA support

### **Phase 4: Enterprise Features**
- [ ] API key authentication
- [ ] Webhooks system
- [ ] Custom role creation UI
- [ ] Directory sync (SCIM)
- [ ] Session management

### **Phase 5: Scale & Performance**
- [ ] Redis rate limiting
- [ ] Horizontal scaling guide
- [ ] Multi-region deployment
- [ ] CDN integration
- [ ] Performance monitoring

---

## 📚 **API Documentation**

**Interactive API Docs:**
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

**All endpoints return:**
- `200 OK` - Success
- `400 Bad Request` - Validation error
- `401 Unauthorized` - Missing/invalid token
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

---

## 🐛 **Troubleshooting**

### **"Organization not found" after registration**
**Solution:** The organization is created but might not be returned immediately. Refresh the page or call `GET /api/v1/orgs` to list organizations.

### **"Failed to invite user"**
**Check:**
1. User has `user.invite` permission
2. Role ID exists (call `GET /orgs/{org_id}/roles`)
3. Email is valid
4. User isn't already a member

### **"403 Forbidden" on protected endpoints**
**Solution:** Check user's role has required permission. Use `GET /audit/orgs/{org_id}/logs` to see permission checks.

### **Database connection errors**
**Solution:**
```bash
# Check if PostgreSQL is running
docker-compose ps

# View logs
docker-compose logs db

# Restart services
docker-compose restart
```

### **Frontend can't connect to backend**
**Solution:** Verify `NEXT_PUBLIC_API_URL` in `frontend/.env.local` matches your backend URL.

---

## 🤝 **Contributing**

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick Start:**
1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and test
4. Commit: `git commit -m "Add my feature"`
5. Push: `git push origin feature/my-feature`
6. Open a Pull Request

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

Inspired by [WorkOS](https://workos.com/), [Auth0](https://auth0.com/), and [Clerk](https://clerk.com/).

---

## 📞 **Support**

- 📖 [Documentation](https://github.com/yourusername/saasready/wiki)
- 💬 [Discussions](https://github.com/yourusername/saasready/discussions)
- 🐛 [Report Bug](https://github.com/yourusername/saasready/issues)
- 💡 [Request Feature](https://github.com/yourusername/saasready/issues)

---

**Made with ❤️ for the SaaS community**