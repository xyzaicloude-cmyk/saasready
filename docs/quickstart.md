---
title: Quick Start Guide
description: Learn how to set up SaaSReady locally with Docker in under 5 minutes. The fastest way to get a multi-tenant auth backend running.
keywords: [docker auth setup, local auth dev, quickstart saasready, b2b saas setup]
---

# Quick Start

Get SaaSReady running on your local machine in under 5 minutes using Docker.

## Prerequisites

- **Docker** and **Docker Compose**
- **Git**

## 1. Clone and Configure

Clone the repository and prepare the environment variables.

```bash
git clone https://github.com/ramprag/saasready.git
cd saasready

# Copy example environment file
cp backend/.env.example .env

# Generate a secure SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# Edit .env and paste the generated key into SECRET_KEY
```

## 2. Launch with Docker Compose

Start the entire stack including the API, Frontend, PostgreSQL, and Redis.

```bash
docker-compose up --build
```

## 3. Verify the Setup

Once the services are up, you can access the following:

- **Admin UI**: [http://localhost:3000](http://localhost:3000)
- **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: `curl http://localhost:8000/health`

## 4. Register Your First User

Use the API to create an account and an organization automatically.

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com", 
    "password": "SecurePassword123!", 
    "full_name": "Demo User"
  }'
```

---

## 5. Drop-in Integration (Python SDK)

This is the fastest way to integrate SaaSReady into your existing Python application.

### Install the SDK

```bash
pip install saasready
```

### Use it in Your App

Connect to your self-hosted instance with just two lines of code:

```python
from saasready import SaaSReady

# Initialize with your self-hosted URL
client = SaaSReady(base_url="http://localhost:8000")

# Everything just works
response = client.auth.login("user@example.com", "SecurePassword123!")
user_info = client.auth.me()
organizations = client.orgs.list()
```

### Why use the SDK?
- **Auth0 Consistency**: Familiar API patterns for login, logout, and user management.
- **Type-Safety**: Fully typed Python client.
- **Auto-Refresh**: Handles JWT token rotation and session persistence for you.

## What's Next?

- Explore the [complete SDK Reference](https://github.com/ramprag/saasready/blob/main/SDK_README.md).
- See [Framework Examples](./framework-examples.md) for FastAPI, Django, and Flask.
- [Setup Email](./setup-guide.md#email-service-setup) to start inviting team members.
