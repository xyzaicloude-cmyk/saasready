---
title: Framework Integration Examples
description: Learn how to integrate SaaSReady with FastAPI, Django, and Flask. Practical code examples for multi-tenant authentication in Python.
keywords: [fastapi multi-tenant example, django auth integration, flask rbac, python saas auth]
---
# Framework Integration Examples

Examples for integrating SaaSReady authentication into popular Python frameworks.

---

## FastAPI Integration

```python
# main.py
from fastapi import FastAPI, Depends, HTTPException, Header
from saasready import SaaSReady, AuthenticationError

app = FastAPI()
auth_client = SaaSReady(base_url="http://localhost:8000")

async def get_current_user(authorization: str = Header(None)):
    """Dependency to get authenticated user"""
    if not authorization:
        raise HTTPException(401, "Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    auth_client.set_token(token)
    
    try:
        return auth_client.auth.me()
    except AuthenticationError:
        raise HTTPException(401, "Invalid token")

@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    return {"message": f"Hello {user.email}"}

@app.get("/public")
async def public_route():
    return {"message": "This is public"}
```

---

## Django Integration

### Middleware

```python
# middleware.py
from saasready import SaaSReady, AuthenticationError

class SaaSReadyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.client = SaaSReady(base_url="http://localhost:8000")
    
    def __call__(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', '').replace('Bearer ', '')
        
        if token:
            try:
                self.client.set_token(token)
                request.saasready_user = self.client.auth.me()
            except AuthenticationError:
                request.saasready_user = None
        else:
            request.saasready_user = None
        
        return self.get_response(request)
```

### Settings

```python
# settings.py
MIDDLEWARE = [
    # ... other middleware
    'yourapp.middleware.SaaSReadyMiddleware',
]
```

### Views

```python
# views.py
from django.http import JsonResponse

def protected_view(request):
    if not request.saasready_user:
        return JsonResponse({"error": "Unauthorized"}, status=401)
    
    return JsonResponse({
        "message": f"Hello {request.saasready_user.email}"
    })
```

### Decorator

```python
# decorators.py
from functools import wraps
from django.http import JsonResponse

def require_auth(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.saasready_user:
            return JsonResponse({"error": "Unauthorized"}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper

# Usage
@require_auth
def my_protected_view(request):
    return JsonResponse({"user": request.saasready_user.email})
```

---

## Flask Integration

### Basic Setup

```python
# app.py
from flask import Flask, request, g, jsonify
from functools import wraps
from saasready import SaaSReady, AuthenticationError

app = Flask(__name__)
auth_client = SaaSReady(base_url="http://localhost:8000")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({"error": "Missing token"}), 401
        
        try:
            auth_client.set_token(token)
            g.user = auth_client.auth.me()
        except AuthenticationError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/protected')
@require_auth
def protected():
    return jsonify({"message": f"Hello {g.user.email}"})

@app.route('/public')
def public():
    return jsonify({"message": "This is public"})
```

### Flask Blueprint

```python
# auth_blueprint.py
from flask import Blueprint, g, jsonify
from functools import wraps
from saasready import SaaSReady, AuthenticationError

auth_bp = Blueprint('auth', __name__)
client = SaaSReady(base_url="http://localhost:8000")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import request
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            client.set_token(token)
            g.current_user = client.auth.me()
        except AuthenticationError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

@auth_bp.route('/me')
@login_required
def me():
    return jsonify({
        "id": g.current_user.id,
        "email": g.current_user.email,
        "full_name": g.current_user.full_name
    })
```

---

## Organization Context

For multi-tenant applications, you often need organization context:

```python
# Any framework
from saasready import SaaSReady

client = SaaSReady(base_url="http://localhost:8000")

def get_current_org(user, org_slug):
    """Get organization by slug if user is a member"""
    client.set_token(user.token)
    orgs = client.orgs.list()
    
    for org in orgs:
        if org.slug == org_slug:
            return org
    
    return None  # User not in this org

# Usage in route
@app.route('/<org_slug>/dashboard')
@require_auth
def org_dashboard(org_slug):
    org = get_current_org(g.user, org_slug)
    if not org:
        return jsonify({"error": "Not a member of this organization"}), 403
    
    return jsonify({"org": org.name, "user": g.user.email})
```

---

## Permission Checking

```python
# permissions.py
from functools import wraps
from flask import g, jsonify

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, org_id=None, **kwargs):
            # Get membership and check permission
            members = client.orgs.list_members(org_id)
            user_membership = next(
                (m for m in members if m.user_id == g.user.id), 
                None
            )
            
            if not user_membership:
                return jsonify({"error": "Not a member"}), 403
            
            # Check role permissions (simplified)
            role = user_membership.role_name
            if role not in ['owner', 'admin'] and permission.startswith('user.'):
                return jsonify({"error": "Insufficient permissions"}), 403
            
            return f(*args, org_id=org_id, **kwargs)
        return decorated
    return decorator

# Usage
@app.route('/orgs/<org_id>/invite', methods=['POST'])
@require_auth
@require_permission('user.invite')
def invite_member(org_id):
    # Only owners/admins can invite
    pass
```

---

## Error Handling

```python
from saasready import (
    SaaSReadyError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    RateLimitError,
    NotFoundError
)

@app.errorhandler(AuthenticationError)
def handle_auth_error(e):
    return jsonify({"error": "Authentication failed", "detail": str(e)}), 401

@app.errorhandler(AuthorizationError)
def handle_authz_error(e):
    return jsonify({"error": "Permission denied", "detail": str(e)}), 403

@app.errorhandler(RateLimitError)
def handle_rate_limit(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "retry_after": e.retry_after
    }), 429
```

---

## Next Steps

- [API Reference](./api-reference.md) - All endpoints
- [Features Guide](./features.md) - 2FA, sessions, email
- [SDK Documentation](https://github.com/ramprag/saasready/blob/main/SDK_README.md) - Full SDK reference
