# Migration Guides

Looking to switch from another auth provider? These guides will help you migrate to SaaSReady.

## Available Guides

| Provider | Time Estimate | Guide |
|----------|--------------|-------|
| Auth0 | 10-15 minutes | [from-auth0.md](./from-auth0.md) |
| WorkOS | 10-15 minutes | [from-workos.md](./from-workos.md) |
| Clerk | 10-15 minutes | [from-clerk.md](./from-clerk.md) |
| Firebase Auth | 1-2 hours | [from-firebase.md](./from-firebase.md) |

## Why Migration is Fast

SaaSReady uses the same patterns as major auth providers:

```python
# The SDK swap is usually just one line!
# Before
from auth0 import Auth0Client
client = Auth0Client(...)

# After
from saasready import SaaSReady
client = SaaSReady(base_url="https://your-instance.com")
```

## General Migration Steps

1. **Deploy SaaSReady** - Docker Compose or your preferred method
2. **Export users** from your current provider
3. **Import users** to SaaSReady
4. **Send password resets** (password hashes can't be migrated)
5. **Swap SDK** in your application
6. **Update environment variables**
7. **Test thoroughly** before going live

## Need a Guide for Another Provider?

Open an issue on [GitHub](https://github.com/ramprag/saasready/issues) and we'll add it!
