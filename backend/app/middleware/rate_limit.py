"""
Rate limiting middleware
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
from datetime import datetime, timedelta
import time


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using sliding window"""

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Get client identifier (IP or API key)
        client_id = self._get_client_id(request)

        # Clean old requests
        now = time.time()
        minute_ago = now - 60
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > minute_ago
        ]

        # Check rate limit
        if len(self.requests[client_id]) >= self.requests_per_minute:
            return Response(
                content='{"error": "rate_limit_exceeded", "message": "Too many requests"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(self.requests[client_id][0] + 60)),
                    "Retry-After": "60"
                }
            )

        # Record request
        self.requests[client_id].append(now)

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            self.requests_per_minute - len(self.requests[client_id])
        )
        response.headers["X-RateLimit-Reset"] = str(
            int(self.requests[client_id][0] + 60) if self.requests[client_id] else int(now + 60)
        )

        return response

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier"""
        # Try API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"api:{api_key[:10]}"

        # Fall back to IP
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"ip:{forwarded.split(',')[0]}"

        return f"ip:{request.client.host}"