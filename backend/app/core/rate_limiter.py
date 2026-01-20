# backend/app/core/rate_limiter.py
"""
Production-grade distributed rate limiter using Redis
"""
import time
import redis
from typing import Optional, Tuple
from fastapi import HTTPException, status
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Distributed rate limiter using Redis sliding window
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        if redis_url:
            try:
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self.redis_client.ping()
                logger.info("✅ Redis rate limiter connected")
            except Exception as e:
                logger.warning(f"⚠️ Redis unavailable, falling back to in-memory: {e}")
                self.fallback_storage = {}

    def check_rate_limit(
            self,
            key: str,
            limit: int,
            window: int = 60,
            burst_multiplier: float = 1.5
    ) -> Tuple[bool, dict]:
        """
        Check if rate limit is exceeded using sliding window

        Args:
            key: Unique identifier (user_id, ip, api_key)
            limit: Maximum requests per window
            window: Time window in seconds (default 60)
            burst_multiplier: Allow burst traffic (default 1.5x)

        Returns:
            tuple: (allowed, metadata)
        """
        if self.redis_client:
            return self._check_redis_rate_limit(key, limit, window, burst_multiplier)
        else:
            return self._check_memory_rate_limit(key, limit, window)

    def _check_redis_rate_limit(
            self,
            key: str,
            limit: int,
            window: int,
            burst_multiplier: float
    ) -> Tuple[bool, dict]:
        """Redis-based sliding window rate limiter"""
        now = time.time()
        window_start = now - window

        redis_key = f"rate_limit:{key}"

        try:
            # Use Redis sorted set for sliding window
            pipe = self.redis_client.pipeline()

            # Remove old entries outside window
            pipe.zremrangebyscore(redis_key, 0, window_start)

            # Count current requests
            pipe.zcard(redis_key)

            # Add current request with timestamp as score
            pipe.zadd(redis_key, {str(now): now})

            # Set expiry on key
            pipe.expire(redis_key, window * 2)

            results = pipe.execute()
            current_count = results[1]

            # Allow burst traffic up to burst_multiplier
            burst_limit = int(limit * burst_multiplier)
            allowed = current_count < burst_limit

            # Calculate reset time
            if current_count > 0:
                oldest_request = float(self.redis_client.zrange(redis_key, 0, 0)[0])
                reset_time = int(oldest_request + window)
            else:
                reset_time = int(now + window)

            metadata = {
                "limit": limit,
                "remaining": max(0, limit - current_count),
                "reset": reset_time,
                "retry_after": max(1, reset_time - int(now)) if not allowed else None
            }

            return allowed, metadata

        except redis.RedisError as e:
            logger.error(f"Redis rate limit error: {e}")
            # Fail open - allow request if Redis fails
            return True, {"limit": limit, "remaining": limit, "reset": int(now + window)}

    def _check_memory_rate_limit(
            self,
            key: str,
            limit: int,
            window: int
    ) -> Tuple[bool, dict]:
        """Fallback in-memory rate limiter (not distributed)"""
        now = time.time()
        window_start = now - window

        if not hasattr(self, 'fallback_storage'):
            self.fallback_storage = {}

        # Clean old entries
        if key in self.fallback_storage:
            self.fallback_storage[key] = [
                ts for ts in self.fallback_storage[key] if ts > window_start
            ]
        else:
            self.fallback_storage[key] = []

        current_count = len(self.fallback_storage[key])
        allowed = current_count < limit

        if allowed:
            self.fallback_storage[key].append(now)

        reset_time = int(self.fallback_storage[key][0] + window) if self.fallback_storage[key] else int(now + window)

        metadata = {
            "limit": limit,
            "remaining": max(0, limit - current_count),
            "reset": reset_time,
            "retry_after": max(1, reset_time - int(now)) if not allowed else None
        }

        return allowed, metadata


class RateLimitConfig:
    """Rate limit configurations for different endpoints"""

    # Global defaults
    DEFAULT_LIMIT = 60
    DEFAULT_WINDOW = 60

    # Endpoint-specific limits (requests per minute)
    LIMITS = {
        "auth:login": 5,           # Strict for brute force prevention
        "auth:register": 3,
        "auth:password_reset": 3,
        "auth:verify_email": 10,
        "api:read": 100,           # Higher for read operations
        "api:write": 30,           # Lower for write operations
        "api:invite": 10,          # Prevent spam invitations
        "webhook:receive": 100,
    }

    @classmethod
    def get_limit(cls, endpoint_type: str) -> int:
        """Get rate limit for endpoint type"""
        return cls.LIMITS.get(endpoint_type, cls.DEFAULT_LIMIT)


# Global rate limiter instance
rate_limiter = None


def init_rate_limiter(redis_url: Optional[str] = None):
    """Initialize global rate limiter"""
    global rate_limiter
    rate_limiter = RateLimiter(redis_url)
    return rate_limiter


def check_rate_limit(
        identifier: str,
        endpoint_type: str = "default",
        custom_limit: Optional[int] = None
) -> dict:
    """
    Check rate limit for identifier

    Args:
        identifier: Unique ID (user_id, IP, API key)
        endpoint_type: Type of endpoint for specific limits
        custom_limit: Override default limit

    Returns:
        dict: Rate limit metadata

    Raises:
        HTTPException: If rate limit exceeded
    """
    if not rate_limiter:
        init_rate_limiter()

    limit = custom_limit or RateLimitConfig.get_limit(endpoint_type)
    key = f"{endpoint_type}:{identifier}"

    allowed, metadata = rate_limiter.check_rate_limit(key, limit)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Please try again later.",
                "retry_after": metadata["retry_after"]
            },
            headers={
                "X-RateLimit-Limit": str(metadata["limit"]),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(metadata["reset"]),
                "Retry-After": str(metadata["retry_after"])
            }
        )

    return metadata