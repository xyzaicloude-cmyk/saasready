"""
Idempotency key handling for safe retries
"""

from fastapi import Header, HTTPException, status
from typing import Optional
import redis
import hashlib
import json
import logging

from .config import settings

logger = logging.getLogger(__name__)


class IdempotencyManager:
    """
    Manage idempotency keys for safe request retries

    Usage:
        @app.post("/")
        async def endpoint(
            idempotency_key: Optional[str] = Depends(require_idempotency_key)
        ):
            ...
    """

    def __init__(self, redis_url: Optional[str] = None):
        """Initialize idempotency manager"""
        self.redis_client = None
        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url)
            except Exception as e:
                logger.warning(f"Failed to connect to Redis for idempotency: {e}")

        self.ttl = 86400  # 24 hours

    def get_cached_response(self, key: str) -> Optional[dict]:
        """Get cached response for idempotency key"""
        if not self.redis_client:
            return None

        try:
            cached = self.redis_client.get(f"idempotency:{key}")
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.error(f"Error getting cached idempotency response: {e}")

        return None

    def cache_response(self, key: str, response: dict):
        """Cache response for idempotency key"""
        if not self.redis_client:
            return

        try:
            self.redis_client.setex(
                f"idempotency:{key}",
                self.ttl,
                json.dumps(response)
            )
        except Exception as e:
            logger.error(f"Error caching idempotency response: {e}")

    def is_processing(self, key: str) -> bool:
        """Check if request is currently being processed"""
        if not self.redis_client:
            return False

        try:
            return self.redis_client.exists(f"idempotency:processing:{key}")
        except Exception as e:
            logger.error(f"Error checking idempotency processing: {e}")
            return False

    def mark_processing(self, key: str):
        """Mark request as being processed"""
        if not self.redis_client:
            return

        try:
            self.redis_client.setex(
                f"idempotency:processing:{key}",
                60,  # 1 minute
                "1"
            )
        except Exception as e:
            logger.error(f"Error marking idempotency processing: {e}")

    def clear_processing(self, key: str):
        """Clear processing marker"""
        if not self.redis_client:
            return

        try:
            self.redis_client.delete(f"idempotency:processing:{key}")
        except Exception as e:
            logger.error(f"Error clearing idempotency processing: {e}")


# Global idempotency manager
idempotency_manager = IdempotencyManager(redis_url=settings.REDIS_URL)


def require_idempotency_key(
        idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")
) -> Optional[str]:
    """
    Require idempotency key for non-idempotent operations

    Usage:
        @app.post("/")
        async def endpoint(
            idempotency_key: str = Depends(require_idempotency_key)
        ):
            # Check for cached response
            cached = idempotency_manager.get_cached_response(idempotency_key)
            if cached:
                return cached

            # Process request
            result = ...

            # Cache response
            idempotency_manager.cache_response(idempotency_key, result)
            return result
    """
    return idempotency_key