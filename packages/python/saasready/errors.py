"""
Exception classes for SaaSReady SDK
"""


class SaaSReadyError(Exception):
    """Base exception for all SaaSReady errors"""

    def __init__(self, message: str, status_code: int = None, response: dict = None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


class AuthenticationError(SaaSReadyError):
    """Authentication failed (401)"""
    pass


class AuthorizationError(SaaSReadyError):
    """Authorization failed / Insufficient permissions (403)"""
    pass


class ValidationError(SaaSReadyError):
    """Request validation failed (422)"""
    pass


class RateLimitError(SaaSReadyError):
    """Rate limit exceeded (429)"""

    def __init__(self, message: str, retry_after: int = None, **kwargs):
        self.retry_after = retry_after
        super().__init__(message, **kwargs)


class NotFoundError(SaaSReadyError):
    """Resource not found (404)"""
    pass


class APIError(SaaSReadyError):
    """Generic API error"""
    pass