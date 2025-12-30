"""
Main SaaSReady client - entry point for SDK
"""
from typing import Optional
from .auth import AuthClient
from .orgs import OrganizationsClient
from .users import UsersClient
from .audit import AuditClient
from .rbac import RBACClient
from .flags import FeatureFlagsClient
from .session import SessionManager
from .utils import HTTPClient


class SaaSReady:
    """
    SaaSReady Python SDK Client

    Enterprise-grade authentication & multi-tenancy platform client.

    Usage:
        >>> from saasready import SaaSReady
        >>>
        >>> # Initialize client
        >>> client = SaaSReady(
        ...     base_url="https://api.yourdomain.com",
        ...     timeout=30.0
        ... )
        >>>
        >>> # Authenticate
        >>> response = client.auth.login("user@example.com", "password")
        >>> client.set_token(response.access_token)
        >>>
        >>> # Use authenticated endpoints
        >>> orgs = client.orgs.list()
        >>> user = client.auth.me()
    """

    def __init__(
            self,
            base_url: str,
            api_key: Optional[str] = None,
            timeout: float = 30.0,
            max_retries: int = 3,
            verify_ssl: bool = True,
    ):
        """
        Initialize SaaSReady client

        Args:
            base_url: Base URL of your SaaSReady instance
            api_key: Optional API key for service-to-service auth
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates
        """
        self._http = HTTPClient(
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            verify_ssl=verify_ssl,
        )

        self._session = SessionManager()

        # Set API key if provided
        if api_key:
            self._session.set_api_key(api_key)

        # Initialize service clients
        self.auth = AuthClient(self._http, self._session)
        self.orgs = OrganizationsClient(self._http, self._session)
        self.users = UsersClient(self._http, self._session)
        self.audit = AuditClient(self._http, self._session)
        self.rbac = RBACClient(self._http, self._session)
        self.flags = FeatureFlagsClient(self._http, self._session)

    def set_token(self, access_token: str, refresh_token: Optional[str] = None):
        """
        Set authentication tokens

        Args:
            access_token: JWT access token
            refresh_token: Optional refresh token
        """
        self._session.set_token(access_token, refresh_token)

    def clear_token(self):
        """Clear authentication tokens"""
        self._session.clear_token()

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated"""
        return self._session.has_token()

    def close(self):
        """Close HTTP connections"""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
