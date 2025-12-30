"""
Session manager - handles tokens and headers
"""
from typing import Optional, Dict
from datetime import datetime, timedelta


class SessionManager:
    """
    Manages authentication tokens and session state

    Thread-safe, in-memory token storage
    """

    def __init__(self):
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._api_key: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

    def set_token(
            self,
            access_token: str,
            refresh_token: Optional[str] = None,
            expires_in: Optional[int] = None
    ):
        """
        Set authentication tokens

        Args:
            access_token: JWT access token
            refresh_token: Optional refresh token
            expires_in: Token expiry in seconds
        """
        self._access_token = access_token
        self._refresh_token = refresh_token

        if expires_in:
            self._token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

    def set_api_key(self, api_key: str):
        """Set API key for service-to-service auth"""
        self._api_key = api_key

    def clear_token(self):
        """Clear all tokens"""
        self._access_token = None
        self._refresh_token = None
        self._api_key = None
        self._token_expires_at = None

    def has_token(self) -> bool:
        """Check if any auth token is set"""
        return bool(self._access_token or self._api_key)

    def get_headers(self) -> Dict[str, str]:
        """Get base headers (no auth)"""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get headers with authentication

        Returns:
            Dict with Authorization header

        Raises:
            ValueError: If no token is set
        """
        headers = self.get_headers()

        if self._api_key:
            headers["X-API-Key"] = self._api_key
        elif self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        else:
            raise ValueError("No authentication token set. Call set_token() or set_api_key() first.")

        return headers

    def is_token_expired(self) -> bool:
        """Check if token is expired"""
        if not self._token_expires_at:
            return False

        return datetime.utcnow() >= self._token_expires_at

    @property
    def access_token(self) -> Optional[str]:
        """Get current access token"""
        return self._access_token

    @property
    def refresh_token(self) -> Optional[str]:
        """Get current refresh token"""
        return self._refresh_token