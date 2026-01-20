"""
Users client - user management operations
"""
from typing import Dict
from .models import User
from .session import SessionManager
from .utils import HTTPClient


class UsersClient:
    """User management operations"""

    def __init__(self, http: HTTPClient, session: SessionManager):
        self._http = http
        self._session = session
        self._base_path = "/api/v1/users"

    def me(self) -> User:
        """
        Get current user profile

        Returns:
            User object
        """
        response = self._http.get(
            f"{self._base_path}/me",
            headers=self._session.get_auth_headers()
        )

        return User(**response)

    def remove_member(self, org_id: str, member_id: str) -> Dict[str, str]:
        """
        Remove member from organization

        Args:
            org_id: Organization ID
            member_id: Member/Membership ID

        Returns:
            Success message
        """
        return self._http.delete(
            f"{self._base_path}/orgs/{org_id}/members/{member_id}",
            headers=self._session.get_auth_headers()
        )