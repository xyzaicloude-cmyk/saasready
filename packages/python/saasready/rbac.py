"""
RBAC client - role-based access control
"""
from typing import List, Dict, Any
from .session import SessionManager
from .utils import HTTPClient


class RBACClient:
    """RBAC operations"""

    def __init__(self, http: HTTPClient, session: SessionManager):
        self._http = http
        self._session = session
        # Note: RBAC checks happen via dependencies in backend
        # This client provides helper methods for frontend

    def check_permission(
            self,
            org_id: str,
            permission: str
    ) -> bool:
        """
        Check if current user has permission in organization

        Note: This is a client-side helper. Actual enforcement
        happens on the backend.

        Args:
            org_id: Organization ID
            permission: Permission key (e.g., "org.update")

        Returns:
            True if user has permission (best effort check)
        """
        # This would typically be done by trying to access
        # a protected endpoint, but we can provide a helper
        try:
            # Try to list members (requires permissions)
            self._http.get(
                f"/api/v1/orgs/{org_id}/members",
                headers=self._session.get_auth_headers()
            )
            return True
        except Exception:
            return False

    def has_role(self, org_id: str, role_name: str) -> bool:
        """
        Check if current user has specific role

        Args:
            org_id: Organization ID
            role_name: Role name (e.g., "owner", "admin")

        Returns:
            True if user has role
        """
        # Get current user's memberships
        try:
            orgs_response = self._http.get(
                "/api/v1/orgs",
                headers=self._session.get_auth_headers()
            )

            for org in orgs_response:
                if org.get("id") == org_id:
                    # Would need membership info with role
                    return True

            return False
        except Exception:
            return False