"""
Audit client - audit log operations
"""
from typing import List
from .models import AuditLog
from .session import SessionManager
from .utils import HTTPClient


class AuditClient:
    """Audit log operations"""

    def __init__(self, http: HTTPClient, session: SessionManager):
        self._http = http
        self._session = session
        self._base_path = "/api/v1/audit"

    def get_logs(
            self,
            org_id: str,
            limit: int = 100,
            offset: int = 0
    ) -> List[AuditLog]:
        """
        Get audit logs for organization

        Args:
            org_id: Organization ID
            limit: Maximum number of logs to return
            offset: Pagination offset

        Returns:
            List of AuditLog objects
        """
        params = {
            "limit": limit,
            "offset": offset,
        }

        response = self._http.get(
            f"{self._base_path}/orgs/{org_id}/logs",
            params=params,
            headers=self._session.get_auth_headers()
        )

        return [AuditLog(**log) for log in response]