"""
Feature flags client
"""
from typing import List, Dict, Any, Optional
from .models import FeatureFlag
from .session import SessionManager
from .utils import HTTPClient


class FeatureFlagsClient:
    """Feature flags operations"""

    def __init__(self, http: HTTPClient, session: SessionManager):
        self._http = http
        self._session = session
        self._base_path = "/api/v1/feature-flags"

    def create_global(
            self,
            key: str,
            name: str,
            description: Optional[str] = None,
            default_enabled: bool = False
    ) -> FeatureFlag:
        """
        Create global feature flag (admin only)

        Args:
            key: Unique flag key
            name: Human-readable name
            description: Optional description
            default_enabled: Default enabled state

        Returns:
            FeatureFlag object
        """
        data = {
            "key": key,
            "name": name,
            "default_enabled": default_enabled,
        }

        if description:
            data["description"] = description

        response = self._http.post(
            self._base_path,
            json=data,
            headers=self._session.get_auth_headers()
        )

        return FeatureFlag(**response)

    def list_global(self) -> List[FeatureFlag]:
        """
        List all global feature flags (admin only)

        Returns:
            List of FeatureFlag objects
        """
        response = self._http.get(
            self._base_path,
            headers=self._session.get_auth_headers()
        )

        return [FeatureFlag(**flag) for flag in response]

    def is_enabled(self, org_id: str, flag_key: str) -> bool:
        """
        Check if feature flag is enabled for organization

        Args:
            org_id: Organization ID
            flag_key: Feature flag key

        Returns:
            True if enabled
        """
        try:
            flags = self._http.get(
                f"/api/v1/orgs/{org_id}/feature-flags",
                headers=self._session.get_auth_headers()
            )

            for flag in flags:
                if flag.get("key") == flag_key:
                    return flag.get("enabled", False)

            return False
        except Exception:
            return False