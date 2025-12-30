"""
Organizations client - manage organizations and memberships
"""
from typing import List, Optional, Dict, Any
from .models import Organization, Membership, Role, FeatureFlag
from .session import SessionManager
from .utils import HTTPClient


class OrganizationsClient:
    """Organization management operations"""

    def __init__(self, http: HTTPClient, session: SessionManager):
        self._http = http
        self._session = session
        self._base_path = "/api/v1/orgs"

    def create(self, name: str, slug: str, description: Optional[str] = None) -> Organization:
        """
        Create new organization

        Args:
            name: Organization name
            slug: Unique URL slug
            description: Optional description

        Returns:
            Organization object
        """
        data = {
            "name": name,
            "slug": slug,
        }

        if description:
            data["description"] = description

        response = self._http.post(
            self._base_path,
            json=data,
            headers=self._session.get_auth_headers()
        )

        return Organization(**response)

    def list(self) -> List[Organization]:
        """
        List user's organizations

        Returns:
            List of Organization objects
        """
        response = self._http.get(
            self._base_path,
            headers=self._session.get_auth_headers()
        )

        return [Organization(**org) for org in response]

    def update(
            self,
            org_id: str,
            name: Optional[str] = None,
            description: Optional[str] = None
    ) -> Organization:
        """
        Update organization

        Args:
            org_id: Organization ID
            name: New name (optional)
            description: New description (optional)

        Returns:
            Updated Organization object
        """
        data = {}

        if name:
            data["name"] = name
        if description is not None:
            data["description"] = description

        response = self._http.patch(
            f"{self._base_path}/{org_id}",
            json=data,
            headers=self._session.get_auth_headers()
        )

        return Organization(**response)

    def list_members(self, org_id: str) -> List[Membership]:
        """
        List organization members

        Args:
            org_id: Organization ID

        Returns:
            List of Membership objects
        """
        response = self._http.get(
            f"{self._base_path}/{org_id}/members",
            headers=self._session.get_auth_headers()
        )

        return [Membership(**member) for member in response]

    def list_roles(self, org_id: str) -> List[Role]:
        """
        List available roles for organization

        Args:
            org_id: Organization ID

        Returns:
            List of Role objects
        """
        response = self._http.get(
            f"{self._base_path}/{org_id}/roles",
            headers=self._session.get_auth_headers()
        )

        return [Role(**role) for role in response]

    def invite_member(
            self,
            org_id: str,
            email: str,
            role_id: str,
            full_name: Optional[str] = None
    ) -> Membership:
        """
        Invite user to organization

        Args:
            org_id: Organization ID
            email: User email
            role_id: Role ID to assign
            full_name: Optional full name

        Returns:
            Membership object
        """
        data = {
            "email": email,
            "role_id": role_id,
        }

        if full_name:
            data["full_name"] = full_name

        response = self._http.post(
            f"{self._base_path}/{org_id}/invite",
            json=data,
            headers=self._session.get_auth_headers()
        )

        return Membership(**response)

    def update_member_role(
            self,
            org_id: str,
            membership_id: str,
            role_id: str
    ) -> Membership:
        """
        Update member's role

        Args:
            org_id: Organization ID
            membership_id: Membership ID
            role_id: New role ID

        Returns:
            Updated Membership object
        """
        data = {"role_id": role_id}

        response = self._http.patch(
            f"{self._base_path}/{org_id}/members/{membership_id}/role",
            json=data,
            headers=self._session.get_auth_headers()
        )

        return Membership(**response)

    # Feature Flags
    def list_feature_flags(self, org_id: str) -> List[FeatureFlag]:
        """
        List feature flags for organization

        Args:
            org_id: Organization ID

        Returns:
            List of FeatureFlag objects
        """
        response = self._http.get(
            f"{self._base_path}/{org_id}/feature-flags",
            headers=self._session.get_auth_headers()
        )

        return [FeatureFlag(**flag) for flag in response]

    def set_feature_flag(
            self,
            org_id: str,
            flag_key: str,
            enabled: bool,
            rollout_percent: Optional[int] = None
    ) -> FeatureFlag:
        """
        Set feature flag for organization

        Args:
            org_id: Organization ID
            flag_key: Feature flag key
            enabled: Whether to enable the flag
            rollout_percent: Optional rollout percentage

        Returns:
            FeatureFlag object
        """
        data = {"enabled": enabled}

        if rollout_percent is not None:
            data["rollout_percent"] = rollout_percent

        response = self._http.put(
            f"{self._base_path}/{org_id}/feature-flags/{flag_key}",
            json=data,
            headers=self._session.get_auth_headers()
        )

        return FeatureFlag(**response)

    def delete_feature_flag(self, org_id: str, flag_key: str) -> FeatureFlag:
        """
        Delete feature flag override (revert to default)

        Args:
            org_id: Organization ID
            flag_key: Feature flag key

        Returns:
            FeatureFlag object with default value
        """
        response = self._http.delete(
            f"{self._base_path}/{org_id}/feature-flags/{flag_key}",
            headers=self._session.get_auth_headers()
        )

        return FeatureFlag(**response)