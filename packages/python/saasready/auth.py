"""
Authentication client - handles all auth operations
"""
from typing import Optional, Dict, Any
from .models import TokenResponse, User
from .session import SessionManager
from .utils import HTTPClient
from .errors import AuthenticationError


class AuthClient:
    """Authentication operations"""

    def __init__(self, http: HTTPClient, session: SessionManager):
        self._http = http
        self._session = session
        self._base_path = "/api/v1/auth"

    def login(
            self,
            email: str,
            password: str,
            two_factor_code: Optional[str] = None
    ) -> TokenResponse:
        """
        Login with email and password

        Args:
            email: User email
            password: User password
            two_factor_code: Optional 2FA code

        Returns:
            TokenResponse with access/refresh tokens

        Raises:
            AuthenticationError: If credentials are invalid
        """
        data = {
            "email": email,
            "password": password,
        }

        if two_factor_code:
            data["two_factor_code"] = two_factor_code

        response = self._http.post(
            f"{self._base_path}/login",
            json=data,
            headers=self._session.get_headers()
        )

        token_response = TokenResponse(**response)

        # Auto-store tokens
        if token_response.access_token:
            self._session.set_token(
                token_response.access_token,
                token_response.refresh_token
            )

        return token_response

    def register(
            self,
            email: str,
            password: str,
            full_name: str
    ) -> TokenResponse:
        """
        Register new user

        Args:
            email: User email
            password: User password
            full_name: User's full name

        Returns:
            TokenResponse with access token
        """
        data = {
            "email": email,
            "password": password,
            "full_name": full_name,
        }

        response = self._http.post(
            f"{self._base_path}/register",
            json=data
        )

        token_response = TokenResponse(**response)

        # Auto-store token
        if token_response.access_token:
            self._session.set_token(token_response.access_token)

        return token_response

    def register_with_invite(
            self,
            email: str,
            password: str,
            full_name: str,
            invite_token: str
    ) -> TokenResponse:
        """
        Register with invitation token

        Args:
            email: User email
            password: User password
            full_name: User's full name
            invite_token: Organization invitation token

        Returns:
            TokenResponse with access token
        """
        data = {
            "email": email,
            "password": password,
            "full_name": full_name,
        }

        response = self._http.post(
            f"{self._base_path}/register-with-invite",
            json=data,
            params={"invite_token": invite_token}
        )

        token_response = TokenResponse(**response)

        if token_response.access_token:
            self._session.set_token(token_response.access_token)

        return token_response

    def me(self) -> User:
        """
        Get current authenticated user

        Returns:
            User object

        Raises:
            AuthenticationError: If not authenticated
        """
        response = self._http.get(
            f"{self._base_path}/me",
            headers=self._session.get_auth_headers()
        )

        return User(**response)

    def logout(self) -> Dict[str, str]:
        """
        Logout current user

        Returns:
            Success message
        """
        response = self._http.post(
            f"{self._base_path}/logout",
            headers=self._session.get_auth_headers()
        )

        # Clear local tokens
        self._session.clear_token()

        return response

    def request_password_reset(self, email: str) -> Dict[str, str]:
        """
        Request password reset email

        Args:
            email: User email

        Returns:
            Success message
        """
        data = {"email": email}

        return self._http.post(
            f"{self._base_path}/password-reset/request",
            json=data
        )

    def confirm_password_reset(
            self,
            token: str,
            new_password: str
    ) -> Dict[str, str]:
        """
        Confirm password reset with token

        Args:
            token: Reset token from email
            new_password: New password

        Returns:
            Success message
        """
        data = {
            "token": token,
            "new_password": new_password,
        }

        return self._http.post(
            f"{self._base_path}/password-reset/confirm",
            json=data
        )

    def change_password(
            self,
            current_password: str,
            new_password: str
    ) -> Dict[str, Any]:
        """
        Change user password (requires authentication)

        Args:
            current_password: Current password
            new_password: New password

        Returns:
            Response with session revocation info
        """
        params = {
            "current_password": current_password,
            "new_password": new_password,
        }

        response = self._http.post(
            f"{self._base_path}/change-password",
            params=params,
            headers=self._session.get_auth_headers()
        )

        # Clear token as all sessions are revoked
        self._session.clear_token()

        return response

    def verify_email(self, token: str) -> Dict[str, str]:
        """
        Verify email with token

        Args:
            token: Verification token from email

        Returns:
            Success message
        """
        data = {"token": token}

        return self._http.post(
            f"{self._base_path}/verify-email",
            json=data
        )

    def resend_verification(self, email: str) -> Dict[str, str]:
        """
        Resend email verification

        Args:
            email: User email

        Returns:
            Success message
        """
        data = {"email": email}

        return self._http.post(
            f"{self._base_path}/resend-verification",
            json=data
        )

    def accept_invitation(self, token: str) -> Dict[str, Any]:
        """
        Accept organization invitation (pre-login)

        Args:
            token: Invitation token

        Returns:
            Invitation details
        """
        data = {"token": token}

        return self._http.post(
            f"{self._base_path}/accept-invitation",
            json=data
        )

    def complete_invitation(self, token: str) -> Dict[str, Any]:
        """
        Complete invitation (post-login)

        Args:
            token: Invitation token

        Returns:
            Organization details
        """
        data = {"token": token}

        return self._http.post(
            f"{self._base_path}/complete-invitation",
            json=data,
            headers=self._session.get_auth_headers()
        )

    # 2FA Methods
    def setup_2fa(self) -> Dict[str, Any]:
        """
        Setup two-factor authentication

        Returns:
            2FA setup details with QR code
        """
        return self._http.post(
            f"{self._base_path}/2fa/setup",
            headers=self._session.get_auth_headers()
        )

    def verify_2fa(self, code: str) -> Dict[str, Any]:
        """
        Verify and activate 2FA

        Args:
            code: 2FA verification code

        Returns:
            Backup codes and success message
        """
        params = {"verification_code": code}

        return self._http.post(
            f"{self._base_path}/2fa/verify",
            params=params,
            headers=self._session.get_auth_headers()
        )

    def disable_2fa(self, password: str) -> Dict[str, str]:
        """
        Disable two-factor authentication

        Args:
            password: Current password for confirmation

        Returns:
            Success message
        """
        params = {"password": password}

        response = self._http.post(
            f"{self._base_path}/2fa/disable",
            params=params,
            headers=self._session.get_auth_headers()
        )

        # Clear token as sessions are revoked
        self._session.clear_token()

        return response

    # Security Methods
    def get_security_activity(self) -> Dict[str, Any]:
        """
        Get security activity for current user

        Returns:
            Security activity details
        """
        return self._http.get(
            f"{self._base_path}/security/activity",
            headers=self._session.get_auth_headers()
        )

    def get_current_session(self) -> Dict[str, Any]:
        """
        Get current session details

        Returns:
            Session information with device details
        """
        return self._http.get(
            f"{self._base_path}/sessions/current",
            headers=self._session.get_auth_headers()
        )
