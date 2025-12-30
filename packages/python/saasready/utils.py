"""
HTTP client utilities with retry logic
"""
import time
import requests
from typing import Dict, Any, Optional
from urllib.parse import urljoin
from .errors import (
    SaaSReadyError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    RateLimitError,
    NotFoundError,
    APIError,
)


class HTTPClient:
    """
    HTTP client with automatic retries and error handling

    Production-grade with:
    - Exponential backoff
    - Connection pooling
    - Timeout handling
    - Structured errors
    """

    def __init__(
            self,
            base_url: str,
            timeout: float = 30.0,
            max_retries: int = 3,
            verify_ssl: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl

        # Session for connection pooling
        self.session = requests.Session()

    def _build_url(self, path: str) -> str:
        """Build full URL from path"""
        return urljoin(self.base_url, path.lstrip("/"))

    def _handle_response(self, response: requests.Response) -> Any:
        """
        Handle HTTP response and raise appropriate errors

        Args:
            response: requests.Response object

        Returns:
            Parsed JSON response

        Raises:
            Appropriate SaaSReadyError subclass
        """
        try:
            data = response.json()
        except ValueError:
            data = {"detail": response.text}

        if response.status_code == 200 or response.status_code == 201:
            return data

        error_detail = data.get("detail", "Unknown error")

        if response.status_code == 401:
            raise AuthenticationError(
                error_detail,
                status_code=401,
                response=data
            )

        if response.status_code == 403:
            raise AuthorizationError(
                error_detail,
                status_code=403,
                response=data
            )

        if response.status_code == 404:
            raise NotFoundError(
                error_detail,
                status_code=404,
                response=data
            )

        if response.status_code == 422:
            raise ValidationError(
                error_detail,
                status_code=422,
                response=data
            )

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                error_detail,
                status_code=429,
                retry_after=int(retry_after) if retry_after else None,
                response=data
            )

        # Generic API error
        raise APIError(
            error_detail,
            status_code=response.status_code,
            response=data
        )

    def _request_with_retry(
            self,
            method: str,
            url: str,
            **kwargs
    ) -> Any:
        """
        Make HTTP request with exponential backoff retry

        Args:
            method: HTTP method
            url: Full URL
            **kwargs: Additional arguments for requests

        Returns:
            Parsed response data
        """
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    **kwargs
                )

                return self._handle_response(response)

            except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout
            ) as e:
                last_exception = e

                # Don't retry on last attempt
                if attempt < self.max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue

            except (
                    AuthenticationError,
                    AuthorizationError,
                    ValidationError,
                    NotFoundError
            ):
                # Don't retry on client errors
                raise

            except RateLimitError as e:
                # Respect Retry-After header
                if e.retry_after and attempt < self.max_retries - 1:
                    time.sleep(e.retry_after)
                    continue
                raise

        # All retries exhausted
        if last_exception:
            raise APIError(
                f"Request failed after {self.max_retries} attempts: {str(last_exception)}",
                status_code=None
            )

    def get(
            self,
            path: str,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Any:
        """Make GET request"""
        url = self._build_url(path)
        return self._request_with_retry(
            "GET",
            url,
            params=params,
            headers=headers
        )

    def post(
            self,
            path: str,
            json: Optional[Dict[str, Any]] = None,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Any:
        """Make POST request"""
        url = self._build_url(path)
        return self._request_with_retry(
            "POST",
            url,
            json=json,
            params=params,
            headers=headers
        )

    def patch(
            self,
            path: str,
            json: Optional[Dict[str, Any]] = None,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Any:
        """Make PATCH request"""
        url = self._build_url(path)
        return self._request_with_retry(
            "PATCH",
            url,
            json=json,
            params=params,
            headers=headers
        )

    def put(
            self,
            path: str,
            json: Optional[Dict[str, Any]] = None,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Any:
        """Make PUT request"""
        url = self._build_url(path)
        return self._request_with_retry(
            "PUT",
            url,
            json=json,
            params=params,
            headers=headers
        )

    def delete(
            self,
            path: str,
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None
    ) -> Any:
        """Make DELETE request"""
        url = self._build_url(path)
        return self._request_with_retry(
            "DELETE",
            url,
            params=params,
            headers=headers
        )

    def close(self):
        """Close HTTP session"""
        self.session.close()