# backend/app/services/device_fingerprint.py
"""
Enterprise Device Fingerprinting Service
Generates unique, persistent device identifiers for security tracking
"""
import hashlib
import json
from typing import Dict, Any, Optional
from fastapi import Request
import ua_parser
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class DeviceFingerprinter:
    """
    Auth0-style device fingerprinting with:
    - Deterministic fingerprint generation
    - Browser/device type detection
    - Privacy-conscious design (no PII in fingerprint)
    - Cross-platform support (Web, Mobile, API)
    """

    def __init__(self, request: Request):
        self.request = request
        self.user_agent = request.headers.get("user-agent", "")
        self.ip_address = request.client.host if request.client else "unknown"

    def generate_fingerprint(self) -> str:
        """
        Generate a deterministic device fingerprint

        Returns:
            SHA256 hash of device characteristics
        """
        fingerprint_data = self._collect_fingerprint_data()

        # Create a stable string representation
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)

        # Generate SHA256 hash
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

    def _collect_fingerprint_data(self) -> Dict[str, Any]:
        """
        Collect device characteristics for fingerprinting

        Note: We avoid collecting PII. Focus on technical characteristics.
        """
        data = {
            # Browser/Device Characteristics
            "user_agent_hash": hashlib.sha256(self.user_agent.encode()).hexdigest()[:16],
            "browser_family": self._get_browser_family(),
            "os_family": self._get_os_family(),
            "device_family": self._get_device_family(),

            # HTTP Headers (technical only)
            "accept_language": self.request.headers.get("accept-language", ""),
            "accept_encoding": self.request.headers.get("accept-encoding", ""),
            "connection": self.request.headers.get("connection", ""),
            "upgrade_insecure_requests": self.request.headers.get("upgrade-insecure-requests", ""),

            # Network characteristics (anonymized)
            "ip_prefix": self._anonymize_ip(self.ip_address),

            # Timezone (from headers)
            "timezone_offset": self.request.headers.get("timezone-offset", ""),

            # Screen/resolution (if available from client)
            "screen_info": self._get_screen_info(),

            # Version for algorithm changes
            "fingerprint_version": "2.0"
        }

        # Add platform-specific data
        if self._is_mobile_app():
            data["platform"] = "mobile"
            data["app_version"] = self.request.headers.get("x-app-version", "")
        elif self._is_browser():
            data["platform"] = "browser"
        else:
            data["platform"] = "api"

        return data

    def _get_browser_family(self) -> str:
        """Extract browser family from User-Agent"""
        try:
            parser = ua_parser.user_agent_parser.Parse(self.user_agent)
            return parser.get("user_agent", {}).get("family", "Unknown")
        except:
            return "Unknown"

    def _get_os_family(self) -> str:
        """Extract OS family from User-Agent"""
        try:
            parser = ua_parser.user_agent_parser.Parse(self.user_agent)
            return parser.get("os", {}).get("family", "Unknown")
        except:
            return "Unknown"

    def _get_device_family(self) -> str:
        """Extract device family from User-Agent"""
        try:
            parser = ua_parser.user_agent_parser.Parse(self.user_agent)
            device = parser.get("device", {}).get("family", "Unknown")
            return "Mobile" if device == "iPhone" or "Android" in device else device
        except:
            return "Unknown"

    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address for privacy (keep only prefix)"""
        if "." in ip_address:  # IPv4
            parts = ip_address.split(".")
            return ".".join(parts[:2]) + ".x.x"
        elif ":" in ip_address:  # IPv6
            parts = ip_address.split(":")
            return ":".join(parts[:3]) + ":xxxx:xxxx"
        return "unknown"

    def _get_screen_info(self) -> str:
        """Extract screen/resolution info from headers"""
        # Note: In production, this would come from client-side JavaScript
        # For now, we extract what we can from headers
        viewport = self.request.headers.get("viewport-width", "")
        dpr = self.request.headers.get("device-pixel-ratio", "")
        return f"{viewport}x{dpr}" if viewport and dpr else ""

    def _is_mobile_app(self) -> bool:
        """Check if request is from mobile app"""
        return bool(self.request.headers.get("x-mobile-app") or
                    "mobile" in self.user_agent.lower())

    def _is_browser(self) -> bool:
        """Check if request is from web browser"""
        browser_indicators = ["mozilla", "chrome", "safari", "firefox", "edge"]
        return any(indicator in self.user_agent.lower() for indicator in browser_indicators)

    def get_device_metadata(self) -> Dict[str, Any]:
        """
        Get detailed device metadata for audit logging

        Returns:
            Dictionary with device characteristics
        """
        return {
            "fingerprint": self.generate_fingerprint(),
            "user_agent": self.user_agent[:255],
            "browser": self._get_browser_family(),
            "os": self._get_os_family(),
            "device_type": self._get_device_family(),
            "platform": "mobile" if self._is_mobile_app() else "browser" if self._is_browser() else "api",
            "ip_address": self.ip_address,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def is_known_device(self, user_id: str, db) -> bool:
        """
        Check if device is known/trusted for user

        Args:
            user_id: User identifier
            db: Database session

        Returns:
            True if device has been used successfully before
        """
        from ..models.login_attempt import LoginAttempt

        # Check for successful logins from this device
        fingerprint = self.generate_fingerprint()

        known_device = db.query(LoginAttempt).filter(
            LoginAttempt.device_id == fingerprint,
            LoginAttempt.identifier == user_id,
            LoginAttempt.success == True
        ).first()

        return known_device is not None

    def calculate_device_risk_score(self, user_id: str, db) -> Dict[str, Any]:
        """
        Calculate risk score for current device

        Returns:
            Dictionary with risk analysis
        """
        fingerprint = self.generate_fingerprint()

        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        # Get device history
        device_history = db.query(LoginAttempt).filter(
            LoginAttempt.device_id == fingerprint,
            LoginAttempt.identifier == user_id,
            LoginAttempt.attempted_at > cutoff
        ).all()

        # Calculate metrics
        total_attempts = len(device_history)
        failed_attempts = sum(1 for attempt in device_history if not attempt.success)
        success_rate = 0

        if total_attempts > 0:
            success_rate = ((total_attempts - failed_attempts) / total_attempts) * 100

        # Risk scoring
        risk_score = 0
        flags = []

        if failed_attempts > 3:
            risk_score += 30
            flags.append("high_failure_rate")

        if total_attempts == 0:
            risk_score += 40  # New device
            flags.append("new_device")
        elif success_rate < 50:
            risk_score += 20
            flags.append("low_success_rate")

        # Geographic anomaly (simplified)
        unique_ips = set(attempt.ip_address for attempt in device_history if attempt.ip_address)
        if len(unique_ips) > 3:
            risk_score += 25
            flags.append("multiple_ips")

        return {
            "device_id": fingerprint,
            "risk_score": min(risk_score, 100),
            "risk_level": "high" if risk_score > 70 else "medium" if risk_score > 30 else "low",
            "flags": flags,
            "total_attempts": total_attempts,
            "success_rate": round(success_rate, 1),
            "is_new_device": total_attempts == 0
        }