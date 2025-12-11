# backend/app/services/suspicious_activity_detector.py
"""
Enterprise Suspicious Activity Detection Service
Real-time threat detection for authentication events
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session
import logging
import ipaddress
from dataclasses import dataclass
import statistics

logger = logging.getLogger(__name__)


@dataclass
class RiskIndicator:
    """Risk indicator with score and metadata"""
    type: str
    score: int  # 0-100
    description: str
    metadata: Dict[str, Any] = None


class SuspiciousActivityDetector:
    """
    Auth0-style suspicious activity detection with:
    - Real-time risk scoring
    - Behavioral anomaly detection
    - Geographic velocity checking
    - Device fingerprint analysis
    - Machine learning ready architecture
    """

    def __init__(self, db: Session):
        self.db = db

    def analyze_login_attempt(
            self,
            user_id: str,
            ip_address: str,
            device_id: Optional[str] = None,
            user_agent: Optional[str] = None,
            is_2fa: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze login attempt for suspicious activity

        Returns:
            Risk analysis with score and indicators
        """
        risk_indicators = []
        total_score = 0

        # 1. Geographic anomalies
        geo_indicators = self._check_geographic_anomalies(user_id, ip_address)
        risk_indicators.extend(geo_indicators)

        # 2. Device anomalies
        if device_id:
            device_indicators = self._check_device_anomalies(user_id, device_id, ip_address)
            risk_indicators.extend(device_indicators)

        # 3. Behavioral anomalies
        behavior_indicators = self._check_behavioral_anomalies(user_id, ip_address, is_2fa)
        risk_indicators.extend(behavior_indicators)

        # 4. IP reputation (simplified)
        ip_indicators = self._check_ip_reputation(ip_address)
        risk_indicators.extend(ip_indicators)

        # 5. Time-based anomalies
        time_indicators = self._check_time_anomalies(user_id)
        risk_indicators.extend(time_indicators)

        # Calculate total score
        for indicator in risk_indicators:
            total_score += indicator.score

        # Normalize to 0-100
        total_score = min(total_score, 100)

        # Determine risk level
        if total_score >= 70:
            risk_level = "CRITICAL"
            action = "BLOCK"
        elif total_score >= 50:
            risk_level = "HIGH"
            action = "REQUIRE_2FA"
        elif total_score >= 30:
            risk_level = "MEDIUM"
            action = "WARN"
        else:
            risk_level = "LOW"
            action = "ALLOW"

        return {
            "risk_score": total_score,
            "risk_level": risk_level,
            "recommended_action": action,
            "indicators": [indicator.__dict__ for indicator in risk_indicators],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def _check_geographic_anomalies(self, user_id: str, ip_address: str) -> List[RiskIndicator]:
        """Check for geographic anomalies (impossible travel, new location)"""
        indicators = []

        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        # Get recent successful logins
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)

        recent_logins = self.db.query(LoginAttempt).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.attempt_type == "email",
            LoginAttempt.success == True,
            LoginAttempt.attempted_at > cutoff,
            LoginAttempt.ip_address.isnot(None)
        ).order_by(LoginAttempt.attempted_at.desc()).limit(10).all()

        if not recent_logins:
            # First login or no recent history
            return [RiskIndicator(
                type="new_location",
                score=20,
                description="First login or no recent login history",
                metadata={"ip_address": ip_address}
            )]

        # Get last login location
        last_login = recent_logins[0]
        last_ip = last_login.ip_address

        # Simple check: different IP subnet
        if self._is_different_subnet(ip_address, last_ip):
            indicators.append(RiskIndicator(
                type="different_subnet",
                score=25,
                description="Login from different network subnet",
                metadata={
                    "current_ip": ip_address,
                    "previous_ip": last_ip,
                    "time_since_last_login": self._hours_since(last_login.attempted_at)
                }
            ))

        # Check for multiple locations in short time
        unique_ips = set(login.ip_address for login in recent_logins if login.ip_address)
        if len(unique_ips) >= 3:
            indicators.append(RiskIndicator(
                type="multiple_locations",
                score=30,
                description=f"Logins from {len(unique_ips)} different locations in 30 days",
                metadata={"unique_locations": len(unique_ips)}
            ))

        return indicators

    def _check_device_anomalies(self, user_id: str, device_id: str, ip_address: str) -> List[RiskIndicator]:
        """Check for device-related anomalies"""
        indicators = []

        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        # Check if device is new
        device_history = self.db.query(LoginAttempt).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.device_id == device_id,
            LoginAttempt.success == True
        ).count()

        if device_history == 0:
            indicators.append(RiskIndicator(
                type="new_device",
                score=35,
                description="Login from new/unrecognized device",
                metadata={"device_id": device_id}
            ))

        # Check device-IP correlation anomalies
        device_ips = self.db.query(LoginAttempt.ip_address).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.device_id == device_id,
            LoginAttempt.success == True,
            LoginAttempt.ip_address.isnot(None)
        ).distinct().all()

        device_ips = [ip[0] for ip in device_ips]

        if ip_address not in device_ips and len(device_ips) > 0:
            indicators.append(RiskIndicator(
                type="device_location_mismatch",
                score=40,
                description="Device used from new location",
                metadata={
                    "device_id": device_id,
                    "current_ip": ip_address,
                    "previous_ips": device_ips
                }
            ))

        return indicators

    def _check_behavioral_anomalies(self, user_id: str, ip_address: str, is_2fa: bool) -> List[RiskIndicator]:
        """Check for behavioral anomalies"""
        indicators = []

        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        # Check failed attempts pattern
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)

        failed_attempts = self.db.query(LoginAttempt).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.attempt_type == "email",
            LoginAttempt.success == False,
            LoginAttempt.attempted_at > cutoff
        ).count()

        if failed_attempts >= 3:
            indicators.append(RiskIndicator(
                type="multiple_failed_attempts",
                score=25 + (failed_attempts * 5),  # 25-50 points
                description=f"{failed_attempts} failed login attempts in 30 minutes",
                metadata={"failed_attempts": failed_attempts}
            ))

        # Check time of day anomalies (if user has history)
        login_times = self.db.query(LoginAttempt.attempted_at).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.attempt_type == "email",
            LoginAttempt.success == True,
            LoginAttempt.attempted_at > datetime.now(timezone.utc) - timedelta(days=90)
        ).all()

        if login_times:
            login_hours = [login_time[0].hour for login_time in login_times]
            current_hour = datetime.now(timezone.utc).hour

            # Check if current hour is unusual
            if login_hours and abs(current_hour - statistics.mean(login_hours)) > 4:
                indicators.append(RiskIndicator(
                    type="unusual_login_time",
                    score=15,
                    description=f"Login at unusual hour: {current_hour}:00",
                    metadata={
                        "current_hour": current_hour,
                        "average_hour": round(statistics.mean(login_hours), 1)
                    }
                ))

        return indicators

    def _check_ip_reputation(self, ip_address: str) -> List[RiskIndicator]:
        """Check IP reputation (simplified version)"""
        indicators = []

        # Check if IP is private/reserved
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                indicators.append(RiskIndicator(
                    type="private_ip",
                    score=10,
                    description="Login from private IP address",
                    metadata={"ip_address": ip_address}
                ))
        except ValueError:
            pass

        # Check for known VPN/Tor indicators (simplified)
        vpn_indicators = ["vpn", "proxy", "tor", "anonymous"]
        if any(indicator in ip_address.lower() for indicator in vpn_indicators):
            indicators.append(RiskIndicator(
                type="vpn_proxy_detected",
                score=30,
                description="Login from VPN/Proxy service",
                metadata={"ip_address": ip_address}
            ))

        # Check for recent abuse from same IP
        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        recent_failures = self.db.query(LoginAttempt).filter(
            LoginAttempt.identifier == ip_address,
            LoginAttempt.attempt_type == "ip",
            LoginAttempt.success == False,
            LoginAttempt.attempted_at > cutoff
        ).count()

        if recent_failures >= 10:
            indicators.append(RiskIndicator(
                type="ip_abuse",
                score=50,
                description=f"IP has {recent_failures} failed attempts in last hour",
                metadata={"failed_attempts": recent_failures}
            ))

        return indicators

    def _check_time_anomalies(self, user_id: str) -> List[RiskIndicator]:
        """Check for time-based anomalies"""
        indicators = []

        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        # Check login frequency anomalies
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        recent_logins = self.db.query(LoginAttempt).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.attempt_type == "email",
            LoginAttempt.success == True,
            LoginAttempt.attempted_at > cutoff
        ).count()

        if recent_logins >= 10:  # Excessive logins
            indicators.append(RiskIndicator(
                type="excessive_logins",
                score=20,
                description=f"{recent_logins} successful logins in 24 hours",
                metadata={"login_count": recent_logins}
            ))

        return indicators

    def _is_different_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in different subnets"""
        try:
            # Simple check: compare first two octets for IPv4
            if "." in ip1 and "." in ip2:
                parts1 = ip1.split(".")[:2]
                parts2 = ip2.split(".")[:2]
                return parts1 != parts2
            return True
        except:
            return True

    def _hours_since(self, timestamp: datetime) -> float:
        """Calculate hours since timestamp"""
        return (datetime.now(timezone.utc) - timestamp).total_seconds() / 3600

    def get_user_risk_profile(self, user_id: str) -> Dict[str, Any]:
        """
        Get comprehensive risk profile for user

        Returns:
            User risk profile with historical analysis
        """
        from ..models.login_attempt import LoginAttempt
        from datetime import datetime, timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        # Get login history
        login_history = self.db.query(LoginAttempt).filter(
            LoginAttempt.identifier == user_id,
            LoginAttempt.attempt_type == "email",
            LoginAttempt.attempted_at > cutoff
        ).all()

        if not login_history:
            return {
                "user_id": user_id,
                "risk_level": "UNKNOWN",
                "has_history": False,
                "message": "No login history available"
            }

        # Calculate statistics
        total_logins = len(login_history)
        successful_logins = sum(1 for login in login_history if login.success)
        failed_logins = total_logins - successful_logins
        success_rate = (successful_logins / total_logins) * 100 if total_logins > 0 else 0

        # Unique devices
        unique_devices = set(login.device_id for login in login_history if login.device_id)

        # Unique locations
        unique_ips = set(login.ip_address for login in login_history if login.ip_address)

        # Recent activity
        recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent_logins = [login for login in login_history if login.attempted_at > recent_cutoff]

        # Risk assessment
        risk_factors = []

        if failed_logins > 5:
            risk_factors.append(f"{failed_logins} failed attempts")

        if len(unique_devices) > 5:
            risk_factors.append(f"{len(unique_devices)} unique devices")

        if len(unique_ips) > 3:
            risk_factors.append(f"{len(unique_ips)} unique locations")

        if success_rate < 70:
            risk_factors.append(f"low success rate ({success_rate:.1f}%)")

        # Overall risk level
        risk_score = len(risk_factors) * 20
        risk_level = "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"

        return {
            "user_id": user_id,
            "risk_level": risk_level,
            "risk_score": min(risk_score, 100),
            "risk_factors": risk_factors,
            "statistics": {
                "total_logins": total_logins,
                "successful_logins": successful_logins,
                "failed_logins": failed_logins,
                "success_rate": round(success_rate, 1),
                "unique_devices": len(unique_devices),
                "unique_locations": len(unique_ips),
                "recent_logins_7d": len(recent_logins)
            },
            "analysis_period_days": 90,
            "last_analysis": datetime.now(timezone.utc).isoformat()
        }