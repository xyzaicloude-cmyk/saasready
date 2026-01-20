"""
Unit Tests for Device Fingerprinting
"""

def test_device_fingerprint_is_deterministic():
    """Test same device generates same fingerprint"""
    from app.services.device_fingerprint import DeviceFingerprinter
    from unittest.mock import Mock

    # Mock request
    request = Mock()
    request.headers = {
        "user-agent": "Mozilla/5.0 Chrome/120.0",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate"
    }
    request.client = Mock()
    request.client.host = "192.168.1.1"

    fp1 = DeviceFingerprinter(request)
    fp2 = DeviceFingerprinter(request)

    assert fp1.generate_fingerprint() == fp2.generate_fingerprint()

def test_device_fingerprint_changes_with_user_agent():
    """Test fingerprint changes when user agent changes"""
    from app.services.device_fingerprint import DeviceFingerprinter
    from unittest.mock import Mock

    request1 = Mock()
    request1.headers = {"user-agent": "Chrome/120.0"}
    request1.client = Mock()
    request1.client.host = "192.168.1.1"

    request2 = Mock()
    request2.headers = {"user-agent": "Firefox/120.0"}
    request2.client = Mock()
    request2.client.host = "192.168.1.1"

    fp1 = DeviceFingerprinter(request1).generate_fingerprint()
    fp2 = DeviceFingerprinter(request2).generate_fingerprint()

    assert fp1 != fp2