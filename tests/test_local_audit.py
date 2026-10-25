from app.local_audit import local_network_snapshot, verify_link_target


def test_link_verification_reports_specific_checks_and_caveat():
    def fake_check(_target):
        return {
            "host": "example.com",
            "addresses": [{"address": "93.184.216.34"}],
            "https": {"status_code": 200, "tls": {"verified": True}},
            "http": {"status_code": 301},
        }
    result = verify_link_target("https://example.com", fake_check)
    assert result["status"] == "Verified"
    assert result["checks"]["dns"] == "Verified"
    assert result["checks"]["tls_certificate"] == "Verified"
    assert "do not prove" in result["disclaimer"]


def test_shortened_link_is_not_claimed_safe():
    def fake_check(_target):
        return {
            "host": "bit.ly",
            "addresses": [{"address": "93.184.216.34"}],
            "https": {"status_code": 200, "tls": {"verified": True}},
            "http": {"status_code": 301},
        }
    result = verify_link_target("https://bit.ly/abc", fake_check)
    assert result["status"] == "Suspicious"
    assert result["warnings"]


def test_local_snapshot_has_status_and_no_password_field():
    result = local_network_snapshot()
    assert "wifi" in result and "network" in result
    assert result["wifi"]["status"] in {"Verified", "Unverified"}
    assert "password" not in result["wifi"]



def test_lan_scope_requires_explicit_authorization_and_private_cidr():
    import pytest
    from app.local_audit import validate_lan_scope

    with pytest.raises(ValueError, match="Confirm"):
        validate_lan_scope("192.168.1.0/24", [80], False)
    with pytest.raises(ValueError, match="RFC1918"):
        validate_lan_scope("8.8.8.0/24", [80], True)
    with pytest.raises(ValueError, match="limit"):
        validate_lan_scope("192.168.0.0/16", [80], True)
    with pytest.raises(ValueError, match="supported"):
        validate_lan_scope("192.168.1.0/24", [1], True)


def test_lan_scan_returns_all_addresses_status_and_progress():
    from app.local_audit import discover_lan

    class FakeConnection:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    def fake_connect(address, timeout):
        ip, port = address
        assert timeout <= 0.35
        if ip == "192.168.1.1" and port == 80:
            return FakeConnection()
        raise OSError("closed or filtered")

    result = discover_lan("192.168.1.0/30", [80], True, connect=fake_connect, arp_output="" )
    assert result["hosts_checked"] == 4
    assert result["checks_completed"] == 4
    assert result["hosts_found"] == 1
    assert result["progress"] == {"completed": 4, "total": 4, "percent": 100}
    assert len(result["hosts"]) == 4
    found = next(host for host in result["hosts"] if host["ip"] == "192.168.1.1")
    assert found["status"] == "responding"
    assert found["open_ports"][0]["port"] == 80
    quiet = next(host for host in result["hosts"] if host["ip"] == "192.168.1.2")
    assert quiet["status"] == "no_response"
    assert quiet["hostname"] is None


def test_auto_subnet_detection_prefers_private_network_with_gateway(monkeypatch):
    import app.local_audit as audit

    monkeypatch.setattr(audit.platform, "system", lambda: "Windows")
    monkeypatch.setattr(audit, "_run_readonly", lambda _command: """Ethernet adapter Wi-Fi:
   IPv4 Address. . . . . . . . . . . : 192.168.1.25
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Ethernet adapter Virtual:
   IPv4 Address. . . . . . . . . . . : 10.0.0.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
""")
    assert audit.detect_local_private_cidr() == "192.168.1.0/24"


def test_auto_subnet_detection_rejects_non_windows(monkeypatch):
    import app.local_audit as audit
    import pytest

    monkeypatch.setattr(audit.platform, "system", lambda: "Linux")
    with pytest.raises(ValueError, match="Windows"):
        audit.detect_local_private_cidr()


def test_discover_lan_supports_auto_target(monkeypatch):
    import app.local_audit as audit

    monkeypatch.setattr(audit, "detect_local_private_cidr", lambda: "192.168.1.0/30")
    class FakeConnection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
    def fake_connect(address, timeout):
        if address == ("192.168.1.1", 80): return FakeConnection()
        raise OSError("closed")
    result = audit.discover_lan("auto", [80], True, connect=fake_connect, arp_output="" )
    assert result["target"] == "192.168.1.0/30"
    assert result["hosts_checked"] == 4
