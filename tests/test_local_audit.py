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
