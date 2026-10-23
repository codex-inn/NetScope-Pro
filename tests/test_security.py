import pytest
from app.security import hash_password, verify_password, validate_target, validate_ports

def test_password_hash_roundtrip():
    stored = hash_password("a-long-test-password-123")
    assert verify_password("a-long-test-password-123", stored)
    assert not verify_password("wrong-password-123", stored)

def test_password_minimum_length():
    with pytest.raises(ValueError):
        hash_password("short")

def test_scanning_disabled_without_allowlist():
    with pytest.raises(ValueError, match="Scanning is disabled"):
        validate_target("192.0.2.1", raw_allowlist="")

def test_target_must_be_inside_approved_range():
    assert validate_target("192.0.2.0/28", raw_allowlist="192.0.2.0/24") == "192.0.2.0/28"
    with pytest.raises(ValueError, match="not fully contained"):
        validate_target("198.51.100.0/28", raw_allowlist="192.0.2.0/24")

def test_target_size_limit():
    with pytest.raises(ValueError, match="limit is 16"):
        validate_target("192.0.2.0/24", max_hosts=16, raw_allowlist="192.0.2.0/24")

def test_ports_allowlist_and_count():
    assert validate_ports([80, 443]) == [80, 443]
    with pytest.raises(ValueError, match="outside"):
        validate_ports([1])
    with pytest.raises(ValueError, match="At most 2"):
        validate_ports([22, 80, 443], max_ports=2)
