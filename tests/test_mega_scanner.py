import pytest

from app import mega_scanner


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "192.168.1.20", "::1", "fc00::1"])
def test_normalize_host_rejects_non_public_ip_literals(target):
    with pytest.raises(mega_scanner.TargetError, match="globally routable"):
        mega_scanner.normalize_host(target)


@pytest.mark.parametrize("target", ["8.8.8.8", "https://8.8.8.8/path", "2001:4860:4860::8888"])
def test_normalize_host_preserves_public_ip_literals(target):
    host = mega_scanner.normalize_host(target)
    assert host == target.removeprefix("https://").split("/")[0]


def test_tls_connection_verifies_ip_hostname(monkeypatch):
    class FakeSocket:
        def settimeout(self, _timeout):
            pass

        def connect(self, _address):
            pass

        def close(self):
            pass

    class FakeContext:
        server_hostname = None

        def wrap_socket(self, raw, *, server_hostname):
            self.server_hostname = server_hostname
            return raw

    raw = FakeSocket()
    context = FakeContext()
    monkeypatch.setattr(mega_scanner.socket, "socket", lambda *_args: raw)
    monkeypatch.setattr(mega_scanner.ssl, "create_default_context", lambda: context)

    conn, returned_context = mega_scanner._connect_public("8.8.8.8", "8.8.8.8", 443, True)

    assert conn is raw
    assert returned_context is context
    assert context.server_hostname == "8.8.8.8"

@pytest.mark.parametrize(
    "target",
    ["ftp://example.com", "https://user:pass@example.com", "localhost", "example"],
)
def test_normalize_host_rejects_unsupported_or_ambiguous_targets(target):
    with pytest.raises(mega_scanner.TargetError):
        mega_scanner.normalize_host(target)


def test_dns_resolution_rejects_domain_with_private_address(monkeypatch):
    def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (mega_scanner.socket.AF_INET, mega_scanner.socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
            (mega_scanner.socket.AF_INET, mega_scanner.socket.SOCK_STREAM, 6, "", ("192.168.1.10", 0)),
        ]

    monkeypatch.setattr(mega_scanner.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(mega_scanner.TargetError, match="non-public address"):
        mega_scanner.resolve_public_host("example.com")


def test_dns_resolution_returns_public_addresses(monkeypatch):
    def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (mega_scanner.socket.AF_INET, mega_scanner.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        ]

    monkeypatch.setattr(mega_scanner.socket, "getaddrinfo", fake_getaddrinfo)
    result = mega_scanner.resolve_public_host("example.com")
    assert result["host"] == "example.com"
    assert result["addresses"] == [{"address": "8.8.8.8", "family": "IPv4"}]
    assert result["checked_at"]


def test_web_check_does_not_follow_redirects_and_reports_headers(monkeypatch):
    calls = []

    def fake_request(host, ip_text, port, use_tls):
        calls.append((host, ip_text, port, use_tls))
        if use_tls:
            return {
                "reachable": True, "scheme": "https", "status_code": 301,
                "status_text": "Moved Permanently", "headers": {"strict-transport-security": "max-age=31536000"},
                "missing_security_headers": [name for name in mega_scanner.SECURITY_HEADERS if name != "strict-transport-security"],
                "tls": {"verified": True, "version": "TLSv1.3"}, "error": None,
            }
        return {
            "reachable": True, "scheme": "http", "status_code": 301,
            "status_text": "Moved Permanently", "headers": {},
            "missing_security_headers": list(mega_scanner.SECURITY_HEADERS), "tls": None, "error": None,
        }

    monkeypatch.setattr(mega_scanner, "resolve_public_host", lambda _target: {
        "host": "example.com", "canonical_name": "example.com",
        "addresses": [{"address": "8.8.8.8", "family": "IPv4"}], "checked_at": "2026-10-23T00:00:00+00:00",
    })
    monkeypatch.setattr(mega_scanner, "_request", fake_request)
    result = mega_scanner.web_check("https://example.com")
    assert result["https"]["status_code"] == 301
    assert result["http"]["status_code"] == 301
    assert len(calls) == 2
    assert [call[2] for call in calls] == [443, 80]
    assert all(call[0] == "example.com" for call in calls)
    assert any("redirects were not followed" in note for note in result["notes"])

