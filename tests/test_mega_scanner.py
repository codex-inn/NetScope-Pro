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

    def fake_request(host, ip_text, port, use_tls, path="/"):
        calls.append((host, ip_text, port, use_tls, path))
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
    monkeypatch.setattr(mega_scanner, "dns_security_check", lambda _host, _selector=None: {
        "checked_at": "2026-10-23T00:00:00+00:00", "records": {},
        "policies": {
            "spf": {"status": "missing", "values": []},
            "dmarc": {"status": "missing", "values": []},
            "caa": {"status": "missing", "values": []},
            "dkim": {"status": "not_requested", "selector": None, "values": []},
        },
    })
    result = mega_scanner.web_check("https://example.com", allowed_hosts=["example.com"])
    assert result["https"]["status_code"] == 301
    assert result["http"]["status_code"] == 301
    assert len(calls) == 2
    assert [call[2] for call in calls] == [443, 80]
    assert all(call[0] == "example.com" for call in calls)
    assert result["findings"]
    assert all(finding["confirmed_vulnerability"] is False for finding in result["findings"])
    assert any("never followed" in note for note in result["notes"])



def test_dns_security_check_queries_dkim_only_when_selector_is_supplied():
    calls = []

    def query(name, record_type):
        calls.append((name, record_type))
        if name == "example.com" and record_type == "TXT":
            return {"Status": 0, "Answer": [{"data": "v=spf1 include:mail.example -all"}]}
        if name == "_dmarc.example.com":
            return {"Status": 0, "Answer": [{"data": "v=DMARC1; p=reject"}]}
        if name == "example.com" and record_type == "CAA":
            return {"Status": 0, "Answer": [{"data": '0 issue "ca.example"'}]}
        if name == "selector1._domainkey.example.com":
            return {"Status": 0, "Answer": [{"data": "v=DKIM1; k=rsa; p=public-key"}]}
        return {"Status": 0}

    report = mega_scanner.dns_security_check("example.com", "selector1", query=query)
    assert ("selector1._domainkey.example.com", "TXT") in calls
    assert report["policies"]["spf"]["status"] == "present"
    assert report["policies"]["dmarc"]["status"] == "present"
    assert report["policies"]["caa"]["status"] == "present"
    assert report["policies"]["dkim"]["status"] == "present"
    assert mega_scanner.dns_security_check("example.com", query=query)["policies"]["dkim"]["status"] == "not_requested"
    assert not any(name.endswith("._domainkey.example.com") for name, _ in calls[-3:])


@pytest.mark.parametrize("selector", ["", ".", "bad selector", "x" * 64, "selector._domainkey"])
def test_dns_security_check_rejects_invalid_dkim_selector(selector):
    with pytest.raises(mega_scanner.TargetError, match="DKIM selector"):
        mega_scanner.dns_security_check("example.com", selector, query=lambda *_: {"Status": 0})


def test_web_check_rejects_non_allowlisted_host_before_dns_lookup(monkeypatch):
    def unexpected_resolution(_target):
        raise AssertionError("must not resolve an unauthorized host")

    monkeypatch.setattr(mega_scanner, "resolve_public_host", unexpected_resolution)
    with pytest.raises(mega_scanner.TargetError, match="AUTHORIZED_WEB_HOSTS"):
        mega_scanner.web_check("example.com", allowed_hosts=["owned.example"])


def test_redirect_chain_records_external_location_without_following(monkeypatch):
    calls = []

    def fake_request(host, ip_text, port, use_tls, path="/"):
        calls.append((host, ip_text, port, use_tls, path))
        return {
            "reachable": True, "scheme": "https" if use_tls else "http", "status_code": 302,
            "headers": {"location": "https://other.example/login"}, "cookie_summary": [],
            "missing_security_headers": list(mega_scanner.SECURITY_HEADERS),
            "tls": {"verified": True, "version": "TLSv1.3"} if use_tls else None, "error": None,
        }

    monkeypatch.setattr(mega_scanner, "_request", fake_request)
    result = mega_scanner._follow_redirects("example.com", "8.8.8.8", "https")
    assert len(calls) == 1
    assert result["external_redirect"] == "https://other.example/login"
    assert result["redirect_chain"] == [{
        "status_code": 302, "from": "https://example.com/", "to": "https://other.example/login", "followed": False
    }]


def test_redirect_chain_follows_only_same_host_and_keeps_path(monkeypatch):
    calls = []

    def fake_request(host, ip_text, port, use_tls, path="/"):
        calls.append((port, use_tls, path))
        if len(calls) == 1:
            return {"reachable": True, "status_code": 302, "headers": {"location": "/secure?from=home"}, "cookie_summary": [], "tls": None, "error": None}
        return {"reachable": True, "status_code": 200, "headers": {}, "cookie_summary": [], "tls": None, "error": None}

    monkeypatch.setattr(mega_scanner, "_request", fake_request)
    result = mega_scanner._follow_redirects("example.com", "8.8.8.8", "http")
    assert calls == [(80, False, "/"), (80, False, "/secure?from=home")]
    assert result["final_url"] == "http://example.com/secure?from=home"
    assert result["redirect_chain"][0]["followed"] is True


def test_findings_include_evidence_explanation_and_fix_without_claiming_vulnerability():
    tls = {"verified": True, "version": "TLSv1.3", "not_after": "Dec 01 00:00:00 2026 GMT", "days_remaining": 12}
    https = {"tls": tls, "final_url": "https://example.com/", "headers": {}, "cookie_summary": []}
    http = {"reachable": True, "status_code": 200}
    dns = {"policies": {
        "spf": {"status": "missing", "values": []},
        "dmarc": {"status": "missing", "values": []},
        "caa": {"status": "missing", "values": []},
        "dkim": {"status": "not_requested", "values": []},
    }}
    findings = mega_scanner._security_findings(https, http, dns)
    expiry = next(f for f in findings if f["title"] == "TLS certificate expires soon")
    assert expiry["severity"] == "high"
    assert expiry["evidence"] and expiry["impact"] and expiry["remediation"]
    assert all(f["confirmed_vulnerability"] is False for f in findings)


@pytest.mark.parametrize("target", ["https://example.com:8443/", "http://example.com:8080/"])
def test_web_check_rejects_nonstandard_ports_before_dns_lookup(monkeypatch, target):
    def unexpected_resolution(_target):
        raise AssertionError("unsupported port must be rejected before DNS")

    monkeypatch.setattr(mega_scanner, "resolve_public_host", unexpected_resolution)
    with pytest.raises(mega_scanner.TargetError, match="standard HTTP and HTTPS ports"):
        mega_scanner.web_check(target, allowed_hosts=["example.com"])

