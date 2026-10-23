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

