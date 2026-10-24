from contextlib import nullcontext

import pytest

from app.local_audit import discover_lan, validate_lan_scope


def test_lan_scope_requires_explicit_authorization():
    with pytest.raises(ValueError, match="Confirm"):
        validate_lan_scope("192.168.1.0/24", [80], False)


@pytest.mark.parametrize("target", ["8.8.8.8", "127.0.0.1", "169.254.1.0/24", "192.168.0.0/16", "2001:db8::/64"])
def test_lan_scope_rejects_non_private_or_oversized_targets(target):
    with pytest.raises(ValueError):
        validate_lan_scope(target, [80], True)


def test_lan_scope_rejects_unsupported_ports():
    with pytest.raises(ValueError, match="supported"):
        validate_lan_scope("192.168.1.0/30", [1], True)


def test_discovery_only_reports_successful_tcp_connects():
    calls = []

    def fake_connect(address, timeout):
        calls.append((address, timeout))
        if address == ("192.168.1.1", 80):
            return nullcontext()
        raise TimeoutError()

    result = discover_lan("192.168.1.0/30", [80, 443], True, connect=fake_connect)
    assert result["hosts_checked"] == 4
    assert result["checks_completed"] == 8
    assert result["hosts_found"] == 1
    assert result["hosts"] == [
        {"ip": "192.168.1.0", "hostname": None, "status": "no_response", "response_time_ms": None, "open_ports": []},
        {"ip": "192.168.1.1", "hostname": None, "status": "responding", "response_time_ms": pytest.approx(0, abs=50), "open_ports": [{"port": 80, "state": "open", "latency_ms": pytest.approx(0, abs=50)}]},
        {"ip": "192.168.1.2", "hostname": None, "status": "no_response", "response_time_ms": None, "open_ports": []},
        {"ip": "192.168.1.3", "hostname": None, "status": "no_response", "response_time_ms": None, "open_ports": []},
    ]
    assert all(timeout == 0.35 for _, timeout in calls)


def test_authenticated_workspace_includes_network_tools_scanner(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "current_user", lambda _request: {"id": 1, "username": "test"})
    request = type("Request", (), {"session": {}})()
    response = main_module.web_workspace(request)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert 'id="lan-scan-run"' in response.body.decode("utf-8")
