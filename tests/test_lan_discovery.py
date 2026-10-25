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


def test_discovery_reports_only_observed_hosts_when_arp_is_empty():
    calls = []

    def fake_connect(address, timeout):
        calls.append((address, timeout))
        if address == ("192.168.1.1", 80):
            return nullcontext()
        raise TimeoutError()

    result = discover_lan("192.168.1.0/30", [80, 443], True, connect=fake_connect, arp_output="" )
    assert result["hosts_checked"] == 4
    assert result["checks_completed"] == 8
    assert result["hosts_found"] == 1
    assert result["hosts"] == [
        {"ip": "192.168.1.0", "hostname": None, "mac_address": None, "neighbor_type": None, "status": "no_response", "response_time_ms": None, "open_ports": []},
        {"ip": "192.168.1.1", "hostname": None, "mac_address": None, "neighbor_type": None, "status": "responding", "response_time_ms": pytest.approx(0, abs=50), "open_ports": [{"port": 80, "state": "open", "latency_ms": pytest.approx(0, abs=50)}]},
        {"ip": "192.168.1.2", "hostname": None, "mac_address": None, "neighbor_type": None, "status": "no_response", "response_time_ms": None, "open_ports": []},
        {"ip": "192.168.1.3", "hostname": None, "mac_address": None, "neighbor_type": None, "status": "no_response", "response_time_ms": None, "open_ports": []},
    ]
    assert all(timeout == 0.35 for _, timeout in calls)



def test_parse_arp_neighbors_keeps_only_addresses_in_target_network():
    from app.local_audit import parse_arp_neighbors

    sample = """Interface: 192.168.1.25 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.2           00-11-22-33-44-55     static
  10.0.0.8              66-77-88-99-aa-bb     dynamic
"""
    assert parse_arp_neighbors(sample, "192.168.1.0/24") == {
        "192.168.1.1": {"mac_address": "aa:bb:cc:dd:ee:ff", "neighbor_type": "dynamic"},
        "192.168.1.2": {"mac_address": "00:11:22:33:44:55", "neighbor_type": "static"},
    }


def test_discovery_merges_mocked_arp_neighbors_with_tcp_results():
    class FakeConnection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    def fake_connect(address, timeout):
        if address == ("192.168.1.1", 80):
            return FakeConnection()
        raise OSError("closed")

    arp = "  192.168.1.2           00-11-22-33-44-55     dynamic"
    result = discover_lan(
        "192.168.1.0/30", [80], True, connect=fake_connect, arp_output=arp
    )
    assert result["hosts_found"] == 2
    assert result["tcp_responding_hosts"] == 1
    assert result["arp_neighbors_found"] == 1
    responder = next(host for host in result["hosts"] if host["ip"] == "192.168.1.1")
    cached = next(host for host in result["hosts"] if host["ip"] == "192.168.1.2")
    assert responder["status"] == "responding"
    assert cached["status"] == "arp_cached"
    assert cached["mac_address"] == "00:11:22:33:44:55"
    assert cached["open_ports"] == []

def test_authenticated_workspace_includes_network_tools_scanner(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "current_user", lambda _request: {"id": 1, "username": "test"})
    request = type("Request", (), {"session": {}})()
    response = main_module.web_workspace(request)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert 'id="lan-scan-run"' in response.body.decode("utf-8")
