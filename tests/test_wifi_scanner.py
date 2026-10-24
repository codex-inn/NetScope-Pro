from unittest.mock import Mock

import pytest

from app.wifi_scanner import WiFiScanUnavailable, parse_netsh_networks, scan_nearby_networks


SAMPLE = """There are 2 networks currently visible.
SSID 1 : Cafe
    Authentication : WPA2-Personal
    Encryption : CCMP
    BSSID 1 : 00:11:22:33:44:55
         Signal             : 86%
         Radio type         : 802.11ac
         Channel            : 36
    BSSID 2 : 00:11:22:33:44:66
         Signal             : 42%
         Radio type         : 802.11n
         Channel            : 6
SSID 2 :
    Authentication : WPA3-Personal
    Encryption : CCMP
    BSSID 1 : aa:bb:cc:dd:ee:ff
         Signal             : 0%
         Channel            : 14
"""


def test_parse_netsh_output_extracts_bssids_and_derived_band():
    networks = parse_netsh_networks(SAMPLE)
    assert len(networks) == 3
    assert networks[0] == {
        "ssid": "Cafe",
        "bssid": "00:11:22:33:44:55",
        "signal_percent": 86,
        "channel": 36,
        "frequency_mhz": 5180,
        "band": "5 GHz",
        "authentication": "WPA2-Personal",
        "encryption": "CCMP",
        "radio_type": "802.11ac",
    }
    assert networks[1]["channel"] == 6
    assert networks[1]["frequency_mhz"] == 2437
    assert networks[1]["band"] == "2.4 GHz"
    assert networks[2]["ssid"] == ""
    assert networks[2]["frequency_mhz"] == 2484
    assert networks[2]["authentication"] == "WPA3-Personal"


def test_parse_netsh_output_keeps_unknown_values_empty():
    networks = parse_netsh_networks(
        "SSID 1 : Test\n    BSSID 1 : 12:34:56:78:90:ab\n"
        "         Signal : unavailable\n         Channel : n/a\n"
    )
    assert networks[0]["signal_percent"] is None
    assert networks[0]["channel"] is None
    assert networks[0]["frequency_mhz"] is None
    assert networks[0]["band"] is None


def test_scan_runs_fixed_command_with_mocked_output(monkeypatch):
    import app.wifi_scanner as scanner

    run = Mock(return_value=Mock(stdout=SAMPLE))
    monkeypatch.setattr(scanner.sys, "platform", "win32")
    monkeypatch.setattr(scanner.subprocess, "run", run)
    assert len(scan_nearby_networks()) == 3
    run.assert_called_once_with(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        shell=False,
    )


def test_scan_is_rejected_off_windows(monkeypatch):
    import app.wifi_scanner as scanner

    monkeypatch.setattr(scanner.sys, "platform", "linux")
    with pytest.raises(WiFiScanUnavailable, match="only on Windows"):
        scan_nearby_networks()


def test_scan_reports_timeout_without_real_command(monkeypatch):
    import app.wifi_scanner as scanner

    def timeout(*args, **kwargs):
        raise scanner.subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(scanner.sys, "platform", "win32")
    monkeypatch.setattr(scanner.subprocess, "run", timeout)
    with pytest.raises(WiFiScanUnavailable, match="timed out"):
        scan_nearby_networks()
