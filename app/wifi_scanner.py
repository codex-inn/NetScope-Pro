"""Read-only nearby Wi-Fi network discovery for Windows."""
from __future__ import annotations

import re
import subprocess
import sys
from typing import Any


class WiFiScanUnavailable(RuntimeError):
    """The local Windows Wi-Fi scan could not be completed."""


def _channel_details(channel: int | None) -> tuple[int | None, str | None]:
    if channel is None:
        return None, None
    if 1 <= channel <= 13:
        return 2407 + 5 * channel, "2.4 GHz"
    if channel == 14:
        return 2484, "2.4 GHz"
    if 32 <= channel <= 177:
        return 5000 + 5 * channel, "5 GHz"
    return None, None


def parse_netsh_networks(output: str) -> list[dict[str, Any]]:
    """Parse English netsh output without invoking the local scan command."""
    networks: list[dict[str, Any]] = []
    ssid: str | None = None
    shared: dict[str, str | None] = {}
    current: dict[str, Any] | None = None

    def finish() -> None:
        if current and current.get("bssid"):
            channel = current.get("channel")
            frequency, band = _channel_details(channel)
            networks.append({
                "ssid": ssid or "",
                "bssid": current["bssid"],
                "signal_percent": current.get("signal_percent"),
                "channel": channel,
                "frequency_mhz": frequency,
                "band": band,
                "authentication": current.get("authentication") or shared.get("authentication"),
                "encryption": current.get("encryption") or shared.get("encryption"),
                "radio_type": current.get("radio_type") or shared.get("radio_type"),
            })

    for line in output.splitlines():
        match = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*?)\s*$", line, re.IGNORECASE)
        if match:
            finish()
            ssid = match.group(1)
            shared = {}
            current = None
            continue
        match = re.match(r"^\s*BSSID\s+\d+\s*:\s*(.*?)\s*$", line, re.IGNORECASE)
        if match:
            finish()
            current = {"bssid": match.group(1).strip()}
            continue
        match = re.match(r"^\s*(Authentication|Encryption|Signal|Channel|Radio type)\s*:\s*(.*?)\s*$", line, re.IGNORECASE)
        if not match:
            continue
        name, value = match.group(1).casefold(), match.group(2).strip()
        target = current if current is not None else shared
        if name in {"authentication", "encryption", "radio type"}:
            key = {"radio type": "radio_type"}.get(name, name)
            target[key] = value or None
        elif name == "signal" and current is not None:
            signal = re.search(r"(\d{1,3})\s*%", value)
            current["signal_percent"] = min(100, int(signal.group(1))) if signal else None
        elif name == "channel" and current is not None:
            number = re.search(r"\d+", value)
            current["channel"] = int(number.group()) if number else None
    finish()
    return networks


def scan_nearby_networks() -> list[dict[str, Any]]:
    """Run the fixed read-only Windows command and parse its output."""
    if sys.platform != "win32":
        raise WiFiScanUnavailable("Nearby Wi-Fi scanning is supported only on Windows.")
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise WiFiScanUnavailable("Windows netsh was not found.") from exc
    except subprocess.TimeoutExpired as exc:
        raise WiFiScanUnavailable("Windows Wi-Fi scan timed out after 20 seconds.") from exc
    except subprocess.CalledProcessError as exc:
        raise WiFiScanUnavailable("Windows netsh could not complete the Wi-Fi scan.") from exc
    return parse_netsh_networks(result.stdout or "")
