"""Local Wi-Fi and network diagnostics using read-only operating-system commands."""
from __future__ import annotations

import platform
import re
import socket
import subprocess
from datetime import datetime, timezone


def _run_readonly(command: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            check=False, errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.stdout[:20000] if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def local_network_snapshot() -> dict:
    """Return best-effort local adapter/Wi-Fi diagnostics; never retrieves Wi-Fi passwords."""
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = {
        "checked_at": checked_at,
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
        "wifi": {"status": "Unverified", "note": "Wi-Fi details are available only when the OS and adapter expose them."},
        "network": {"status": "Unverified", "ipv4_addresses": [], "default_gateway": None},
        "limitations": ["Read-only local diagnostics; does not disconnect devices, crack Wi-Fi, or retrieve saved passwords."],
    }
    if platform.system() == "Windows":
        wlan = _run_readonly(["netsh", "wlan", "show", "interfaces"])
        if wlan:
            def value(pattern: str) -> str | None:
                match = re.search(pattern, wlan, flags=re.IGNORECASE | re.MULTILINE)
                return match.group(1).strip() if match else None
            ssid = value(r"^\s*SSID\s*:\s*(.+)$")
            # BSSID is a hardware address; intentionally omit it from the default report.
            signal = value(r"^\s*Signal\s*:\s*(\d+%)")
            channel = value(r"^\s*Channel\s*:\s*(\d+)")
            auth = value(r"^\s*Authentication\s*:\s*(.+)$")
            if ssid:
                result["wifi"] = {
                    "status": "Verified",
                    "ssid": ssid,
                    "signal": signal or "Unverified",
                    "channel": channel or "Unverified",
                    "authentication": auth or "Unverified",
                }
            else:
                result["wifi"] = {"status": "Unverified", "note": "No connected Wi-Fi interface was reported by Windows."}
        ipconfig = _run_readonly(["ipconfig"])
        addresses = sorted(set(re.findall(r"IPv4[^:\n]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", ipconfig, flags=re.IGNORECASE)))
        gateway_match = re.search(r"Default Gateway[^:\n]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", ipconfig, flags=re.IGNORECASE)
        gateway = gateway_match.group(1) if gateway_match else None
        result["network"] = {
            "status": "Verified" if addresses else "Unverified",
            "ipv4_addresses": addresses,
            "default_gateway": gateway,
        }
    else:
        result["limitations"].append("Detailed Wi-Fi and gateway parsing is currently implemented for Windows only.")
    return result


def verify_link_target(target: str, web_check) -> dict:
    """Use the existing SSRF-resistant public website checker; report check-level status."""
    result = web_check(target)
    host = result.get("host", "")
    lowered = host.lower()
    shorteners = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "cutt.ly"}
    warnings = []
    if lowered in shorteners or any(lowered.endswith("." + domain) for domain in shorteners):
        warnings.append("URL shortener detected; the final destination is not followed or verified.")
    if "xn--" in lowered:
        warnings.append("Internationalized/punycode hostname: visually similar characters may be present.")
    https = result.get("https", {})
    tls_status = "Verified" if https.get("tls_valid") is True else "Failed" if https.get("tls_valid") is False else "Unverified"
    status = "Suspicious" if warnings else "Verified" if tls_status == "Verified" and https.get("status_code") else "Unverified"
    return {
        "status": status,
        "host": host,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": {
            "dns": "Verified" if result.get("addresses") else "Failed",
            "https_reachability": "Verified" if https.get("status_code") else "Failed",
            "tls_certificate": tls_status,
            "http_reachability": "Verified" if result.get("http", {}).get("status_code") else "Failed",
            "security_headers": "Review",
        },
        "warnings": warnings,
        "details": result,
        "disclaimer": "These checks do not prove a link is harmless. No redirects are followed; a short link's destination remains unverified.",
    }
