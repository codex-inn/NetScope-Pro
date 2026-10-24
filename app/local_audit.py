"""Read-only local Wi-Fi and public-link diagnostics."""
from __future__ import annotations
import concurrent.futures
import ipaddress
import platform, re, socket, subprocess, time, threading
from datetime import datetime, timezone


LAN_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8443)
LAN_MAX_HOSTS = 256
LAN_MAX_CONCURRENCY = 32
LAN_CONNECT_TIMEOUT = 0.35
RFC1918_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_lan_connection_slots = threading.BoundedSemaphore(LAN_MAX_CONCURRENCY)


def validate_lan_scope(target: str, ports: list[int], authorized: bool) -> tuple[ipaddress.IPv4Network, list[int]]:
    """Validate explicit LAN discovery scope before any sockets are opened."""
    if authorized is not True:
        raise ValueError("Confirm that you own or are authorized to assess this private LAN.")
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Enter a valid private IPv4 address or CIDR.") from exc
    if network.version != 4 or not any(network.subnet_of(allowed) for allowed in RFC1918_NETWORKS):
        raise ValueError("Only RFC1918 private IPv4 addresses and networks are accepted.")
    if network.num_addresses > LAN_MAX_HOSTS:
        raise ValueError(f"Target contains {network.num_addresses} addresses; limit is {LAN_MAX_HOSTS}.")
    if not isinstance(ports, list) or not ports or len(ports) > len(LAN_PORTS):
        raise ValueError(f"Choose between 1 and {len(LAN_PORTS)} supported TCP ports.")
    if any(type(port) is not int or port not in LAN_PORTS for port in ports):
        raise ValueError("One or more ports are outside the supported LAN TCP port list.")
    return network, list(dict.fromkeys(ports))


def discover_lan(target: str, ports: list[int], authorized: bool, *, connect=socket.create_connection) -> dict:
    """Bounded TCP connect discovery; reports only hosts that accept selected ports."""
    network, selected_ports = validate_lan_scope(target, ports, authorized)
    started = time.monotonic()
    tasks = [(str(host), port) for host in network for port in selected_ports]
    open_by_host: dict[str, list[dict]] = {}

    def probe(ip: str, port: int):
        began = time.monotonic()
        _lan_connection_slots.acquire()
        try:
            with connect((ip, port), timeout=LAN_CONNECT_TIMEOUT):
                return ip, {"port": port, "state": "open", "latency_ms": round((time.monotonic() - began) * 1000, 2)}
        except (OSError, TimeoutError):
            return None
        finally:
            _lan_connection_slots.release()

    with concurrent.futures.ThreadPoolExecutor(max_workers=LAN_MAX_CONCURRENCY) as pool:
        for result in pool.map(lambda item: probe(*item), tasks):
            if result:
                ip, port_result = result
                open_by_host.setdefault(ip, []).append(port_result)
    # Include every address in the bounded target range so the UI can distinguish
    # responding hosts from addresses that did not answer the selected TCP ports.
    hosts = []
    for address in network:
        ip = str(address)
        found = sorted(open_by_host.get(ip, []), key=lambda item: item["port"])
        hosts.append({
            "ip": ip,
            "hostname": None,
            "status": "responding" if found else "no_response",
            "response_time_ms": min((item["latency_ms"] for item in found), default=None),
            "open_ports": found,
        })
    return {
        "target": str(network), "ports": selected_ports, "hosts_checked": network.num_addresses,
        "checks_completed": len(tasks), "hosts_found": len(open_by_host), "hosts": hosts,
        "progress": {"completed": len(tasks), "total": len(tasks), "percent": 100},
        "duration_seconds": round(time.monotonic() - started, 2),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": "TCP connect only",
        "limitations": ["A host is marked responding only if it accepts a selected TCP connection; filtered hosts may still exist.",
                        "Hostname reverse lookup is not performed; hostname is null when not resolved.",
                        "No service exploitation, UDP probing, or OS fingerprinting is performed."],
    }


def _run_readonly(command: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                check=False, errors="replace",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.stdout[:20000] if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def local_network_snapshot() -> dict:
    """Return best-effort adapter details; never reads saved Wi-Fi passwords."""
    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platform": platform.platform(), "hostname": socket.gethostname(),
        "wifi": {"status": "Unverified", "note": "Wi-Fi details depend on OS and adapter support."},
        "network": {"status": "Unverified", "ipv4_addresses": [], "default_gateway": None},
        "limitations": ["Read-only diagnostics; does not disconnect devices, crack Wi-Fi, or retrieve saved passwords."],
    }
    if platform.system() == "Windows":
        wlan = _run_readonly(["netsh", "wlan", "show", "interfaces"])
        def value(pattern: str) -> str | None:
            match = re.search(pattern, wlan, flags=re.IGNORECASE | re.MULTILINE)
            return match.group(1).strip() if match else None
        ssid = value(r"^\s*SSID\s*:\s*(.+)$") if wlan else None
        if ssid:
            result["wifi"] = {
                "status": "Verified", "ssid": ssid,
                "signal": value(r"^\s*Signal\s*:\s*(\d+%)") or "Unverified",
                "channel": value(r"^\s*Channel\s*:\s*(\d+)") or "Unverified",
                "authentication": value(r"^\s*Authentication\s*:\s*(.+)$") or "Unverified",
            }
        else:
            result["wifi"] = {"status": "Unverified", "note": "Windows did not report a connected Wi-Fi interface."}
        ipconfig = _run_readonly(["ipconfig"])
        addresses = sorted(set(re.findall(r"IPv4[^:\n]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", ipconfig, flags=re.IGNORECASE)))
        gateway_match = re.search(r"Default Gateway[^:\n]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", ipconfig, flags=re.IGNORECASE)
        result["network"] = {"status": "Verified" if addresses else "Unverified",
                             "ipv4_addresses": addresses,
                             "default_gateway": gateway_match.group(1) if gateway_match else None}
    else:
        result["limitations"].append("Detailed Wi-Fi/gateway parsing is currently implemented for Windows.")
    return result


def verify_link_target(target: str, web_check) -> dict:
    """Use the existing SSRF-resistant public website checker; never follow redirects."""
    result = web_check(target)
    host = result.get("host", "")
    lowered = host.lower()
    shorteners = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "cutt.ly"}
    warnings = []
    if lowered in shorteners or any(lowered.endswith("." + domain) for domain in shorteners):
        warnings.append("URL shortener detected; its final destination is not followed or verified.")
    if "xn--" in lowered:
        warnings.append("Punycode hostname detected; visually similar characters may be present.")
    https = result.get("https", {})
    tls = https.get("tls") or {}
    tls_status = "Verified" if tls.get("verified") is True else "Failed" if tls.get("verified") is False else "Unverified"
    checks = {
        "dns": "Verified" if result.get("addresses") else "Failed",
        "https_reachability": "Verified" if https.get("status_code") else "Failed",
        "tls_certificate": tls_status,
        "http_reachability": "Verified" if result.get("http", {}).get("status_code") else "Failed",
        "security_headers": "Review",
    }
    status = "Suspicious" if warnings else "Verified" if checks["dns"] == "Verified" and checks["tls_certificate"] == "Verified" else "Unverified"
    return {"status": status, "host": host, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "checks": checks, "warnings": warnings, "details": result,
            "disclaimer": "Checks do not prove a link is harmless. Redirects are not followed; short-link destinations remain unverified."}
