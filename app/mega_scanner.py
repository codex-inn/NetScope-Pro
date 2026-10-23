"""Safe, bounded diagnostics for explicitly authorized public web targets.

This module deliberately excludes private, loopback, link-local, multicast, and
reserved destinations to prevent the web checker from becoming an SSRF proxy.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 16_384
DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


class TargetError(ValueError):
    """Raised when a web target is invalid or not publicly routable."""


def normalize_host(target: str) -> str:
    raw = (target or "").strip()
    if not raw or len(raw) > 2048:
        raise TargetError("Enter a valid public domain, public IP, or HTTP(S) URL.")
    # A bare IPv6 literal contains colons that urllib.parse interprets as a
    # port separator. Recognize literals before parsing URL authority syntax.
    if "://" not in raw:
        try:
            literal = ipaddress.ip_address(raw)
        except ValueError:
            pass
        else:
            if not literal.is_global:
                raise TargetError("Only globally routable public IP addresses are allowed.")
            return literal.compressed
    candidate = raw if "://" in raw else "//" + raw
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            raise TargetError("Only HTTP and HTTPS targets are supported.")
        if parsed.username or parsed.password:
            raise TargetError("URLs containing credentials are not accepted.")
        host = parsed.hostname
        # Reject control characters, malformed ports, and ambiguous authorities.
        _ = parsed.port
    except ValueError as exc:
        raise TargetError("The target URL is malformed.") from exc
    if not host or any(ch in host for ch in ("%", "\\", "\x00")):
        raise TargetError("Enter a valid public domain or IP address.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise TargetError("Only globally routable public IP addresses are allowed.")
        return ip.compressed
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetError("The domain name is invalid.") from exc
    if len(host) > 253 or "." not in host:
        raise TargetError("Enter a fully qualified public domain name.")
    labels = host.split(".")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise TargetError("The domain name contains invalid characters.")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise TargetError("Local hostnames are not allowed.")
    return host


def resolve_public_host(target: str) -> dict:
    host = normalize_host(target)
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal.compressed]
        canonical_name = host
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError) as exc:
            raise TargetError("DNS lookup failed for this target.") from exc
        addresses = sorted({item[4][0].split("%", 1)[0] for item in infos})
        if not addresses:
            raise TargetError("The target did not resolve to an IP address.")
        canonical_name = host
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if any(not address.is_global for address in parsed):
        raise TargetError("The domain resolves to a non-public address; the request was blocked.")
    return {
        "host": host,
        "canonical_name": canonical_name,
        "addresses": [
            {"address": address.compressed, "family": "IPv6" if address.version == 6 else "IPv4"}
            for address in parsed
        ],
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _connect_public(host: str, ip_text: str, port: int, use_tls: bool):
    ip = ipaddress.ip_address(ip_text)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT_SECONDS)
    try:
        sockaddr = (ip.compressed, port, 0, 0) if ip.version == 6 else (ip.compressed, port)
        raw.connect(sockaddr)
        if not use_tls:
            return raw, None
        context = ssl.create_default_context()
        # Passing IP literals through server_hostname enables certificate IP SAN
        # matching while OpenSSL omits the DNS-only SNI extension for IPs.
        wrapped = context.wrap_socket(raw, server_hostname=host)
        return wrapped, context
    except Exception:
        raw.close()
        raise


def _request(host: str, ip_text: str, port: int, use_tls: bool) -> dict:
    conn = None
    try:
        conn, _ = _connect_public(host, ip_text, port, use_tls)
        host_header = f"[{host}]" if ":" in host else host
        request = (
            f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\n"
            "User-Agent: NetScope-Pro-MegaScanner/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii", "strict")
        conn.sendall(request)
        data = bytearray()
        while len(data) < MAX_RESPONSE_BYTES:
            chunk = conn.recv(min(4096, MAX_RESPONSE_BYTES - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if b"\r\n\r\n" in data:
                break
        header_bytes = bytes(data).split(b"\r\n\r\n", 1)[0]
        lines = header_bytes.decode("iso-8859-1", "replace").split("\r\n")
        status_line = lines[0] if lines else ""
        match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$", status_line)
        headers = {}
        if match:
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
        tls_info = None
        if use_tls and hasattr(conn, "getpeercert"):
            cert = conn.getpeercert() or {}
            cipher = conn.cipher()
            tls_info = {
                "verified": True,
                "version": conn.version(),
                "cipher": cipher[0] if cipher else None,
                "subject": _flatten_cert_name(cert.get("subject", ())),
                "issuer": _flatten_cert_name(cert.get("issuer", ())),
                "not_after": cert.get("notAfter"),
            }
        return {
            "reachable": True,
            "scheme": "https" if use_tls else "http",
            "status_code": int(match.group(1)) if match else None,
            "status_text": match.group(2) if match else status_line[:200],
            "headers": {name: headers[name] for name in SECURITY_HEADERS if name in headers},
            "missing_security_headers": [name for name in SECURITY_HEADERS if name not in headers],
            "tls": tls_info,
            "error": None,
        }
    except ssl.SSLCertVerificationError:
        return {"reachable": False, "scheme": "https", "status_code": None,
                "headers": {}, "missing_security_headers": list(SECURITY_HEADERS),
                "tls": {"verified": False}, "error": "TLS certificate verification failed."}
    except (OSError, ssl.SSLError, ValueError, UnicodeError) as exc:
        return {"reachable": False, "scheme": "https" if use_tls else "http",
                "status_code": None, "headers": {}, "missing_security_headers": list(SECURITY_HEADERS),
                "tls": None, "error": str(exc)[:240]}
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def web_check(target: str) -> dict:
    dns = resolve_public_host(target)
    host = dns["host"]
    # Use the already-vetted numeric address for the socket connection; do not
    # pass an untrusted target to a generic URL-fetching client or follow redirects.
    first_ip = dns["addresses"][0]["address"]
    https_result = _request(host, first_ip, 443, True)
    http_result = _request(host, first_ip, 80, False)
    return {
        **dns,
        "https": https_result,
        "http": http_result,
        "notes": [
            "Only the supplied public host was checked; redirects were not followed.",
            "A missing header is a review hint, not proof of a vulnerability.",
            "A successful HTTPS result means the certificate passed this machine's trust checks."
        ],
    }


def _flatten_cert_name(value) -> str | None:
    parts = []
    for group in value or ():
        for key, item in group:
            parts.append(f"{key}={item}")
    return ", ".join(parts)[:500] or None

