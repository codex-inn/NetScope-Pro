"""Safe, bounded diagnostics for explicitly authorized public web targets.

This module deliberately excludes private, loopback, link-local, multicast, and
reserved destinations to prevent the web checker from becoming an SSRF proxy.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 16_384
MAX_REDIRECTS = 4
REDIRECT_CODES = {301, 302, 303, 307, 308}
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


def _request(host: str, ip_text: str, port: int, use_tls: bool, path: str = "/") -> dict:
    conn = None
    try:
        conn, _ = _connect_public(host, ip_text, port, use_tls)
        host_header = f"[{host}]" if ":" in host else host
        if not path.startswith("/") or any(ch in path for ch in "\r\n"):
            raise TargetError("The server supplied an invalid redirect path.")
        request = (
            f"HEAD {path} HTTP/1.1\r\nHost: {host_header}\r\n"
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
                    key, value = key.strip().lower(), value.strip()
                    if key == "set-cookie":
                        headers.setdefault(key, []).append(value)
                    else:
                        headers[key] = value
        tls_info = None
        if use_tls and hasattr(conn, "getpeercert"):
            cert = conn.getpeercert() or {}
            cipher = conn.cipher()
            not_after = cert.get("notAfter")
            not_before = cert.get("notBefore")
            tls_info = {
                "verified": True,
                "verification_method": "Python system trust store with hostname verification",
                "version": conn.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "subject": _flatten_cert_name(cert.get("subject", ())),
                "issuer": _flatten_cert_name(cert.get("issuer", ())),
                "subject_alt_names": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"][:30],
                "serial_number": cert.get("serialNumber"),
                "not_before": not_before,
                "not_after": not_after,
                "days_remaining": max(-99999, (ssl.cert_time_to_seconds(not_after) - int(datetime.now(timezone.utc).timestamp())) // 86400) if not_after else None,
            }
        return {
            "reachable": True,
            "scheme": "https" if use_tls else "http",
            "status_code": int(match.group(1)) if match else None,
            "status_text": match.group(2) if match else status_line[:200],
            "headers": {name: headers[name] for name in (*SECURITY_HEADERS, "location") if name in headers},
            "cookie_summary": _summarize_cookies(headers.get("set-cookie", [])),
            "missing_security_headers": [name for name in SECURITY_HEADERS if name not in headers],
            "tls": tls_info,
            "error": None,
        }
    except ssl.SSLCertVerificationError:
        return {"reachable": False, "scheme": "https", "status_code": None,
                "headers": {}, "cookie_summary": [], "missing_security_headers": list(SECURITY_HEADERS),
                "tls": {"verified": False}, "error": "TLS certificate verification failed."}
    except (OSError, ssl.SSLError, ValueError, UnicodeError) as exc:
        return {"reachable": False, "scheme": "https" if use_tls else "http",
                "status_code": None, "headers": {}, "cookie_summary": [], "missing_security_headers": list(SECURITY_HEADERS),
                "tls": None, "error": str(exc)[:240]}
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _summarize_cookies(values: list[str]) -> list[dict]:
    output = []
    for index, raw in enumerate(values, 1):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for morsel in cookie.values():
            output.append({
                "index": index,
                "secure": bool(morsel["secure"]),
                "http_only": bool(morsel["httponly"]),
                "same_site": morsel["samesite"] or None,
            })
    return output


def _follow_redirects(host: str, ip_text: str, scheme: str) -> dict:
    current = f"{scheme}://{host}/"
    redirects = []
    result = None
    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        result = _request(host, ip_text, port, parsed.scheme == "https", path)
        result["url"] = current
        location = result.get("headers", {}).get("location")
        if result.get("status_code") not in REDIRECT_CODES or not location:
            break
        destination = urljoin(current, location)
        next_url = urlsplit(destination)
        same_host = (next_url.hostname or "").rstrip(".").lower() == host.lower()
        try:
            redirect_port = next_url.port
        except ValueError:
            redirect_port = -1
        same_scope = (
            same_host
            and next_url.scheme.lower() in {"http", "https"}
            and redirect_port in {None, 80, 443}
            and not next_url.username
            and not next_url.password
        )
        followed = bool(same_scope and hop < MAX_REDIRECTS)
        redirects.append({"status_code": result["status_code"], "from": current, "to": destination, "followed": followed})
        if not followed:
            break
        current = destination
    assert result is not None
    result["redirect_chain"] = redirects
    result["final_url"] = result.get("url", current)
    result["external_redirect"] = next(
        (item["to"] for item in redirects if not item["followed"] and (urlsplit(item["to"]).hostname or "").rstrip(".").lower() != host.lower()),
        None,
    )
    return result


def _doh_query(name: str, record_type: str) -> dict:
    query = urllib.parse.urlencode({"name": name, "type": record_type})
    request = urllib.request.Request(
        "https://cloudflare-dns.com/dns-query?" + query,
        headers={"accept": "application/dns-json", "user-agent": "NetScope-Pro-Authorized-Inspector/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = response.read(32_768)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise TargetError("Public DNS security lookup failed or timed out.") from exc
    try:
        data = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetError("Public DNS provider returned invalid JSON.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
        raise TargetError("Public DNS provider returned an invalid response.")
    return data


def dns_security_check(host: str, selector: str | None = None, query=_doh_query) -> dict:
    host = normalize_host(host)
    if selector is not None:
        selector = selector.strip().rstrip(".")
        if len(selector) > 63 or not DOMAIN_LABEL.fullmatch(selector):
            raise TargetError("DKIM selector must be one valid DNS label (1â€“63 characters).")
    records = {}
    for record_type in ("TXT", "CAA"):
        data = query(host, record_type)
        records[record_type] = [str(a.get("data", "")) for a in data.get("Answer", []) if isinstance(a, dict)]
    dmarc_data = query("_dmarc." + host, "TXT")
    records["DMARC"] = [
        str(a.get("data", "")) for a in dmarc_data.get("Answer", [])
        if isinstance(a, dict) and "v=dmarc1" in str(a.get("data", "")).lower()
    ]
    if selector:
        dkim_data = query(f"{selector}._domainkey.{host}", "TXT")
        records["DKIM"] = [str(a.get("data", "")) for a in dkim_data.get("Answer", []) if isinstance(a, dict)]
    spf = [value for value in records["TXT"] if "v=spf1" in value.lower()]
    dmarc = records["DMARC"]
    dkim = records.get("DKIM")
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "records": records,
        "policies": {
            "spf": {"status": "multiple" if len(spf) > 1 else "present" if spf else "missing", "values": spf},
            "dmarc": {"status": "multiple" if len(dmarc) > 1 else "present" if dmarc else "missing", "values": dmarc},
            "caa": {"status": "present" if records["CAA"] else "missing", "values": records["CAA"]},
            "dkim": {"status": "not_requested" if selector is None else "present" if dkim else "missing", "selector": selector, "values": dkim or []},
        },
    }


def _security_findings(https: dict, http: dict, dns: dict) -> list[dict]:
    findings = []

    def add(severity, title, evidence, impact, remediation, status="review"):
        findings.append({
            "severity": severity, "status": status, "title": title, "evidence": evidence,
            "impact": impact, "remediation": remediation, "confirmed_vulnerability": False,
        })

    tls = https.get("tls")
    if tls and tls.get("verified"):
        add(
            "info", "TLS certificate verified",
            f"System trust and hostname checks passed; {tls.get('version') or 'TLS version unavailable'}; expires {tls.get('not_after') or 'date unavailable'}.",
            "This confirms the current connection passed this machine's trust checks; it does not prove the website is safe.",
            "Keep the certificate renewed and maintain modern TLS settings.", "observed",
        )
        days = tls.get("days_remaining")
        if days is not None and days < 30:
            add("high" if days < 14 else "medium", "TLS certificate expires soon",
                f"Certificate validity remaining: {days} days.",
                "Clients may reject HTTPS after the certificate expires.",
                "Renew and deploy the certificate before its expiry.")
        version = tls.get("version") or ""
        if version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
            add("medium", "Legacy TLS protocol negotiated", f"Negotiated protocol: {version}.",
                "Legacy protocols have weaker security properties and compatibility risks.",
                "Disable legacy protocols and require TLS 1.2 or later.")
    elif https.get("error"):
        add("high", "TLS connection could not be verified", https.get("error", "TLS handshake failed."),
            "A client could not establish a trusted HTTPS connection in this check.",
            "Check certificate validity, hostname coverage, chain delivery, and server TLS configuration.")

    headers = https.get("headers", {})
    csp = headers.get("content-security-policy", "")
    header_checks = [
        ("strict-transport-security", "HSTS is not observed", "medium",
         "Browsers may continue using HTTP if a link starts unencrypted.",
         "Serve HTTPS consistently, then configure an appropriate Strict-Transport-Security policy."),
        ("content-security-policy", "Content Security Policy is not observed", "medium",
         "The browser has no observed CSP policy to restrict resource loading.",
         "Define and test a Content-Security-Policy for the site's required resources."),
        ("x-content-type-options", "MIME sniffing protection is not observed", "low",
         "Some browsers may infer content types instead of respecting the declared type.",
         "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer policy is not observed", "low",
         "Navigation may disclose more referrer information than intended.",
         "Set an appropriate Referrer-Policy."),
        ("permissions-policy", "Permissions policy is not observed", "low",
         "Browser capabilities are not explicitly constrained by this response.",
         "Disable browser features the site does not use with Permissions-Policy."),
    ]
    for key, title, severity, impact, fix in header_checks:
        if not headers.get(key):
            add(severity, title, f"Response header '{key}' was absent on {https.get('final_url', 'the inspected HTTPS response')}.", impact, fix)
    if not headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        add("medium", "Framing protection is not observed",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "The page may be embeddable in a frame; this observation alone does not establish a clickjacking vulnerability.",
            "Set CSP frame-ancestors or X-Frame-Options according to embedding requirements.")
    for cookie in https.get("cookie_summary", []):
        missing = [name for name, value in (("Secure", cookie["secure"]), ("HttpOnly", cookie["http_only"]), ("SameSite", cookie["same_site"])) if not value]
        if missing:
            add("low", "Cookie attributes need review",
                f"Cookie {cookie['index']} is missing: {', '.join(missing)}. Cookie values were not recorded.",
                "Missing attributes can increase exposure to transport, script, or cross-site request risks depending on cookie use.",
                "Add Secure and HttpOnly where appropriate, and choose an intentional SameSite policy.")
    if http.get("reachable") and http.get("status_code") and not 300 <= http["status_code"] < 400:
        add("medium", "HTTP does not redirect to HTTPS",
            f"HTTP returned status {http['status_code']} without an observed redirect.",
            "A client that starts with HTTP may not be upgraded to the encrypted endpoint.",
            "Redirect HTTP requests to HTTPS and enable HSTS after verification.")

    for label, policy in dns.get("policies", {}).items():
        if policy["status"] == "missing":
            if label == "spf":
                add("medium", "SPF record not observed", "No SPF policy was returned in the domain's TXT records.",
                    "Receiving mail systems have less guidance for validating authorized senders.",
                    "Publish one SPF TXT record that lists intended senders and ends with an intentional policy.")
            elif label == "dmarc":
                add("medium", "DMARC record not observed", "No DMARC policy was returned at _dmarc for this domain.",
                    "Domain owners have less visibility and control over mail using their domain.",
                    "Publish a DMARC policy, start with reporting if appropriate, and tighten enforcement after review.")
            elif label == "caa":
                add("info", "CAA record not observed", "No CAA records were returned.",
                    "Certificate authorities are not restricted by an observed CAA policy.",
                    "Consider publishing CAA records for the certificate authorities you use.")
            elif label == "dkim":
                add("info", "DKIM selector not observed", f"No DKIM TXT record was returned for selector {policy.get('selector')}.",
                    "This lookup cannot determine whether another selector is in use.",
                    "Confirm the selector with your mail provider and publish its DKIM public key if needed.")
        elif policy["status"] == "multiple":
            add("medium", f"{label.upper()} records are multiple", f"More than one {label.upper()} policy was returned.",
                "Conflicting policy records may be interpreted inconsistently.",
                f"Review and consolidate the {label.upper()} policy records.")
        elif label == "spf" and policy["values"] and not policy["values"][0].lower().endswith("-all"):
            add("low", "SPF ending needs review", policy["values"][0],
                "A permissive or soft-fail ending may provide weaker sender guidance.",
                "Review authorized senders and choose an intentional SPF ending.")
        elif label == "dmarc" and policy["values"] and "p=none" in policy["values"][0].lower():
            add("low", "DMARC policy is monitoring only", policy["values"][0],
                "A p=none policy reports but does not request quarantine or rejection.",
                "Move toward quarantine or reject only after reviewing legitimate mail sources.")
    return findings


def web_check(target: str, allowed_hosts=None, selector: str | None = None) -> dict:
    raw = (target or "").strip()
    candidate = raw if "://" in raw else "//" + raw
    try:
        requested_port = urlsplit(candidate).port
    except ValueError as exc:
        raise TargetError("The target URL is malformed.") from exc
    if requested_port not in {None, 80, 443}:
        raise TargetError("Website assessment supports only standard HTTP and HTTPS ports.")
    host = normalize_host(target)
    if allowed_hosts is None:
        allowed_hosts = os.getenv("AUTHORIZED_WEB_HOSTS", "").split(",")
    normalized_allowed = {normalize_host(str(value)) for value in allowed_hosts if str(value).strip()}
    if not normalized_allowed or host not in normalized_allowed:
        raise TargetError("Website assessment is disabled or the host is not in AUTHORIZED_WEB_HOSTS.")
    dns = resolve_public_host(host)

    # Pin each bounded connection to the first vetted numeric address. Only exact same-host redirects are followed.
    first_ip = dns["addresses"][0]["address"]
    https_result = _follow_redirects(host, first_ip, "https")
    http_result = _follow_redirects(host, first_ip, "http")
    dns_result = {**dns_security_check(host, selector), "host": host}
    findings = _security_findings(https_result, http_result, dns_result)
    return {
        "schema_version": 1,
        "assessment_type": "authorized_website_security_assessment",
        "authorized_scope": {"host": host, "allowlist_match": True},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **dns,
        "https": https_result,
        "http": http_result,
        "dns_security": dns_result,
        "findings": findings,
        "notes": [
            "Only the exact configured host was checked; redirects to other hosts are recorded but never followed.",
            "The assessment is bounded to one resolved public address, HEAD responses, five hops per scheme, and five-second socket timeouts.",
            "Findings are configuration observations, not proof of exploitation or a confirmed vulnerability.",
            "DNS security lookups are sent to Cloudflare DNS-over-HTTPS; the queried hostname is visible to that provider.",
            "Certificate verification uses this machine's system trust store; results may differ from other clients and certificate revocation status is not checked.",
        ],
    }


def _flatten_cert_name(value) -> str | None:
    parts = []
    for group in value or ():
        for key, item in group:
            parts.append(f"{key}={item}")
    return ", ".join(parts)[:500] or None


