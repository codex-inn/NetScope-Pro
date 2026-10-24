# NetScope Pro

NetScope Pro combines a browser-based URL/DNS workspace with an optional Cloudflare Worker for bounded HTTP inspection and TCP reachability checks, and an optional local Python API for certificate inspection. Browser history is stored in local storage; the project adds no database for the web assessment features.

## Features

- URL structure analysis and public DNS-over-HTTPS queries for A, AAAA, MX, NS, TXT, and CAA.
- DNS mail and certificate-authority policy review for SPF, DMARC, CAA, and an optional supplied DKIM selector.
- Website checks for HTTPS/TLS trust and certificate metadata, HTTP security headers, cookie flags, and same-host redirect chains in the local Python API. The Cloudflare Worker provides bounded header/redirect checks; its runtime does not expose peer-certificate chain details.
- Evidence-based findings with severity, meaning, impact, and remediation; observations are not asserted to be confirmed vulnerabilities.
- Local browser history, comparison/change detection, JSON/CSV/PDF exports, and print reports.
- Optional exact-host authorized Worker TCP checks on a small supported port list.
- Optional private LAN discovery through the loopback Python API, using bounded TCP connection checks.

## Run browser app

Open `index.html` or serve the project directory using any static HTTP server. No build step is required. Use **DNS Inspector** and **Link Analyzer** for browser-only functions. Browser DNS queries go to Cloudflare DNS-over-HTTPS, which can see queried names.

## Local API website assessment (full certificate metadata)

The Python API performs the TLS socket handshake needed to observe the peer certificate. Use it only on hosts you own or have written authorization to assess.

1. Use Python 3.11 or later; install project dependencies with `pip install -r requirements.txt`.
2. Copy `.env.example` to `.env`, set unique local credentials/secrets, and set `AUTHORIZED_WEB_HOSTS` to exact authorized hostnames, comma-separated. Leave empty to disable website assessments. Do not include wildcard domains or targets you do not control.
3. Start the local API using the project's documented app entry point (from the repository root): `uvicorn app.main:app --host 127.0.0.1 --port 8765`. Keep it bound to loopback.
4. Open the local dashboard served by the API, navigate to **Website security assessment**, enter an exact configured host, and tick the explicit authorization confirmation. Optionally provide the active DKIM selector.

The API rejects hosts outside the exact allowlist before DNS resolution; resolves and pins to a validated public address; rejects private/reserved addresses and unsupported ports; verifies HTTPS using the system trust store; follows only bounded same-host HTTP(S) redirects; does not forward credentials/cookies; uses five-second network timeouts, bounded response reads, concurrency limits, and per-client rate limits. DNS lookups use Cloudflare DNS-over-HTTPS. Review `app/mega_scanner.py` and `app/main.py` for exact current bounds.

## Authorized private LAN discovery

Start the local Python API and sign in. Open **Private LAN Discovery** in its dashboard, or open `/workspace` and use **Network Tools** with the authenticated local API. The local API serves `/workspace` same-origin so the browser can securely use your session. LAN discovery is available only through the loopback API (`127.0.0.1`); GitHub Pages cannot directly scan private networks. Enter a private IPv4 address or CIDR, select supported TCP ports, and confirm that you own the network or have explicit authorization. Only RFC1918 private IPv4 ranges are accepted, with at most 256 addresses and eight fixed ports per request. The API uses TCP connect checks with a 350 ms per-connection timeout, at most 32 concurrent connections, and a limit of two scans per minute. Results include each address, response status, response latency when a selected port accepts a connection, and open selected ports; hostname is explicitly shown as not resolved because reverse DNS is not implemented. The dashboard provides JSON and CSV export. Non-responsive results do not prove a device is offline; filtered hosts may still exist. No UDP, OS fingerprinting, or service exploitation is performed. Use the existing Nmap feature only for networks explicitly listed in `APPROVED_CIDRS`.

## Optional Cloudflare Worker

The static GitHub Pages UI can use the optional Worker for its existing bounded TCP and HTTP checks. In `cloudflare-worker`, configure exact public hostnames in `ALLOWED_SCAN_TARGETS` and the Pages origin in `CORS_ORIGINS`, then deploy with Wrangler (`npx wrangler deploy`). Configure the site’s Worker base URL in **Main Network Scan**. The Worker does not expose certificate issuer, SAN, expiry, or chain metadata; use the local API for those fields. Worker deployment is independent from GitHub Pages.

## Tests

- Python: `pytest -q` (the web-check suite uses mocked DNS/socket responses; no third-party host is contacted).
- Worker/PDF export: `node --test cloudflare-worker/tests/*.test.mjs` (uses mocked DNS and network operations).
- Static JS: `node --check cloudflare-worker/src/index.js`; the `index.html` app is inline JavaScript and should be checked in a browser after edits.

## Limits and safe interpretation

No traceroute, packet capture, or broad port scan is performed. The local LAN discovery feature is limited to explicitly authorized private IPv4 targets and selected TCP ports as documented above. Header presence is not proof that a control is effective, and missing headers are not automatically vulnerabilities. A certificate result reflects the local runtime trust store and does not check revocation. Redirects to other hosts are recorded and not followed. DKIM is checked only for the selector supplied, if any. DNS absence may reflect provider behavior, delegation, caching, or lookup failure.

Never scan a third-party target without explicit authorization. The consent checkbox supplements, but does not replace, the exact configured allowlist. Do not configure TNAU or any other third-party target without its explicit authorization.

