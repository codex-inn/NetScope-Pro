# NetScope Pro Web

**A browser-first web security workspace. No executable download is required.**

Public website: https://codex-inn.github.io/NetScope-Pro/

NetScope Pro Web is designed to run from a normal browser. It provides a responsive dashboard for URL structure analysis, public DNS-over-HTTPS lookups, caution indicators, local browser history, and printable/copyable reports.

## Features

- Responsive dashboard with Overview, Link Analyzer, DNS Inspector, Analysis History, Main Network Scan, and Network Tools
- URL parsing and visible indicators for HTTP vs HTTPS, punycode, embedded user information, explicit ports, IP literals, and known shortener domains
- Public DNS lookups using Cloudflare DNS-over-HTTPS for A, AAAA, MX, NS, TXT, and CAA records
- Clear per-check labels: Verified, Unverified, Suspicious, and Failed
- Recent analysis history stored in the browser's local storage
- Copyable findings and Print / Save PDF reports
- Optional hosted API integration for bounded TCP checks on service-owner-allowlisted public targets
- No login, executable, extension, or local installation needed for the website

## Open the website

1. Visit https://codex-inn.github.io/NetScope-Pro/
2. Enter a URL in **Quick analysis** and select **Analyze link**.
3. Review each check separately; use **DNS Inspector** to inspect public DNS records.
4. Copy findings or choose **Print / Save PDF** to save a report.

## Important browser-only limits

A public static website cannot access the computer's Wi-Fi SSID/password, inspect nearby devices, scan private LAN ports, or reliably inspect arbitrary websites' TLS certificates and response headers. Those operations require a separately deployed backend or local agent, which is intentionally outside this web-only edition.

This analyzer does not fetch arbitrary website pages or follow redirects. DNS records and URL patterns are indicators only—not proof that a website is safe or malicious. A site can be harmful even if every visible check passes. Avoid entering URLs containing session tokens, passwords, or private identifiers. DNS queries send the queried hostname to Cloudflare's public DNS-over-HTTPS service.

## Development

The site is a static HTML/CSS/JavaScript app in `index.html`. No build step or package installation is needed. For local preview, open `index.html` in a modern browser or use any static web server.

Only assess URLs and systems you are authorized to inspect.

## Main Network Scan (optional hosted API)

The website is static, so GitHub Pages itself cannot open arbitrary TCP connections or discover devices on your Wi-Fi. The **Main Network Scan** screen calls an optional hosted API; without that API deployed and configured, it will report that scanning is unavailable rather than inventing results.

### Deploy the optional API

1. In your hosting provider, create a Python web service from this repository using the included `render.yaml` blueprint (or configure a service with root directory `api`, build command `pip install -r requirements.txt`, and start command `uvicorn main:app --host 0.0.0.0 --port $PORT`).
2. Set `ALLOWED_SCAN_TARGETS` to a comma-separated list of public hostnames or individual public IP addresses that you own or are explicitly authorized to assess. Example: `example.org`. Do not add private LAN addresses. Leave it unset until you are ready to configure an authorized target.
3. Set `CORS_ORIGINS` to `https://codex-inn.github.io` (and any additional exact trusted frontend origins you control).
4. Deploy the API, then open the website and paste the API base URL into **Main Network Scan**. Click **Check API connection**.
5. Enter an exact allowlisted hostname/IP, select supported ports, check the authorization confirmation, and start the scan.

### Scope and safeguards

- Only individually allowlisted targets are accepted. The API rejects private, loopback, link-local, reserved, and non-public resolved addresses.
- The scan is limited to a small fixed TCP port list, a small number of checks per request, short connection timeouts, and a basic per-client rate limit.
- Results are TCP reachability observations only. A port marked closed/filtered is inconclusive and does not identify a vulnerability.
- This cannot scan the user's local Wi-Fi or discover private-LAN devices. That would require a separately installed local component, which this project intentionally does not provide.
- A hosted service has its own operating costs and network restrictions. Configure and use it only for systems you are authorized to test.
