# NetScope Pro Web

**A browser-first web security workspace. No executable download is required.**

Public website: https://codex-inn.github.io/NetScope-Pro/

NetScope Pro Web is designed to run from a normal browser. It provides a responsive dashboard for URL structure analysis, public DNS-over-HTTPS lookups, caution indicators, local browser history, and printable/copyable reports.

## Features

- Responsive dashboard with Overview, Link Analyzer, DNS Inspector, Analysis History, and Network Tools
- URL parsing and visible indicators for HTTP vs HTTPS, punycode, embedded user information, explicit ports, IP literals, and known shortener domains
- Public DNS lookups using Cloudflare DNS-over-HTTPS for A, AAAA, MX, NS, TXT, and CAA records
- Clear per-check labels: Verified, Unverified, Suspicious, and Failed
- Recent analysis history stored in the browser's local storage
- Copyable findings and Print / Save PDF reports
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
