# Mega Scanner tools

The Mega Tools dashboard adds two bounded diagnostics for a user-supplied public target:

- **DNS / public IP lookup** resolves the host and shows its public IPv4/IPv6 addresses.
- **Website check** tries HTTP on port 80 and HTTPS on port 443, reports status codes, TLS trust information, and selected security headers.
- **JSON report export** downloads recent scan history and alerts.

## Safety limits

- Only test hosts you own or have explicit authorization to assess.
- The website checker rejects non-public resolved addresses and does not follow redirects.
- It sends a small `HEAD /` request only; it does not crawl paths, exploit vulnerabilities, brute-force credentials, or scan all internet addresses.
- Missing security headers are review hints, not proof of a vulnerability.
- DNS and web checks run in a bounded worker pool (`MEGA_WORKER_LIMIT`, default 4, maximum 8). If all worker slots are occupied, the API returns HTTP 503 with `Retry-After`; try again after existing checks finish.
- Request timeouts limit how long the API waits, but Python cannot forcibly stop a blocking system DNS resolver call already running in a worker thread. Worker slots remain occupied until that call exits, preventing unbounded worker accumulation.
- Nmap port scans remain subject to the existing `APPROVED_CIDRS` allowlist, target-size limit, port allowlist, and concurrency cap. A public IP must be explicitly approved in `.env` before Nmap scanning.
- The dashboard is still intended to run on localhost. Do not expose it directly to the public internet.

## Using it

Start the app using the existing Quick Start instructions in `README.md`, sign in, and open **Mega tools** from the sidebar. The website checks are separate from Nmap port scans and do not change the approved CIDR list.

## Limitations

These are basic diagnostics, not a complete vulnerability scanner or penetration test. Results depend on DNS, network access, remote server behavior, and the local certificate trust store. Live target testing should only be performed with authorization.