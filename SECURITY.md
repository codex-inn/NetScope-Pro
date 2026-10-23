# Security policy and operational safety

NetScope Pro is intended for authorized inventory and bounded service checks only.

## Required controls

- Configure APPROVED_CIDRS with only institution-approved networks.
- Keep the service bound to loopback unless a reviewed deployment design requires otherwise.
- Use unique long secrets and strong passwords; never commit .env or database files.
- Limit access to the host and its SQLite database.
- Record authorization, change tickets, scan windows, and approved ranges outside the app.
- Review each alert manually. An open port is not by itself proof of vulnerability.
- Do not enable recurring scans until the institution's owner has approved the exact target, frequency, and ports.

## Reporting a security issue

Do not include real credentials, public IPs, student information, or sensitive network maps in public issues. Report security concerns privately to the repository maintainer.
