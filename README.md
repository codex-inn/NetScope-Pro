# NetScope Pro

Windows-first network inventory and bounded TCP-port auditing dashboard using Python, FastAPI, SQLite, and Nmap. Use only on networks you own or are explicitly authorized to administer.

## Safety defaults

- Scanning is disabled until APPROVED_CIDRS is configured in .env.
- Requested targets must be fully contained in an approved CIDR.
- IPv4 target size is capped (default 256 addresses).
- TCP ports come from a fixed common-port allowlist; at most 25 per job by default.
- Conservative Nmap connect scans only: no scripts, OS detection, or version detection.
- Local-only bind by default (127.0.0.1); do not expose this app directly to the internet.
- Users, scan jobs, findings, and audit events are stored in SQLite.
- No scan runs automatically at startup.

## Requirements

- Windows 10/11
- Python 3.11+
- Nmap for Windows: https://nmap.org/download.html

## Install (PowerShell)

1. Install Python and Nmap. Ensure nmap.exe is available on PATH.
2. In this repository run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

3. Set APP_SECRET_KEY to a long random secret, set a strong BOOTSTRAP_ADMIN_PASSWORD (at least 12 characters), and add only written-authorized target CIDRs to APPROVED_CIDRS. Separate CIDRs with commas. Scanning stays disabled if this value is empty.
4. Verify Nmap with `nmap --version`.
5. Start the app:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

6. Open http://127.0.0.1:8765 and sign in using the bootstrap admin credentials from .env.

## Features

- Responsive dashboard, device inventory, scan history, alerts
- Administrator and operator roles
- CIDR allowlist validation, target/port limits, job concurrency limit
- Conservative Nmap TCP connect scans with timeout
- SQLite persistence and audit logging
- Admin user-management API
- Optional scheduler configuration (disabled by default)

## API

- GET / — dashboard
- GET /api/health — health status
- POST /api/login and POST /api/logout — session login/logout
- GET /api/dashboard — counts and recent jobs
- GET /api/scans and POST /api/scans — history and start a bounded scan
- GET /api/alerts — alerts
- GET /api/users and POST /api/users — administrator-only user management
- GET /api/schedules and POST /api/schedules — administrator-only schedule configuration

## Tests

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Tests validate input limits and scope; they do not scan a live network.

## Limitations

This is an MVP, not a certified security product. It may not identify every device on switched networks or discover MAC addresses across routers. Findings are indicators for review, not proof of compromise. Before institutional deployment, add formal CSRF protection, secret rotation, backups/restore, managed TLS, retention controls, and an independent security review.
