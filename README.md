# 🔎 NetScope Pro

**A local-first network security dashboard** built with FastAPI, SQLite, and Nmap, with a public project homepage and downloadable Windows executable.

> **Authorized use only.** Scan only systems and networks you own or have explicit permission to test.

## 🌐 Website and Windows app

- **Project homepage:** https://codex-inn.github.io/NetScope-Pro/
- **Source code:** https://github.com/codex-inn/NetScope-Pro
- **Windows download:** open [Windows executable builds](https://github.com/codex-inn/NetScope-Pro/actions/workflows/windows-build.yml), select the latest successful run, then download `NetScopePro-Windows` from **Artifacts**.
- **Automated tests:** [GitHub Actions tests](https://github.com/codex-inn/NetScope-Pro/actions/workflows/tests.yml)

The homepage is a public product/guide page. It cannot access your PC's Wi-Fi or run network scans from a static hosted page. Use the local Windows app for actual checks; this keeps local network access on your own computer.

## ✨ Features

- Responsive local dashboard, scan history, alerts, and user roles
- Approved CIDR and TCP-port restrictions for authorized network scans
- Conservative Nmap TCP connect scans
- SQLite storage and audit logging
- Optional scheduled scans (disabled by default)
- Public DNS/IP lookup, HTTP/HTTPS reachability, TLS certificate checks, and common security-header observations
- Link verification with check-level Verified/Unverified/Suspicious/Failed results and explicit caveats
- Read-only Windows Wi-Fi/local network snapshot (SSID, signal, channel, authentication, IPv4 and gateway where available)
- JSON report export and browser Print / Save PDF controls

## 🪟 Use the Windows executable

1. Open the [Windows executable workflow](https://github.com/codex-inn/NetScope-Pro/actions/workflows/windows-build.yml).
2. Open the latest run with a green **Success** status.
3. Download the `NetScopePro-Windows` ZIP from the **Artifacts** section.
4. Extract the ZIP, then run `NetScopePro.exe`.
5. Open the local address displayed by the app (normally `http://127.0.0.1:8765`) and sign in with the local bootstrap admin credentials.
6. Install [Nmap for Windows](https://nmap.org/download.html) separately if you need Nmap-based scans.

GitHub Actions artifacts expire after their configured retention period. Tagged releases are also supported by the release workflow when a version tag is published.

## 🧰 Run from source (Windows 10/11)

Requirements: Python 3.11+, and Nmap for network scans.

In PowerShell, from the project folder:

```powershell
py -3 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Edit `.env` before starting:
- Set a long, random `APP_SECRET_KEY`.
- Set a strong `BOOTSTRAP_ADMIN_PASSWORD` (12+ characters).
- Add only authorized network ranges to `APPROVED_CIDRS` (comma-separated). Leave it empty to keep scanning disabled.

Confirm Nmap is installed with `nmap --version`, then run:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765** and sign in with the bootstrap admin credentials from `.env`.

## 🔗 Link verification and local Wi-Fi audit

The Link Verification panel reuses the public-target-safe website checker and reports DNS, HTTP/HTTPS reachability, TLS verification, and review hints for shortener/punycode hosts. It does not follow redirects and does not guarantee a link is harmless. The Wi-Fi / Local panel uses read-only Windows commands to show connection details and basic IPv4/gateway information where the OS exposes them; it never retrieves saved Wi-Fi passwords or disconnects devices.

## 🌐 Network scanner

The web checker tests HTTP/HTTPS on ports 80/443, verifies TLS using the local trust store, and reports common security headers. It rejects non-public resolved addresses and does not follow redirects. Missing headers are review hints, not proof of a vulnerability. Nmap scans require the target to be explicitly included in `APPROVED_CIDRS`. See [docs/MEGA-SCANNER.md](docs/MEGA-SCANNER.md) for details.

## 🧪 Tests

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

GitHub Actions runs the test suite on Windows and Ubuntu. These tests do not verify scans against a live network.

## ⚠️ Security notes

- Binds to `127.0.0.1` by default; **do not expose it directly to the internet**.
- Scan scope and port count are restricted, but results may not reveal every device.
- A passed check means only that specific check passed; it does not certify a URL or network as safe.
- This is an MVP, not a certified security product or a substitute for an independent security review.
- Review [SECURITY.md](SECURITY.md) and [docs/OPERATIONS.md](docs/OPERATIONS.md) before use.

## 📄 License

See [LICENSE](LICENSE).
