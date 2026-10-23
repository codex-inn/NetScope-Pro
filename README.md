# 🔎 NetScope Pro

**A local-first network inventory and TCP port auditing dashboard** built with FastAPI, SQLite, and Nmap.

> 🛡️ **Authorized use only.** Scan only systems and networks you own or have explicit permission to test.

## ✨ Features

- 📊 Responsive dashboard, scan history, and alerts
- 👥 Admin and operator roles
- 🎯 Approved CIDR and TCP-port restrictions
- 🔍 Conservative Nmap TCP connect scans
- 🗃️ SQLite storage and audit logging
- ⏱️ Optional scheduled scans (disabled by default)
- 🌐 Mega Tools: public DNS/IP lookup, HTTP/HTTPS reachability, TLS certificate checks, and common security-header observations
- 📤 JSON export of recent scan history and alerts

## 🧰 Requirements

- Windows 10/11
- Python 3.11+
- [Nmap for Windows](https://nmap.org/download.html)

## 🚀 Quick start

In PowerShell, from the project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Edit `.env` before starting:
- Set a long, random `APP_SECRET_KEY`.
- Set a strong `BOOTSTRAP_ADMIN_PASSWORD` (12+ characters).
- Add only authorized network ranges to `APPROVED_CIDRS` (comma-separated). **Leave it empty to keep scanning disabled.**

Confirm Nmap is installed with `nmap --version`, then run:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765** and sign in with the bootstrap admin credentials from `.env`.

## 🌐 Mega Scanner tools

Open **Mega tools** after signing in to use public DNS/IP lookup and basic website checks. The web checker tests HTTP/HTTPS on ports 80/443, verifies TLS using the local trust store, and reports common security headers. It rejects non-public resolved addresses and does not follow redirects. Missing headers are review hints, not proof of a vulnerability. Nmap scans still require the target to be explicitly included in `APPROVED_CIDRS`. See [docs/MEGA-SCANNER.md](docs/MEGA-SCANNER.md) for details. Use only targets you own or are authorized to assess.

## 🪟 Windows executable

Download the latest successful build from [GitHub Actions](https://github.com/codex-inn/NetScope-Pro/actions/workflows/windows-build.yml). Open a successful run, download the **NetScopePro-Windows** artifact, and extract the ZIP. Artifacts expire according to GitHub's retention period. Nmap must still be installed separately.

## 🧪 Tests

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

GitHub Actions runs the test suite on Windows and Ubuntu. These tests do not verify scans against a live network.

## ⚠️ Security notes

- Binds to `127.0.0.1` by default; **do not expose it directly to the internet**.
- Scan scope and port count are restricted, but results may not reveal every device.
- This is an MVP, not a certified security product or a substitute for an independent security review.
- Review [SECURITY.md](SECURITY.md) and the [operations checklist](docs/OPERATIONS.md) before use.

## 📄 License

See [LICENSE](LICENSE).
