# NetScope Pro local scanner quick start (Windows)

The hosted GitHub Pages site cannot read Windows Wi-Fi adapter data or scan your private LAN. For those real features, run the existing Python service on the Windows computer that is connected to the network.

## 1. Prepare the local service

1. Install Python 3.11 or newer.
2. Download or clone this repository to your Windows computer.
3. Open PowerShell in the repository folder.
4. Run:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` before the first run:
- Set `APP_SECRET_KEY` to a unique random secret of at least 32 characters.
- Set `BOOTSTRAP_ADMIN_USERNAME` and a unique `BOOTSTRAP_ADMIN_PASSWORD` (at least 12 characters).
- Keep `HOST=127.0.0.1`; do not expose the local scanner to your LAN or the public internet.
- Keep `APPROVED_CIDRS=` empty unless you have explicitly authorized targets for the separate Nmap scan.
- Keep `AUTHORIZED_WEB_HOSTS=` empty unless you want to enable website assessment for exact hostnames you own or are authorized to assess.

The initial admin account is created only when the configured username does not already exist and the password meets the bootstrap checks. If the database already exists, changing the bootstrap password does not reset an existing account.

## 2. Start the API

Run `run-netscope.bat` or use:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Open <http://127.0.0.1:8765/> and sign in with the local admin credentials. Keep the terminal open while using the local scanner.

## 3. Run a Wi-Fi / LAN check

1. In the local dashboard, open **Wi-Fi Network Scan**.
2. Confirm that you own the Wi-Fi/LAN or have explicit permission to assess it.
3. Use `auto` for supported Windows subnet detection, or enter a private IPv4 CIDR such as `192.168.1.0/24` that you administer.
4. Choose only the supported TCP ports you need and start the scan.
5. Export the observed results if required.

The LAN scanner is limited to RFC1918 private IPv4 ranges with no more than 256 addresses, a small fixed TCP-port list, bounded connection concurrency, and rate limiting. Results reflect only ARP cache entries and responses to selected TCP checks. A missing device is not proof that it is disconnected; a responding port is not proof of vulnerability. Nearby access-point discovery uses Windows `netsh` and only reports networks visible to the adapter.

## 4. Use the hosted website

Open <https://codex-inn.github.io/NetScope-Pro/> for browser-only URL analysis and DNS queries. The DNS Inspector now requests the resolver's DNSSEC authenticated-data signal when available. An absent signal is **unconfirmed**, not proof of tampering or a DNSSEC failure.

Use the **Network Tools → Local Wi-Fi & LAN scanner** link to open the local dashboard at `http://127.0.0.1:8765`. The hosted page cannot call the local authenticated API directly: the API intentionally rejects non-local origins. This link opens the local dashboard instead of weakening that security boundary.

## Privacy and safety

- Do not enter passwords, session tokens, or secret URLs into reports.
- DNS queries go to Cloudflare DNS-over-HTTPS, which can observe queried domain names.
- Keep the local API bound to loopback. Do not add broad CORS rules or port-forward it.
- Scan only systems you own or have explicit permission to assess.
