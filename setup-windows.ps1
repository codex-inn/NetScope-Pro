$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
  throw "Python launcher not found. Install Python 3.11+ from https://www.python.org/downloads/windows/"
}
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
  Write-Warning "Nmap was not found on PATH. Install Nmap from https://nmap.org/download.html before scanning."
}
if (-not (Test-Path ".venv")) { py -3 -m venv .venv }
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env. Edit APP_SECRET_KEY, BOOTSTRAP_ADMIN_PASSWORD, and APPROVED_CIDRS before using scans." -ForegroundColor Yellow
}
Write-Host "Setup complete. Edit .env, then run .\run-netscope.bat" -ForegroundColor Green
