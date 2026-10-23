$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
  throw "Python launcher not found. Install Python 3.11+ from https://www.python.org/downloads/windows/"
}

if (-not (Test-Path ".venv")) { py -3 -m venv .venv }
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller
& ".\.venv\Scripts\python.exe" -m PyInstaller --clean --noconfirm --onefile --collect-submodules uvicorn --collect-submodules apscheduler --collect-submodules fastapi --collect-submodules starlette --name NetScopePro run_desktop.py

Write-Host ""
Write-Host "Build complete: $PSScriptRoot\dist\NetScopePro.exe" -ForegroundColor Green
Write-Host "Install Nmap separately, then place a configured .env beside the executable." -ForegroundColor Yellow
Write-Host "Keep the application bound to localhost; do not expose it to the internet." -ForegroundColor Yellow
