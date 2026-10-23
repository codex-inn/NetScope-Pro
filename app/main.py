from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from starlette.middleware.sessions import SessionMiddleware

from app.security import hash_password, verify_password, validate_target, validate_ports, approved_networks, ALLOWED_PORTS, html_escape
from app.mega_scanner import TargetError, resolve_public_host, web_check

load_dotenv()
APP_NAME = os.getenv("APP_NAME", "NetScope Pro")
SECRET_KEY = os.getenv("APP_SECRET_KEY", "")
if len(SECRET_KEY) < 32 or SECRET_KEY.startswith("replace-"):
    # Refuse insecure production configuration; a generated local secret is acceptable for development only.
    SECRET_KEY = os.urandom(32).hex()
DB_PATH = Path(os.getenv("DATABASE_PATH", "data/netscope.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
MAX_HOSTS = int(os.getenv("MAX_TARGET_HOSTS", "256"))
MAX_PORTS = int(os.getenv("MAX_PORTS_PER_SCAN", "25"))
SCAN_TIMEOUT = max(15, min(int(os.getenv("SCAN_TIMEOUT_SECONDS", "120")), 300))
MAX_CONCURRENT = max(1, min(int(os.getenv("MAX_CONCURRENT_SCANS", "1")), 3))
PORTS_DEFAULT = [22, 53, 80, 443, 445, 3389, 8080, 8443]

app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="strict", https_only=False)
scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT)
scheduler_jobs: dict[int, dict] = {}
scheduler = AsyncIOScheduler(timezone="UTC")

# Lightweight per-process login throttling. For multi-worker/public deployments, use a
# shared rate-limit store and a reverse proxy; this MVP is intended for localhost use.
LOGIN_MAX_ATTEMPTS = max(3, min(int(os.getenv("LOGIN_MAX_ATTEMPTS", "5")), 20))
LOGIN_WINDOW_SECONDS = max(60, min(int(os.getenv("LOGIN_WINDOW_SECONDS", "900")), 3600))
_login_failures: dict[str, list[float]] = {}


def login_is_limited(key: str, current_time: float | None = None) -> bool:
    current_time = time.time() if current_time is None else current_time
    cutoff = current_time - LOGIN_WINDOW_SECONDS
    failures = [stamp for stamp in _login_failures.get(key, []) if stamp > cutoff]
    _login_failures[key] = failures
    return len(failures) >= LOGIN_MAX_ATTEMPTS


def record_login_failure(key: str, current_time: float | None = None) -> None:
    current_time = time.time() if current_time is None else current_time
    cutoff = current_time - LOGIN_WINDOW_SECONDS
    # Periodically discard stale keys to keep memory bounded.
    for old_key in list(_login_failures):
        recent = [stamp for stamp in _login_failures[old_key] if stamp > cutoff]
        if recent:
            _login_failures[old_key] = recent
        else:
            _login_failures.pop(old_key, None)
    _login_failures.setdefault(key, []).append(current_time)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db() -> None:
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator')),
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, ports TEXT NOT NULL,
            status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
            requested_by TEXT NOT NULL, summary TEXT, error TEXT
        );
        CREATE TABLE IF NOT EXISTS devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            ip TEXT NOT NULL, hostname TEXT, state TEXT NOT NULL, open_ports TEXT NOT NULL DEFAULT '[]',
            UNIQUE(scan_id, ip)
        );
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
            detail TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS schedules(
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, ports TEXT NOT NULL,
            interval_minutes INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)
        username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin").strip() or "admin"
        password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
        existing = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not existing and len(password) >= 12 and not password.startswith("ChangeThis-") and not password.startswith("replace-"):
            con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                        (username, hash_password(password), "admin", now()))
            con.execute("INSERT INTO audit(actor,action,detail,created_at) VALUES(?,?,?,?)",
                        ("system", "bootstrap_admin_created", username, now()))


init_db()


@app.middleware("http")
async def enforce_same_origin_for_unsafe_requests(request: Request, call_next):
    # Browsers send Origin on cross-origin POST requests. Reject mismatches while
    # allowing local command-line clients that do not send Origin.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        host = request.headers.get("host", "")
        if origin:
            from urllib.parse import urlsplit
            parsed = urlsplit(origin)
            expected_host = host.lower()
            origin_host = (parsed.netloc or "").lower()
            if parsed.scheme not in {"http", "https"} or not origin_host or origin_host != expected_host:
                return JSONResponse({"detail": "Cross-origin request rejected."}, status_code=403)
    response = await call_next(request)
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response


async def execute_scheduled_scan(schedule_id: int) -> None:
    with db() as con:
        row = con.execute("SELECT * FROM schedules WHERE id=? AND enabled=1", (schedule_id,)).fetchone()
        running = con.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
    if not row or running >= MAX_CONCURRENT:
        return
    try:
        target = validate_target(row["target"], MAX_HOSTS)
        ports = validate_ports(safe_json(row["ports"], []), MAX_PORTS)
    except ValueError as exc:
        audit("scheduler", "scheduled_scan_rejected", f"id={schedule_id}: {exc}")
        return
    with db() as con:
        cur = con.execute("INSERT INTO scans(target,ports,status,started_at,requested_by) VALUES(?,?,?,?,?)",
                          (target, json.dumps(ports), "running", now(), f"schedule:{schedule_id}"))
        scan_id = cur.lastrowid
    audit("scheduler", "scheduled_scan_started", f"schedule_id={schedule_id}; scan_id={scan_id}")
    asyncio.create_task(run_nmap(scan_id, target, ports, f"schedule:{schedule_id}"))


def register_schedule(schedule_id: int, interval_minutes: int) -> None:
    job_id = f"netscope-schedule-{schedule_id}"
    if scheduler.running and scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if scheduler.running:
        scheduler.add_job(execute_scheduled_scan, "interval", minutes=interval_minutes,
                          args=[schedule_id], id=job_id, replace_existing=True, max_instances=1,
                          coalesce=True)


@app.on_event("startup")
async def start_optional_scheduler():
    if os.getenv("SCHEDULER_ENABLED", "false").lower() != "true":
        return
    scheduler.start()
    with db() as con:
        rows = con.execute("SELECT id,interval_minutes FROM schedules WHERE enabled=1").fetchall()
    for row in rows:
        scheduler.add_job(execute_scheduled_scan, "interval", minutes=row["interval_minutes"],
                          args=[row["id"]], id=f"netscope-schedule-{row['id']}",
                          replace_existing=True, max_instances=1, coalesce=True)


@app.on_event("shutdown")
async def stop_optional_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)


def audit(actor: str, action: str, detail: str = "") -> None:
    with db() as con:
        con.execute("INSERT INTO audit(actor,action,detail,created_at) VALUES(?,?,?,?)",
                    (actor, action, detail[:1000], now()))


def current_user(request: Request) -> dict:
    uid = request.session.get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Please sign in.")
    with db() as con:
        row = con.execute("SELECT id,username,role,active FROM users WHERE id=?", (uid,)).fetchone()
    if not row or not row["active"]:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return dict(row)


def admin_user(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return user


def safe_json(value: str, default):
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return default


@app.get("/api/health")
def health():
    return {"status": "ok", "app": APP_NAME, "nmap_available": bool(shutil.which("nmap") or shutil.which("nmap.exe"))}


@app.post("/api/login")
def login(request: Request, username: Annotated[str, Form()], password: Annotated[str, Form()]):
    normalized_username = username.strip()[:80] or "unknown"
    client_host = request.client.host if request.client else "unknown"
    rate_key = f"{client_host}:{normalized_username.casefold()}"
    if login_is_limited(rate_key):
        audit(normalized_username, "login_rate_limited", client_host)
        return RedirectResponse("/?error=Too%20many%20login%20attempts.%20Wait%2015%20minutes.", status_code=303)
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username.strip(),)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        record_login_failure(rate_key)
        audit(normalized_username, "login_failed", client_host)
        return RedirectResponse("/?error=Invalid%20username%20or%20password", status_code=303)
    _login_failures.pop(rate_key, None)
    request.session.clear()
    request.session["uid"] = row["id"]
    request.session["username"] = row["username"]
    audit(row["username"], "login_success")
    return RedirectResponse("/", status_code=303)


@app.post("/api/logout")
def logout(request: Request):
    username = request.session.get("username", "unknown")
    request.session.clear()
    audit(username, "logout")
    return RedirectResponse("/", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    uid = request.session.get("uid")
    user = None
    if uid:
        try:
            user = current_user(request)
        except HTTPException:
            user = None
    if not user:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", html_escape(request.query_params.get("error", ""))))
    return HTMLResponse(DASHBOARD_HTML.replace("__USER__", html_escape(user["username"])).replace("__ROLE__", html_escape(user["role"])))


@app.get("/api/dashboard")
def dashboard(user: dict = Depends(current_user)):
    with db() as con:
        counts = {
            "scans": con.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "devices": con.execute("SELECT COUNT(DISTINCT ip) FROM devices").fetchone()[0],
            "alerts": con.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0],
            "running": con.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0],
        }
        recent = [dict(r) for r in con.execute("SELECT id,target,status,started_at,finished_at,requested_by,summary,error FROM scans ORDER BY id DESC LIMIT 10")]
    return {"counts": counts, "recent": recent}


@app.get("/api/scans")
def scans(user: dict = Depends(current_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["ports"] = safe_json(item["ports"], [])
            item["summary"] = safe_json(item["summary"] or "{}", {})
            output.append(item)
    return output


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int, user: dict = Depends(current_user)):
    with db() as con:
        scan = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found.")
        devices = [dict(r) for r in con.execute("SELECT * FROM devices WHERE scan_id=? ORDER BY ip", (scan_id,))]
        alerts = [dict(r) for r in con.execute("SELECT * FROM alerts WHERE scan_id=? ORDER BY id DESC", (scan_id,))]
    result = dict(scan)
    result["ports"] = safe_json(result["ports"], [])
    result["summary"] = safe_json(result["summary"] or "{}", {})
    for d in devices:
        d["open_ports"] = safe_json(d["open_ports"], [])
    result["devices"] = devices
    result["alerts"] = alerts
    return result


async def run_nmap(scan_id: int, target: str, ports: list[int], actor: str):
    async with scan_semaphore:
        try:
            executable = shutil.which("nmap") or shutil.which("nmap.exe")
            if not executable:
                raise RuntimeError("Nmap was not found. Install Nmap for Windows and ensure nmap.exe is on PATH.")
            # Revalidate immediately before launching the process.
            target = validate_target(target, MAX_HOSTS)
            ports = validate_ports(ports, MAX_PORTS)
            cmd = [executable, "-n", "-sT", "-T2", "--open", "--reason",
                   "--host-timeout", f"{SCAN_TIMEOUT}s", "--max-retries", "1",
                   "-p", ",".join(map(str, ports)), "-oX", "-", target]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT + 15)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                raise RuntimeError("Scan timed out and was stopped.")
            if proc.returncode not in (0, 1):
                raise RuntimeError((stderr.decode("utf-8", "replace") or "Nmap exited with an error.")[:500])
            import xml.etree.ElementTree as ET
            root = ET.fromstring(stdout)
            found = []
            with db() as con:
                for host in root.findall("host"):
                    addr = host.find("address[@addrtype='ipv4']")
                    if addr is None:
                        continue
                    ip = addr.attrib.get("addr", "")
                    # Defensive result scope check.
                    ip_obj = ipaddress.ip_address(ip)
                    if not any(ip_obj in net for net in approved_networks()):
                        continue
                    status_el = host.find("status")
                    state = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"
                    hostname_el = host.find("hostnames/hostname")
                    hostname = hostname_el.attrib.get("name", "") if hostname_el is not None else ""
                    opened = []
                    for port_el in host.findall("ports/port"):
                        state_el = port_el.find("state")
                        if state_el is not None and state_el.attrib.get("state") == "open":
                            opened.append({"port": int(port_el.attrib["portid"]), "protocol": port_el.attrib.get("protocol", "tcp")})
                    con.execute("INSERT OR REPLACE INTO devices(scan_id,ip,hostname,state,open_ports) VALUES(?,?,?,?,?)",
                                (scan_id, ip, hostname, state, json.dumps(opened)))
                    found.append({"ip": ip, "hostname": hostname, "state": state, "open_ports": opened})
                    for item in opened:
                        port = item["port"]
                        severity = "high" if port in (23, 445, 3389, 5900) else "medium" if port in (21, 22, 80, 8080, 8443) else "info"
                        title = f"Open TCP port {port} on {ip}"
                        detail = "Review whether this service is expected and access-controlled; an open port alone does not prove a vulnerability."
                        con.execute("INSERT INTO alerts(scan_id,severity,title,detail,created_at) VALUES(?,?,?,?,?)",
                                    (scan_id, severity, title, detail, now()))
                summary = {"hosts_with_open_ports": len(found), "open_port_count": sum(len(d["open_ports"]) for d in found)}
                con.execute("UPDATE scans SET status='completed',finished_at=?,summary=? WHERE id=?",
                            (now(), json.dumps(summary), scan_id))
                con.execute("INSERT INTO audit(actor,action,detail,created_at) VALUES(?,?,?,?)",
                            (actor, "scan_completed", json.dumps({"scan_id": scan_id, **summary}), now()))
        except Exception as exc:
            with db() as con:
                con.execute("UPDATE scans SET status='failed',finished_at=?,error=? WHERE id=?",
                            (now(), str(exc)[:1000], scan_id))
                con.execute("INSERT INTO audit(actor,action,detail,created_at) VALUES(?,?,?,?)",
                            (actor, "scan_failed", f"scan_id={scan_id}: {str(exc)[:300]}", now()))


@app.post("/api/scans", status_code=202)
async def create_scan(request: Request, user: dict = Depends(current_user)):
    if user["role"] not in ("admin", "operator"):
        raise HTTPException(403, "Insufficient role.")
    try:
        payload = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Request body must be a JSON object.")
    try:
        target = validate_target(str(payload.get("target", "")), MAX_HOSTS)
        raw_ports = payload.get("ports", PORTS_DEFAULT)
        if not isinstance(raw_ports, list):
            raise ValueError("Ports must be a JSON list of allowed TCP port numbers.")
        ports = validate_ports(raw_ports, MAX_PORTS)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))
    with db() as con:
        running = con.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
        if running >= MAX_CONCURRENT:
            raise HTTPException(429, "Scan queue is full. Wait for the active scan to finish.")
        cur = con.execute("INSERT INTO scans(target,ports,status,started_at,requested_by) VALUES(?,?,?,?,?)",
                          (target, json.dumps(ports), "running", now(), user["username"]))
        scan_id = cur.lastrowid
        con.execute("INSERT INTO audit(actor,action,detail,created_at) VALUES(?,?,?,?)",
                    (user["username"], "scan_started", json.dumps({"scan_id": scan_id, "target": target, "ports": ports}), now()))
    asyncio.create_task(run_nmap(scan_id, target, ports, user["username"]))
    return {"id": scan_id, "status": "running", "target": target, "ports": ports}


@app.get("/api/alerts")
def alerts(user: dict = Depends(current_user)):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")]


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, user: dict = Depends(current_user)):
    with db() as con:
        cur = con.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Alert not found.")
    audit(user["username"], "alert_acknowledged", str(alert_id))
    return {"ok": True}


@app.get("/api/users")
def list_users(user: dict = Depends(admin_user)):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT id,username,role,active,created_at FROM users ORDER BY id")]


@app.post("/api/users", status_code=201)
async def create_user(request: Request, user: dict = Depends(admin_user)):
    try:
        payload = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Request body must be a JSON object.")
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    role = str(payload.get("role", "operator"))
    if len(username) < 3 or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(400, "Username must be 3-40 letters, digits, underscore or hyphen.")
    if role not in ("admin", "operator"):
        raise HTTPException(400, "Role must be admin or operator.")
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    try:
        with db() as con:
            cur = con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                              (username, password_hash, role, now()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists.")
    audit(user["username"], "user_created", json.dumps({"username": username, "role": role}))
    return {"id": cur.lastrowid, "username": username, "role": role}


@app.post("/api/schedules/{schedule_id}/enable")
async def set_schedule_enabled(schedule_id: int, request: Request, user: dict = Depends(admin_user)):
    if os.getenv("SCHEDULER_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Scheduler is disabled in .env. Set SCHEDULER_ENABLED=true after reviewing the approved scope.")
    try:
        payload = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Request body must be valid JSON.")
    if not isinstance(payload, dict) or not isinstance(payload.get("enabled", False), bool):
        raise HTTPException(400, "The enabled field must be true or false.")
    enabled = payload.get("enabled", False)
    with db() as con:
        row = con.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Schedule not found.")
        con.execute("UPDATE schedules SET enabled=? WHERE id=?", (1 if enabled else 0, schedule_id))
    job_id = f"netscope-schedule-{schedule_id}"
    if enabled:
        register_schedule(schedule_id, int(row["interval_minutes"]))
    elif scheduler.running and scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    audit(user["username"], "schedule_enabled" if enabled else "schedule_disabled", str(schedule_id))
    return {"id": schedule_id, "enabled": enabled}


@app.get("/api/schedules")
def list_schedules(user: dict = Depends(admin_user)):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM schedules ORDER BY id DESC")]


@app.post("/api/schedules", status_code=201)
async def create_schedule(request: Request, user: dict = Depends(admin_user)):
    if os.getenv("SCHEDULER_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Scheduler is disabled. Enable SCHEDULER_ENABLED=true only after reviewing your approved scope.")
    try:
        payload = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Request body must be a JSON object.")
    try:
        target = validate_target(str(payload.get("target", "")), MAX_HOSTS)
        raw_ports = payload.get("ports", PORTS_DEFAULT)
        if not isinstance(raw_ports, list):
            raise ValueError("Ports must be a JSON list of allowed TCP port numbers.")
        ports = validate_ports(raw_ports, MAX_PORTS)
        interval = int(payload.get("interval_minutes", 1440))
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))
    if interval < 60 or interval > 10080:
        raise HTTPException(400, "Schedule interval must be 60 to 10080 minutes.")
    with db() as con:
        cur = con.execute("INSERT INTO schedules(target,ports,interval_minutes,enabled,created_by,created_at) VALUES(?,?,?,?,?,?)",
                          (target, json.dumps(ports), interval, 0, user["username"], now()))
    audit(user["username"], "schedule_created_disabled", str(cur.lastrowid))
    return {"id": cur.lastrowid, "enabled": False, "message": "Saved disabled. An administrator must explicitly enable this schedule after reviewing the approved scope."}



@app.post("/api/mega/dns")
async def mega_dns(request: Request, user: dict = Depends(current_user)):
    try:
        payload = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Request body must be a JSON object.")
    try:
        result = await asyncio.wait_for(asyncio.to_thread(resolve_public_host, str(payload.get("target", ""))), timeout=8)
    except TargetError as exc:
        audit(user["username"], "mega_dns_rejected", str(exc))
        raise HTTPException(400, str(exc))
    except asyncio.TimeoutError:
        raise HTTPException(504, "DNS lookup timed out.")
    audit(user["username"], "mega_dns_checked", result["host"])
    return result


@app.post("/api/mega/web-check")
async def mega_web_check(request: Request, user: dict = Depends(current_user)):
    try:
        payload = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Request body must be a JSON object.")
    try:
        result = await asyncio.wait_for(asyncio.to_thread(web_check, str(payload.get("target", ""))), timeout=18)
    except TargetError as exc:
        audit(user["username"], "mega_web_check_rejected", str(exc))
        raise HTTPException(400, str(exc))
    except asyncio.TimeoutError:
        raise HTTPException(504, "Website checks timed out.")
    audit(user["username"], "mega_web_check_completed", json.dumps({"host": result["host"], "https": result["https"]["status_code"], "http": result["http"]["status_code"]}))
    return result


@app.get("/api/mega/export/scans")
def mega_export_scans(user: dict = Depends(current_user)):
    with db() as con:
        scan_rows = [dict(row) for row in con.execute("SELECT id,target,ports,status,started_at,finished_at,requested_by,summary,error FROM scans ORDER BY id DESC LIMIT 500")]
        alert_rows = [dict(row) for row in con.execute("SELECT id,scan_id,severity,title,detail,created_at,acknowledged FROM alerts ORDER BY id DESC LIMIT 1000")]
        for row in scan_rows:
            row["ports"] = safe_json(row["ports"], [])
            row["summary"] = safe_json(row["summary"] or "{}", {})
    audit(user["username"], "mega_export_scans", f"scans={len(scan_rows)}; alerts={len(alert_rows)}")
    return JSONResponse({"exported_at": now(), "scans": scan_rows, "alerts": alert_rows},
                        headers={"Content-Disposition": 'attachment; filename="netscope-mega-report.json"'})

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetScope Pro · Sign in</title><style>
:root{color-scheme:dark;--bg:#080d18;--panel:#101a2a;--line:#233149;--text:#edf4ff;--muted:#8fa3bd;--accent:#61e6bd}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#152846,#080d18 55%);font:15px system-ui;color:var(--text);min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(440px,100%);background:#101a2aee;border:1px solid var(--line);border-radius:22px;padding:32px;box-shadow:0 24px 80px #0007}.logo{width:48px;height:48px;border-radius:15px;background:#61e6bd18;color:var(--accent);display:grid;place-items:center;font-size:25px}.muted{color:var(--muted)}label{display:block;margin:16px 0 7px;color:#c9d7e9}input{width:100%;padding:13px;border:1px solid var(--line);background:#0a1220;border-radius:10px;color:var(--text)}button{margin-top:22px;width:100%;padding:13px;background:var(--accent);color:#06130f;border:0;border-radius:10px;font-weight:750;cursor:pointer}.error{color:#ff9d9d;min-height:20px}.small{font-size:12px;line-height:1.5}</style></head><body><main class="card"><div class="logo">⌁</div><h1>NetScope <span style="color:#61e6bd">Pro</span></h1><p class="muted">Network visibility for authorized administrators.</p><p class="error">__ERROR__</p><form method="post" action="/api/login"><label>Username</label><input name="username" autocomplete="username" required maxlength="40"><label>Password</label><input type="password" name="password" autocomplete="current-password" required><button type="submit">Sign in securely →</button></form><p class="muted small">Local dashboard · Scanning remains disabled until an approved CIDR is configured.</p></main></body></html>"""

DASHBOARD_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetScope Pro</title><style>
:root{color-scheme:dark;--bg:#080d18;--panel:#101a2a;--panel2:#0c1524;--line:#223149;--text:#edf4ff;--muted:#8fa3bd;--accent:#61e6bd;--blue:#83a9ff;--warn:#ffcf70}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px system-ui,-apple-system,Segoe UI,sans-serif}.layout{display:grid;grid-template-columns:230px 1fr;min-height:100vh}.side{padding:24px 16px;background:#0b1321;border-right:1px solid var(--line)}.brand{font-size:20px;font-weight:800;padding:0 10px 28px}.brand span{color:var(--accent)}.nav{padding:12px;border-radius:9px;color:var(--muted);margin:4px 0;cursor:pointer}.nav.active,.nav:hover{background:#61e6bd15;color:var(--accent)}.main{padding:26px;min-width:0}.top{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}.muted{color:var(--muted)}.pill{border:1px solid var(--line);padding:7px 10px;border-radius:99px;color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:24px 0}.panel,.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.stat .value{font-size:28px;font-weight:800;margin-top:9px}.stat .label{color:var(--muted)}.columns{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(260px,1fr);gap:15px}.sectionhead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:15px}h1{font-size:26px;margin:0}h2{font-size:16px;margin:0}button{background:var(--accent);border:0;border-radius:9px;padding:10px 14px;font-weight:750;cursor:pointer;color:#06130f}button.secondary{background:#17253a;color:var(--text);border:1px solid var(--line)}input,select{width:100%;background:#091220;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px;margin:6px 0 12px}label{color:var(--muted);font-size:12px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:11px 8px;font-size:12px;vertical-align:top}th{color:var(--muted);font-weight:600}.status{color:var(--accent)}.alert{border-left:3px solid var(--warn);padding:10px 12px;background:var(--panel2);border-radius:5px;margin:8px 0}.hidden{display:none}.note{border:1px solid #4e432b;background:#2a2417;color:#ffe2a1;padding:12px;border-radius:10px;margin:18px 0;font-size:12px}.empty{padding:24px;text-align:center;color:var(--muted)}.formrow{display:grid;grid-template-columns:1fr 1fr;gap:10px}.toast{color:var(--accent);min-height:20px;font-size:12px}pre{white-space:pre-wrap;word-break:break-word}@media(max-width:1000px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.columns{grid-template-columns:1fr}}@media(max-width:650px){.layout{grid-template-columns:1fr}.side{border-right:0;border-bottom:1px solid var(--line);padding:12px}.brand{padding:6px 10px}.navs{display:flex;gap:4px;overflow:auto}.nav{white-space:nowrap}.main{padding:16px}.grid{gap:8px}.stat{padding:13px}.stat .value{font-size:22px}.formrow{grid-template-columns:1fr}}</style></head><body><div class="layout"><aside class="side"><div class="brand">⌁ NetScope <span>Pro</span></div><div class="navs"><div class="nav active" onclick="show('overview',this)">◫ Overview</div><div class="nav" onclick="show('mega',this)">✦ Mega tools</div><div class="nav" onclick="show('scans',this)">◎ Scan history</div><div class="nav" onclick="show('alerts',this)">♧ Alerts</div><div class="nav" onclick="show('users',this)">♙ Users</div><div class="nav" onclick="show('schedules',this)">◷ Schedules</div></div><p class="muted" style="font-size:11px;margin:28px 10px">AUTHORIZED NETWORKS ONLY</p></aside><main class="main"><header class="top"><div><p class="muted" style="margin:0 0 5px">NETWORK OPERATIONS / CONSOLE</p><h1 id="pageTitle">Overview</h1></div><div style="display:flex;align-items:center;gap:12px"><span class="pill">__USER__ · __ROLE__</span><form action="/api/logout" method="post"><button class="secondary">Sign out</button></form></div></header><div class="note">Safety mode: scan only networks explicitly approved by your institution. Configure APPROVED_CIDRS in .env before scanning. This app is local-only by default.</div><div class="toast" id="toast"></div>
<section id="overview"><div class="grid"><div class="stat"><div class="label">Scan jobs</div><div class="value" id="countScans">—</div></div><div class="stat"><div class="label">Unique discovered IPs</div><div class="value" id="countDevices">—</div></div><div class="stat"><div class="label">Unacknowledged alerts</div><div class="value" id="countAlerts">—</div></div><div class="stat"><div class="label">Running scans</div><div class="value" id="countRunning">—</div></div></div><div class="columns"><div class="panel"><div class="sectionhead"><h2>Recent scan jobs</h2><button class="secondary" onclick="loadAll()">Refresh</button></div><div id="recentTable" class="empty">Loading scan history…</div></div><div class="panel"><div class="sectionhead"><h2>Start a bounded scan</h2><span class="pill">Nmap TCP connect</span></div><label>Approved IPv4 target / CIDR</label><input id="target" placeholder="e.g. 192.0.2.0/28"><label>TCP ports (comma-separated allowed ports)</label><input id="ports" value="22,80,443,445,3389"><p class="muted" style="font-size:12px">Only common ports from the built-in allowlist are accepted. Max 25 ports and 256 addresses by default.</p><button onclick="startScan()">Start scan →</button><p class="muted" style="font-size:12px">Nmap must be installed on this Windows machine.</p></div></div></section>
<section id="mega" class="hidden"><div class="columns"><div class="panel"><div class="sectionhead"><h2>Public DNS / IP lookup</h2><span class="pill">DNS resolution</span></div><label>Public domain or public IP</label><input id="megaDnsTarget" placeholder="example.com or 8.8.8.8"><button onclick="runMegaDns()">Resolve target →</button><pre id="megaDnsResult" class="muted"></pre></div><div class="panel"><div class="sectionhead"><h2>Website security check</h2><span class="pill">HTTP · HTTPS · TLS</span></div><label>Public website domain / URL</label><input id="megaWebTarget" placeholder="https://example.com"><button onclick="runMegaWeb()">Check website →</button><p class="muted" style="font-size:12px">Checks HTTP/HTTPS reachability, certificate trust and common security headers. It does not exploit the site or follow redirects.</p><pre id="megaWebResult" class="muted"></pre></div></div><div class="panel" style="margin-top:15px"><div class="sectionhead"><h2>Export report</h2><span class="pill">JSON</span></div><p class="muted">Download the latest 500 scan records and 1,000 alerts.</p><a href="/api/mega/export/scans" style="color:var(--accent)">Download Mega Scanner report ↓</a></div></section><section id="scans" class="panel hidden"><div class="sectionhead"><h2>Scan history</h2><button class="secondary" onclick="loadScans()">Refresh</button></div><div id="scansTable" class="empty">Loading…</div></section>
<section id="alerts" class="panel hidden"><div class="sectionhead"><h2>Security alerts</h2><button class="secondary" onclick="loadAlerts()">Refresh</button></div><div id="alertsList" class="empty">Loading…</div></section>
<section id="users" class="panel hidden"><div class="sectionhead"><h2>User management</h2><span class="pill">Admin only</span></div><div class="formrow"><div><label>New username</label><input id="newUsername" placeholder="network_operator"></div><div><label>Temporary password (12+ chars)</label><input id="newPassword" type="password" placeholder="Use a strong password"></div></div><label>Role</label><select id="newRole"><option value="operator">Operator — scan and view</option><option value="admin">Administrator — manage users</option></select><button onclick="createUser()">Create user</button><div id="usersList" style="margin-top:18px"></div></section>
<section id="schedules" class="panel hidden"><div class="sectionhead"><h2>Scheduled scans</h2><span class="pill">Disabled by default</span></div><p class="muted">Scheduling is opt-in. Saved schedules remain disabled until an administrator enables scheduling in .env and explicitly enables each reviewed schedule.</p><div class="formrow"><div><label>Approved target / CIDR</label><input id="scheduleTarget" placeholder="approved CIDR"></div><div><label>Interval (60–10080 minutes)</label><input id="scheduleInterval" type="number" min="60" max="10080" value="1440"></div></div><label>TCP ports</label><input id="schedulePorts" value="22,80,443"><button onclick="createSchedule()">Save disabled schedule</button><div id="scheduleList" style="margin-top:18px"></div></section>
</main></div><script>
async function api(url,opts={}){const r=await fetch(url,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});let d;try{d=await r.json()}catch{d={detail:await r.text()}}if(!r.ok)throw new Error(d.detail||'Request failed');return d}
function toast(s){document.getElementById('toast').textContent=s;setTimeout(()=>document.getElementById('toast').textContent='',6000)}
function show(id,el){document.querySelectorAll('main section').forEach(s=>s.classList.add('hidden'));document.getElementById(id).classList.remove('hidden');document.querySelectorAll('.nav').forEach(n=>n.classList.remove('active'));el.classList.add('active');document.getElementById('pageTitle').textContent=({overview:'Overview',mega:'Mega Scanner Tools',scans:'Scan history',alerts:'Security alerts',users:'User management',schedules:'Scheduled scans'})[id];if(id==='scans')loadScans();if(id==='alerts')loadAlerts();if(id==='users')loadUsers();if(id==='schedules')loadSchedules()}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function table(rows){if(!rows.length)return '<div class="empty">No records yet.</div>';return '<div style="overflow:auto"><table><thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Started</th><th>Requested by</th></tr></thead><tbody>'+rows.map(x=>'<tr><td>#'+x.id+'</td><td>'+esc(x.target)+'</td><td class="status">'+esc(x.status)+'</td><td>'+esc(x.started_at)+'</td><td>'+esc(x.requested_by)+'</td></tr>').join('')+'</tbody></table></div>'}
async function runMegaDns(){const out=document.getElementById('megaDnsResult');out.textContent='Resolving…';try{const d=await api('/api/mega/dns',{method:'POST',body:JSON.stringify({target:document.getElementById('megaDnsTarget').value})});out.textContent=JSON.stringify(d,null,2)}catch(e){out.textContent=e.message}}
async function runMegaWeb(){const out=document.getElementById('megaWebResult');out.textContent='Checking public website…';try{const d=await api('/api/mega/web-check',{method:'POST',body:JSON.stringify({target:document.getElementById('megaWebTarget').value})});out.textContent=JSON.stringify(d,null,2)}catch(e){out.textContent=e.message}}
async function loadAll(){try{const d=await api('/api/dashboard');countScans.textContent=d.counts.scans;countDevices.textContent=d.counts.devices;countAlerts.textContent=d.counts.alerts;countRunning.textContent=d.counts.running;recentTable.innerHTML=table(d.recent); }catch(e){toast(e.message)}}
async function loadScans(){try{scansTable.innerHTML=table(await api('/api/scans'))}catch(e){scansTable.textContent=e.message}}
async function loadAlerts(){try{const a=await api('/api/alerts');alertsList.innerHTML=a.length?a.map(x=>'<div class="alert"><b>'+esc(x.severity.toUpperCase())+' · '+esc(x.title)+'</b><p>'+esc(x.detail)+'</p><small class="muted">'+esc(x.created_at)+'</small>'+(x.acknowledged?' · Acknowledged':' <button class="secondary" onclick="ack('+x.id+')">Acknowledge</button>')+'</div>').join(''):'<div class="empty">No alerts yet.</div>'}catch(e){alertsList.textContent=e.message}}
async function ack(id){try{await api('/api/alerts/'+id+'/acknowledge',{method:'POST'});await loadAlerts();await loadAll()}catch(e){toast(e.message)}}
async function startScan(){try{const ports=document.getElementById('ports').value.split(',').map(x=>Number(x.trim()));const d=await api('/api/scans',{method:'POST',body:JSON.stringify({target:document.getElementById('target').value,ports})});toast('Scan #'+d.id+' queued. Refresh for status.');await loadAll()}catch(e){toast(e.message)}}
async function loadUsers(){try{const u=await api('/api/users');usersList.innerHTML='<div style="overflow:auto"><table><tr><th>User</th><th>Role</th><th>Active</th></tr>'+u.map(x=>'<tr><td>'+esc(x.username)+'</td><td>'+esc(x.role)+'</td><td>'+x.active+'</td></tr>').join('')+'</table></div>'}catch(e){usersList.textContent=e.message}}
async function createUser(){try{const d=await api('/api/users',{method:'POST',body:JSON.stringify({username:newUsername.value,password:newPassword.value,role:newRole.value})});toast('Created '+d.username);newPassword.value='';await loadUsers()}catch(e){toast(e.message)}}
async function loadSchedules(){try{const s=await api('/api/schedules');scheduleList.innerHTML=s.length?'<table><tr><th>Target</th><th>Interval</th><th>Status</th><th>Action</th></tr>'+s.map(x=>'<tr><td>'+esc(x.target)+'</td><td>'+x.interval_minutes+' min</td><td>'+(x.enabled?'Enabled':'Disabled')+'</td><td><button class="secondary" onclick="toggleSchedule('+x.id+','+(!x.enabled)+')">'+(x.enabled?'Disable':'Enable')+'</button></td></tr>').join('')+'</table>':'<div class="empty">No saved schedules.</div>'}catch(e){scheduleList.textContent=e.message}}
async function toggleSchedule(id,enabled){try{const d=await api('/api/schedules/'+id+'/enable',{method:'POST',body:JSON.stringify({enabled})});toast('Schedule '+(d.enabled?'enabled':'disabled'));await loadSchedules()}catch(e){toast(e.message)}}
async function createSchedule(){try{const ports=schedulePorts.value.split(',').map(x=>Number(x.trim()));const d=await api('/api/schedules',{method:'POST',body:JSON.stringify({target:scheduleTarget.value,ports,interval_minutes:Number(scheduleInterval.value)})});toast(d.message);await loadSchedules()}catch(e){toast(e.message)}}
loadAll();loadAlerts();setInterval(loadAll,10000);
</script></body></html>"""