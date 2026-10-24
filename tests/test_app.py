import os
from pathlib import Path

# Keep test database outside the repository and avoid creating a bootstrap account.
test_data = Path(__file__).resolve().parents[1] / "data"
test_data.mkdir(exist_ok=True)
os.environ["DATABASE_PATH"] = str(test_data / "test.db")
os.environ["APP_SECRET_KEY"] = "test-only-secret-key-that-is-long-enough-123"
os.environ["APPROVED_CIDRS"] = ""
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = ""
os.environ["SCHEDULER_ENABLED"] = "false"

from fastapi.testclient import TestClient
from app.main import app


def test_health_endpoint_has_security_headers():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_login_error_query_is_escaped():
    with TestClient(app) as client:
        response = client.get("/", params={"error": '<script>alert("x")</script>'})
    assert response.status_code == 200
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in response.text
    assert '<script>alert("x")</script>' not in response.text


def test_protected_dashboard_requires_login():
    with TestClient(app) as client:
        response = client.get("/api/dashboard")
    assert response.status_code == 401


def test_create_user_rejects_invalid_json_and_non_object_payloads():
    from app.main import current_user

    app.dependency_overrides[current_user] = lambda: {"id": 1, "username": "test-admin", "role": "admin", "active": 1}
    try:
        with TestClient(app) as client:
            invalid_json = client.post("/api/users", content="{", headers={"Content-Type": "application/json"})
            non_object = client.post("/api/users", json=[])
        assert invalid_json.status_code == 400
        assert invalid_json.json()["detail"] == "Request body must be valid JSON."
        assert non_object.status_code == 400
        assert non_object.json()["detail"] == "Request body must be a JSON object."
    finally:
        app.dependency_overrides.pop(current_user, None)



def test_cross_origin_post_is_rejected():
    with TestClient(app) as client:
        response = client.post("/api/logout", headers={"Origin": "https://attacker.example"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-origin request rejected."


def test_login_rate_limit_blocks_repeated_failures():
    from app.main import _login_failures
    _login_failures.clear()
    with TestClient(app, follow_redirects=False) as client:
        for _ in range(5):
            response = client.post("/api/login", data={"username": "missing_rate_limit_user", "password": "wrong-password"})
            assert response.status_code == 303
        blocked = client.post("/api/login", data={"username": "missing_rate_limit_user", "password": "wrong-password"})
    assert blocked.status_code == 303
    assert "Too%20many%20login%20attempts" in blocked.headers["location"]
    _login_failures.clear()



def test_scan_rejects_unapproved_target_with_client_error():
    import time
    from app.main import db
    from app.security import hash_password

    username = "testuser_" + str(time.time_ns())
    password = "Test-only-password-123!"
    with db() as con:
        con.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            (username, hash_password(password), "admin", "2026-01-01T00:00:00+00:00"),
        )
    with TestClient(app, follow_redirects=False) as client:
        login = client.post("/api/login", data={"username": username, "password": password})
        assert login.status_code == 303
        response = client.post("/api/scans", json={"target": "192.0.2.1", "ports": [80]})
    assert response.status_code == 400
    assert "Scanning is disabled" in response.json()["detail"]

def test_mega_scanner_endpoints_require_login():
    with TestClient(app) as client:
        dns = client.post("/api/mega/dns", json={"target": "example.com"})
        web_check = client.post("/api/mega/web-check", json={"target": "https://example.com"})
        report = client.get("/api/mega/export/scans")
    assert dns.status_code == 401
    assert web_check.status_code == 401
    assert report.status_code == 401


def test_mega_scanner_rejects_non_object_json(monkeypatch):
    from app.main import current_user

    app.dependency_overrides[current_user] = lambda: {
        "id": 1, "username": "test-admin", "role": "admin", "active": 1
    }
    try:
        with TestClient(app) as client:
            dns = client.post("/api/mega/dns", json=[])
            web_check = client.post("/api/mega/web-check", json=[])
        assert dns.status_code == 400
        assert web_check.status_code == 400
        assert dns.json()["detail"] == "Request body must be a JSON object."
        assert web_check.json()["detail"] == "Request body must be a JSON object."
    finally:
        app.dependency_overrides.pop(current_user, None)

def test_mega_dns_endpoint_returns_lookup_result(monkeypatch):
    from app.main import current_user
    import app.main as main_module

    expected = {
        "host": "example.com",
        "canonical_name": "example.com",
        "addresses": [{"address": "8.8.8.8", "family": "IPv4"}],
        "checked_at": "2026-10-23T00:00:00+00:00",
    }
    monkeypatch.setattr(main_module, "resolve_public_host", lambda target: expected)
    app.dependency_overrides[current_user] = lambda: {
        "id": 1, "username": "test-admin", "role": "admin", "active": 1
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/mega/dns", json={"target": "example.com"})
        assert response.status_code == 200
        assert response.json() == expected
    finally:
        app.dependency_overrides.pop(current_user, None)


def test_mega_web_check_endpoint_returns_bounded_check(monkeypatch):
    from app.main import current_user
    import app.main as main_module

    expected = {
        "host": "example.com",
        "addresses": [{"address": "8.8.8.8", "family": "IPv4"}],
        "https": {"status_code": 200, "reachable": True},
        "http": {"status_code": 301, "reachable": True},
        "notes": ["redirects were not followed"],
        "findings": [],
    }
    monkeypatch.setattr(main_module, "web_check", lambda target: expected)
    app.dependency_overrides[current_user] = lambda: {
        "id": 1, "username": "test-admin", "role": "admin", "active": 1
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/mega/web-check", json={"target": "https://example.com", "authorized": True})
        assert response.status_code == 200
        assert response.json() == expected
    finally:
        app.dependency_overrides.pop(current_user, None)

def test_mega_scanner_returns_retryable_error_when_worker_slots_are_full(monkeypatch):
    from app.main import current_user, MegaScannerBusy
    import app.main as main_module

    def busy_worker(_operation, _target):
        raise MegaScannerBusy("Mega Scanner is busy; wait for an existing check to finish.")

    monkeypatch.setattr(main_module, "_run_mega_bounded", busy_worker)
    app.dependency_overrides[current_user] = lambda: {
        "id": 1, "username": "test-admin", "role": "admin", "active": 1
    }
    try:
        with TestClient(app) as client:
            dns = client.post("/api/mega/dns", json={"target": "example.com"})
            website = client.post("/api/mega/web-check", json={"target": "https://example.com"})
        assert dns.status_code == 503
        assert website.status_code == 503
        assert dns.headers["retry-after"] == "3"
        assert website.headers["retry-after"] == "3"
    finally:
        app.dependency_overrides.pop(current_user, None)

def test_static_scan_ui_uses_deployed_worker_as_default_api():
    index = Path(__file__).resolve().parents[1] / "index.html"
    html = index.read_text(encoding="utf-8")
    assert "https://netscope-pro-scan-api.kowshik-educ.workers.dev" in html
    assert "const DEFAULT_SCAN_API=" in html


def test_static_scan_ui_explains_missing_worker_allowlist():
    index = Path(__file__).resolve().parents[1] / "index.html"
    html = index.read_text(encoding="utf-8")
    assert "configured_targets: 0" in html
    assert "ALLOWED_SCAN_TARGETS" in html
    assert "Check API connection" in html



def test_mega_web_check_requires_explicit_authorization(monkeypatch):
    from app.main import current_user
    import app.main as main_module

    monkeypatch.setattr(main_module, "web_check", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not inspect")))
    app.dependency_overrides[current_user] = lambda: {
        "id": 1, "username": "test-admin", "role": "admin", "active": 1
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/mega/web-check", json={"target": "example.com"})
        assert response.status_code == 400
        assert "Confirm authorization" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(current_user, None)


def test_mega_web_check_rejects_oversized_request(monkeypatch):
    from app.main import current_user
    app.dependency_overrides[current_user] = lambda: {
        "id": 1, "username": "test-admin", "role": "admin", "active": 1
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/mega/web-check", content=" " * 5000, headers={"Content-Type": "application/json"})
        assert response.status_code == 413
    finally:
        app.dependency_overrides.pop(current_user, None)


def test_web_check_rate_limit_is_bounded_per_user(monkeypatch):
    from app.main import web_check_is_limited
    import app.main as main_module

    monkeypatch.setattr(main_module, "_web_check_requests", {})
    for i in range(main_module.WEB_CHECK_MAX_REQUESTS):
        assert web_check_is_limited("operator", current_time=float(i)) is False
    assert web_check_is_limited("operator", current_time=10.0) is True
    assert web_check_is_limited("other", current_time=10.0) is False

