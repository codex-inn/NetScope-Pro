import os
import tempfile
from pathlib import Path

# Keep test database outside the repository and avoid creating a bootstrap account.
os.environ["DATABASE_PATH"] = str(Path(tempfile.mkdtemp(prefix="netscope-test-")) / "test.db")
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
