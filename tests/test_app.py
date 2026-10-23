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
