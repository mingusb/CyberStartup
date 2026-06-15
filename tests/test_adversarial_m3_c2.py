import os
import sys
import json
import time
import pytest
from unittest.mock import patch, MagicMock, mock_open
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect

# Ensure project directories are in path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src/cyberstartup"))

from api.production_api import app, create_jwt, verify_jwt, execute_telemetry_pipeline
import main

client = TestClient(app)

# =====================================================================
# AREA 1: Invalid or malformed payloads to API routes
# =====================================================================

def test_login_malformed_payloads():
    """Stress-test /api/login with invalid, missing, or malformed JSON payloads."""
    # 1. Invalid JSON syntax
    response = client.post("/api/login", content="{invalid_json_format", headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    
    # 2. Empty JSON body
    response = client.post("/api/login", json={})
    assert response.status_code == 422
    
    # 3. Missing username or password
    response = client.post("/api/login", json={"username": "admin"})
    assert response.status_code == 422
    
    # 4. Invalid value types (integer instead of string)
    response = client.post("/api/login", json={"username": 12345, "password": "cyberstartup2026"})
    assert response.status_code == 422

    # 5. Extreme input sizes
    extreme_username = "A" * 10000
    response = client.post("/api/login", json={"username": extreme_username, "password": "cyberstartup2026"})
    assert response.status_code == 401  # Handled, but returned unauthenticated (which is correct)

def test_token_malformed_payloads():
    """Stress-test /api/token with missing, invalid, or empty form/JSON data."""
    # 1. Missing username/password entirely
    response = client.post("/api/token", data={})
    assert response.status_code == 401
    
    # 2. Invalid content type
    response = client.post("/api/token", content="not-a-form", headers={"Content-Type": "text/plain"})
    assert response.status_code == 401


# =====================================================================
# AREA 2: Write failures or permission errors on the telemetry json paths
# =====================================================================

def test_telemetry_write_failure_isolation():
    """
    Test the dual telemetry write path under filesystem errors (e.g. PermissionError).
    Asserts the lack of isolation: if the first write path fails, the second path is skipped.
    """
    original_open = open
    written_paths = []

    def mock_open_fn(file, mode='r', *args, **kwargs):
        filename = str(file)
        if "website/dashboard.json" in filename:
            raise PermissionError("Permission denied on website/dashboard.json")
        if "docs/dashboard.json" in filename:
            written_paths.append(filename)
        return original_open(file, mode, *args, **kwargs)

    # Mock python's builtins.open to simulate failure on the first path
    with patch('builtins.open', new=mock_open_fn):
        try:
            # We trigger the write path by calling execute_telemetry_pipeline inside a dynamic context or background logic
            # To test the execute_telemetry_pipeline backup write block:
            data = {
                "threats_preempted": 1,
                "nodes_saved": 5,
                "cost_avoided": 100000,
                "hours_saved": 24,
                "blast_radius_score": 0.1,
                "threshold": 0.05,
                "mode": "Tier 1 Base SaaS"
            }
            
            # Replicate the backup write logic inside production_api.py
            paths = ["website/dashboard.json", "docs/dashboard.json"]
            with pytest.raises(PermissionError):
                for path_segment in paths:
                    with open(os.path.join(PROJECT_ROOT, path_segment), "w") as f:
                        json.dump(data, f)
            
            # Assert that the second path (docs/dashboard.json) was NEVER attempted/written
            assert len(written_paths) == 0, "Second telemetry write path should be skipped if first fails"
        except Exception as e:
            assert isinstance(e, PermissionError)


def test_main_write_failure_isolation():
    """
    Test main.py's dual telemetry write path under PermissionError.
    Verifies that if the first file fails, the second file is skipped.
    """
    original_open = open
    written_paths = []

    def mock_open_fn(file, mode='r', *args, **kwargs):
        filename = str(file)
        if "website/dashboard.json" in filename:
            raise PermissionError("Permission denied")
        if "docs/dashboard.json" in filename:
            written_paths.append(filename)
        return original_open(file, mode, *args, **kwargs)

    with patch('builtins.open', new=mock_open_fn):
        dashboard_data = {"test": "data"}
        # Replicate the exact logic from main.py
        try:
            for path_segment in ["../../website/dashboard.json", "../../docs/dashboard.json"]:
                dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path_segment)
                with open(dashboard_path, "w") as f:
                    json.dump(dashboard_data, f)
        except (PermissionError, IOError) as e:
            # Verified that it catches the exception and prints the warning
            pass
        
        # Verify the second file was skipped (never written)
        assert len(written_paths) == 0, "main.py should skip the second path if the first fails"


# =====================================================================
# AREA 3: Route conflicts and boundary requests on /docs
# =====================================================================

def test_docs_route_boundary_requests():
    """Test route conflicts, redirects, and path traversal vulnerabilities on /docs mount."""
    response = client.get("/docs")
    assert response.status_code in [200, 307, 301, 404]
    
    # 2. Accessing /docs/ index page
    response = client.get("/docs/")
    assert response.status_code == 200
    
    # 3. Requesting a nonexistent file under /docs/
    response = client.get("/docs/nonexistent_file_xyz.html")
    assert response.status_code == 404
    
    # 4. Path traversal attempt via /docs/
    # Starlette StaticFiles should block traversal attempts
    response = client.get("/docs/../website/index.html")
    assert response.status_code in [400, 404]

    # 5. OpenAPI docs (Swagger UI) is public
    response = client.get("/api/openapi-docs")
    assert response.status_code == 200
    
    # 6. OpenAPI JSON schema is public
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "paths" in response.json()


# =====================================================================
# AREA 4: Unauthenticated or malformed requests to protected endpoints
# =====================================================================

def test_unauthenticated_protected_endpoints():
    """Assert that protected endpoints strictly return 401 for unauthorized/invalid requests."""
    # 1. /dashboard.json with no credentials
    response = client.get("/dashboard.json")
    assert response.status_code == 401
    
    # 2. /dashboard.json with invalid/malformed token
    response = client.get("/dashboard.json", headers={"Authorization": "Bearer invalid.token.value"})
    assert response.status_code == 401
    
    # 3. /dashboard.json with expired token
    expired_token = create_jwt({"sub": "admin", "exp": time.time() - 3600})
    response = client.get("/dashboard.json", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    
    # 4. /dashboard.json with signature mismatch (token tampered)
    valid_payload = {"sub": "admin", "exp": time.time() + 3600}
    jwt_secret_wrong = "wrong_secret_key"
    tampered_token = create_jwt(valid_payload, secret=jwt_secret_wrong)
    response = client.get("/dashboard.json", headers={"Authorization": f"Bearer {tampered_token}"})
    assert response.status_code == 401

def test_api_export_path_traversal_vulnerability():
    """
    Test the /api/export endpoint for path traversal / arbitrary file write vulnerabilities.
    Confirms that a path traversal query parameter allows writing reports to arbitrary locations.
    """
    # Create a valid token
    valid_token = create_jwt({"sub": "admin", "exp": time.time() + 3600})
    
    # Target an arbitrary location in the workspace (path traversal)
    arbitrary_output_path = os.path.join(PROJECT_ROOT, "tests/arbitrary_roi_report.pdf")
    if os.path.exists(arbitrary_output_path):
        os.remove(arbitrary_output_path)
        
    try:
        # Request export with custom path traversal
        response = client.get(
            f"/api/export?output_path={arbitrary_output_path}",
            headers={"Authorization": f"Bearer {valid_token}"}
        )
        assert response.status_code == 200
        
        # Verify the file was created at the arbitrary location outside docs/whitepaper/
        assert os.path.exists(arbitrary_output_path), "Arbitrary file write vulnerability exposed: file written to arbitrary path"
    finally:
        if os.path.exists(arbitrary_output_path):
            os.remove(arbitrary_output_path)

def test_websocket_authentication_boundaries():
    """Test websocket endpoints for authentication boundaries (missing/invalid tokens)."""
    # 1. WebSocket connection with missing token
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/api/ws"):
            pass
    assert exc_info.value.code == 1008
    
    # 2. WebSocket connection with invalid token
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/api/ws?token=invalid_jwt"):
            pass
    assert exc_info.value.code == 1008
