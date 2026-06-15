import os
import sys
import json
import time
import pytest
import ctypes
from unittest.mock import patch, MagicMock

# Ensure project directories are in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/cyberstartup')))

from fastapi.testclient import TestClient
from api.production_api import app, verify_jwt, create_jwt, execute_telemetry_pipeline
from telemetry.linux_pmu import LiveTelemetry
from orchestration.bpf_injector import ZeroTrustController, P4AsicController
import main

# Setup test client
client = TestClient(app)

# =====================================================================
# 1. INVALID OR MALFORMED PAYLOADS TO API ROUTES
# =====================================================================

def test_login_invalid_payloads():
    """
    Test /api/login with invalid and malformed payloads, wrong types, and large strings.
    """
    # Empty body
    response = client.post("/api/login", json={})
    assert response.status_code == 422  # Validation Error

    # Malformed JSON
    response = client.post("/api/login", content="{'invalid': }", headers={"Content-Type": "application/json"})
    assert response.status_code in [400, 422]

    # Wrong field types
    response = client.post("/api/login", json={"username": 12345, "password": ["some_password"]})
    assert response.status_code == 422

    # Wrong credentials (SQL injection / XSS payload style)
    response = client.post("/api/login", json={"username": "' OR '1'='1", "password": "<script>alert(1)</script>"})
    assert response.status_code == 401

    # Buffer overflow/Resource exhaustion payload (extremely large strings)
    large_username = "A" * 50000
    large_password = "B" * 50000
    response = client.post("/api/login", json={"username": large_username, "password": large_password})
    assert response.status_code == 401


def test_token_invalid_payloads():
    """
    Test /api/token with missing, invalid, or malformed body parameters.
    """
    # Missing fields in form/json
    response = client.post("/api/token", json={})
    assert response.status_code == 401  # Raises 401 on missing or incorrect credentials

    # Wrong content type
    response = client.post("/api/token", content="invalid_content", headers={"Content-Type": "text/plain"})
    assert response.status_code == 401


# =====================================================================
# 2. UNAUTHENTICATED OR MALFORMED REQUESTS TO PROTECTED ENDPOINTS
# =====================================================================

def test_unauthenticated_protected_endpoints():
    """
    Verify protected endpoints block unauthenticated or malformed requests.
    """
    # No Auth header on /dashboard.json
    response = client.get("/dashboard.json")
    assert response.status_code == 401

    # Invalid Auth header structure
    response = client.get("/dashboard.json", headers={"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="})
    assert response.status_code == 401

    # Bearer header without token
    response = client.get("/dashboard.json", headers={"Authorization": "Bearer "})
    assert response.status_code == 401

    # Missing token parameter on /api/ws
    with pytest.raises(Exception):
        with client.websocket_connect("/api/ws") as websocket:
            pass


def test_malformed_jwt_tokens():
    """
    Verify verify_jwt handles invalid, malformed, expired, and type-mismatched tokens.
    """
    # Token with invalid parts (too few dots)
    response = client.get("/dashboard.json", headers={"Authorization": "Bearer invalidtoken"})
    assert response.status_code == 401

    # Token with invalid signature
    malformed_token = create_jwt({"sub": "admin", "exp": time.time() + 3600}, secret="wrongsecret")
    response = client.get("/dashboard.json", headers={"Authorization": f"Bearer {malformed_token}"})
    assert response.status_code == 401

    # Expired token
    expired_token = create_jwt({"sub": "admin", "exp": time.time() - 3600})
    response = client.get("/dashboard.json", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401

    # Expired token with invalid exp type (string exp instead of float/int)
    invalid_exp_token = create_jwt({"sub": "admin", "exp": "invalid_date_type"})
    response = client.get("/dashboard.json", headers={"Authorization": f"Bearer {invalid_exp_token}"})
    assert response.status_code == 401


# =====================================================================
# 3. WRITE FAILURES OR PERMISSION ERRORS ON TELEMETRY PATHS
# =====================================================================

@patch('glob.glob')
@patch('telemetry.linux_pmu.LiveTelemetry.read_cpu_stats')
@patch('telemetry.linux_pmu.LiveTelemetry.read_network_topology')
def test_production_api_telemetry_write_failure(mock_net, mock_cpu, mock_glob):
    """
    Verify write failures/permission errors on dashboard.json do not crash the API endpoint.
    """
    import torch
    mock_cpu.return_value = torch.zeros((10, 128))
    mock_net.return_value = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    mock_glob.side_effect = lambda p: ['dummy1.txt', 'dummy2.txt', 'dummy3.txt', 'dummy4.txt', 'dummy5.txt'] if 'txt' in p else ['dummy.bin']

    original_open = open
    def mock_open(file, mode='r', *args, **kwargs):
        if 'dashboard.json' in str(file):
            raise PermissionError("Access Denied")
        return original_open(file, mode, *args, **kwargs)

    with patch('builtins.open', side_effect=mock_open):
        token = create_jwt({"sub": "admin", "exp": time.time() + 3600})
        # Clear cache to force dynamic write path execution
        import api.production_api
        api.production_api._cached_dashboard_data = None
        
        response = client.get("/dashboard.json", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert "threats_preempted" in response.json()


@patch('glob.glob')
@patch('telemetry.linux_pmu.LiveTelemetry.read_cpu_stats')
@patch('telemetry.linux_pmu.LiveTelemetry.read_network_topology')
@patch('models.ct_gode.CT_GODE.__call__')
def test_main_cli_write_failure(mock_ctgode, mock_net, mock_cpu, mock_glob, monkeypatch):
    """
    Verify write failures/permission errors do not crash main CLI execution.
    """
    import torch
    # Mock CLI arguments
    monkeypatch.setattr(sys, 'argv', ['main.py'])
    
    # Mock threat intel path resolving to return 5 files to avoid GIN IndexError
    mock_glob.side_effect = lambda p: ['dummy1.txt', 'dummy2.txt', 'dummy3.txt', 'dummy4.txt', 'dummy5.txt'] if 'txt' in p else ['dummy.bin']

    # Mock dynamic telemetry values
    mock_cpu.return_value = torch.zeros((10, 128))
    mock_net.return_value = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    mock_ctgode.return_value = torch.ones(10) * 0.9  # Exceed threshold

    original_open = open
    def mock_open_fn(file, mode='r', *args, **kwargs):
        if 'dashboard.json' in str(file):
            raise PermissionError("Access Denied")
        return original_open(file, mode, *args, **kwargs)

    # Mock other compilation or execution side effects to prevent errors
    with patch('builtins.open', side_effect=mock_open_fn), \
         patch('orchestration.dynamic_compiler.PolymorphicCompiler.compile_ebpf_shaper', return_value=True), \
         patch('orchestration.bpf_injector.ZeroTrustController.inject_compromised_ip', return_value=True), \
         patch('orchestration.bpf_injector.P4AsicController.inject_p4_routing', return_value={}):
        
        # Verify run completes without raising permission error (i.e. failsafe output check)
        main.main()


# =====================================================================
# 4. ROUTE CONFLICTS AND BOUNDARY REQUESTS ON /DOCS
# =====================================================================

def test_route_conflicts_and_boundary_docs():
    """
    Test for boundary requests, trailing slash behavior, and directory traversal on /docs mount.
    """
    # Trailing slash vs no trailing slash
    response_no_slash = client.get("/docs")
    assert response_no_slash.status_code in [200, 307, 301, 404]

    response_slash = client.get("/docs/")
    assert response_slash.status_code == 200

    # Specific subfile
    response_index = client.get("/docs/index.html")
    assert response_index.status_code == 200

    # Nonexistent file inside docs
    response_missing = client.get("/docs/nonexistent_file_xyz.html")
    assert response_missing.status_code == 404

    # Directory traversal attempt
    response_traversal = client.get("/docs/../website/index.html")
    assert response_traversal.status_code in [404, 400, 200]  # Allow 200 if client normalizes to /website/index.html

    # Malformed URL path parameter to mount
    response_malformed = client.get("/docs/%00")
    assert response_malformed.status_code in [404, 400]

    # OpenAPI docs endpoint validation (verify it works and does not conflict)
    response_openapi = client.get("/api/openapi-docs")
    assert response_openapi.status_code == 200
    assert "text/html" in response_openapi.headers["content-type"]


# =====================================================================
# 5. HARDWARE MOCK VERIFICATION VS LIVE HARDWARE EXECUTION
# =====================================================================

def test_hardware_pmu_insecure_permissions(monkeypatch):
    """
    Verify LiveTelemetry read_network_topology raises PermissionError if eBPF map exists but has insecure permissions.
    """
    # Mock os.path.exists to return True (simulating map exists)
    monkeypatch.setattr(os.path, 'exists', lambda p: True if 'cyberstartup_tcp_map' in str(p) else False)
    
    # Mock os.stat to return insecure permissions (UID != 0 or mode has permissions for group/others)
    mock_stat = MagicMock()
    mock_stat.st_uid = 1000  # Non-root user owns the map file
    mock_stat.st_mode = 0o777 # World-writable/readable
    monkeypatch.setattr(os, 'stat', lambda p: mock_stat)

    telemetry = LiveTelemetry(num_assets=5)
    with pytest.raises(RuntimeError, match="Insecure permissions on"):
        telemetry.read_network_topology()


def test_hardware_pmu_missing_strict_mode(monkeypatch):
    """
    Verify read_cpu_stats raises RuntimeError in Strict Hardware Mode if map is missing.
    """
    # Mock map path not existing
    monkeypatch.setattr(os.path, 'exists', lambda p: False)

    telemetry = LiveTelemetry(num_assets=5)
    with pytest.raises(RuntimeError, match="Strict Hardware Mode: Failed to read PMU stats"):
        telemetry.read_cpu_stats()


def test_sgx_attestation_enclave_missing(monkeypatch):
    """
    Verify ZeroTrustController fails closed and raises RuntimeError when SGX CDLL is completely missing.
    """
    # Mock CDLL loading to raise OSError
    with patch('ctypes.CDLL', side_effect=OSError("Enclave library sgx_enclave.so not found")):
        with pytest.raises(RuntimeError, match="Hardware Attestation Failed: sgx_enclave.so missing"):
            ZeroTrustController()


def test_sgx_attestation_signature_invalid(monkeypatch):
    """
    Verify ZeroTrustController fails closed and raises RuntimeError when SGX attestation returns 0 (invalid).
    """
    # Mock CDLL load, but attest_enclave returns 0
    mock_sgx = MagicMock()
    mock_sgx.attest_enclave.return_value = 0 # Invalid signature
    
    with patch('ctypes.CDLL', return_value=mock_sgx):
        with pytest.raises(RuntimeError, match="Hardware Attestation Failed: sgx_enclave.so missing or invalid. Failsafe activated"):
            ZeroTrustController()
