import os
import sys
import json
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest
from unittest.mock import patch, MagicMock

# Add project root and scripts directory to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))

from gen_pitch_deck import PitchDeck

class MockDashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/dashboard.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = {
                "threats_preempted": 99,
                "nodes_saved": 88,
                "cost_avoided": "$5.5M",
                "hours_saved": 110,
                "blast_radius_score": 0.45,
                "threshold": 0.2,
                "mode": "Live Test Mode"
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Suppress server logs to keep console output clean
        pass

@pytest.fixture(autouse=True)
def mock_initialization():
    """Mock the subprocess and glob scanning during initialization to avoid environment dependencies."""
    env_vars = ["CYBERSTARTUP_NO_SUDO", "CYBERSTARTUP_BUILD_STEP", "CYBERSTARTUP_MOCK_TELEMETRY"]
    old_vals = {v: os.environ.get(v) for v in env_vars}
    for v in env_vars:
        if v in os.environ:
            del os.environ[v]
    try:
        with patch("subprocess.run") as mock_sub, patch("glob.glob") as mock_glob:
            mock_sub.return_value = MagicMock(returncode=0, stdout="Mock CLI execution log output")
            mock_glob.return_value = []
            yield
    finally:
        for v in env_vars:
            if old_vals[v] is not None:
                os.environ[v] = old_vals[v]

def test_integration_tier1_live_backend():
    """Verify live API fetch when server is running on a dynamic port without mocking urllib."""
    server = None
    server_thread = None
    try:
        server = HTTPServer(("127.0.0.1", 0), MockDashboardHandler)
        port = server.server_address[1]
        mock_api_url = f"http://127.0.0.1:{port}/dashboard.json"
        
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        # Instantiate PitchDeck and verify it accesses the live local server
        with patch.dict(os.environ, {"CYBERSTARTUP_API_URL": mock_api_url}):
            pdf = PitchDeck()
        assert pdf.telemetry_source == f"Live FastAPI Backend ({mock_api_url})"
        assert pdf.threats_preempted == "99"
        assert pdf.nodes_saved == "88"
        assert pdf.cost_avoided == "$5.5M"
        assert pdf.hours_saved == "110"
        
    finally:
        if server:
            server.shutdown()
            server.server_close()
        if server_thread:
            server_thread.join(timeout=1.0)

def test_integration_tier2_backend_offline_cache_valid():
    """Verify static cache fallback when backend is offline and dashboard.json path is valid."""
    # Ensure no server is running on port 8000
    # Use a temporary file for DASHBOARD_JSON_PATH to avoid mutating website/dashboard.json
    cache_data = {
        "threats_preempted": 77,
        "nodes_saved": 66,
        "cost_avoided": "$4.4M",
        "hours_saved": 80,
        "blast_radius_score": 0.35,
        "threshold": 0.1,
        "mode": "Cache Integration Test"
    }
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_cache:
        json.dump(cache_data, temp_cache)
        temp_cache_path = temp_cache.name
        
    try:
        # Run with DASHBOARD_JSON_PATH pointing to temp cache file
        with patch.dict(os.environ, {"DASHBOARD_JSON_PATH": temp_cache_path}):
            pdf = PitchDeck()
            assert "Static Cache File" in pdf.telemetry_source
            assert temp_cache_path in pdf.telemetry_source
            assert pdf.threats_preempted == "77"
            assert pdf.nodes_saved == "66"
            assert pdf.cost_avoided == "$4.4M"
            assert pdf.hours_saved == "80"
    finally:
        if os.path.exists(temp_cache_path):
            os.remove(temp_cache_path)

def test_integration_tier3_backend_offline_cache_missing():
    """Verify default fallback when backend is offline and cache file is missing."""
    non_existent_path = "/tmp/non_existent_dashboard_file_12345.json"
    with patch.dict(os.environ, {"DASHBOARD_JSON_PATH": non_existent_path}):
        pdf = PitchDeck()
        assert "Hardcoded Defaults" in pdf.telemetry_source
        assert pdf.threats_preempted == "1"
        assert pdf.nodes_saved == "10"
        assert pdf.cost_avoided == "$8.9M"
        assert pdf.hours_saved == "140"

def test_integration_tier3_backend_offline_cache_malformed():
    """Verify default fallback when backend is offline and cache file has malformed JSON."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_cache:
        temp_cache.write("{invalid_json_data:")
        temp_cache_path = temp_cache.name
        
    try:
        with patch.dict(os.environ, {"DASHBOARD_JSON_PATH": temp_cache_path}):
            pdf = PitchDeck()
            assert "Hardcoded Defaults" in pdf.telemetry_source
            assert pdf.threats_preempted == "1"
            assert pdf.nodes_saved == "10"
            assert pdf.cost_avoided == "$8.9M"
            assert pdf.hours_saved == "140"
    finally:
        if os.path.exists(temp_cache_path):
            os.remove(temp_cache_path)
