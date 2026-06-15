import os
import sys
import json
import urllib.request
import urllib.error
import pytest
from unittest.mock import patch, mock_open, MagicMock

# Add project root and scripts directory to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))

from gen_pitch_deck import PitchDeck

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

def test_tier1_live_backend_success():
    """
    Tier 1: FastAPI backend is running and returns valid JSON.
    The script should successfully fetch live metrics and return early.
    """
    mock_api_data = {
        "threats_preempted": 99,
        "nodes_saved": 88,
        "cost_avoided": "$5.5M",
        "hours_saved": 110,
        "blast_radius_score": 0.45,
        "threshold": 0.2,
        "mode": "Live Test Mode"
    }
    
    # Mock urlopen to return a successful response with mock_api_data
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps(mock_api_data).encode("utf-8")
    mock_response.__enter__.return_value = mock_response  # Ensure 'with urlopen() as response' works correctly
    
    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        pdf = PitchDeck()
        
        # Verify Tier 1 was used
        assert pdf.telemetry_source == "Live FastAPI Backend (http://localhost:8000/dashboard.json)"
        assert pdf.threats_preempted == "99"
        assert pdf.nodes_saved == "88"
        assert pdf.cost_avoided == "$5.5M"
        assert pdf.hours_saved == "110"
        mock_urlopen.assert_called_once()

def test_tier2_backend_offline_cache_valid():
    """
    Tier 2: FastAPI backend is offline, but website/dashboard.json exists and is valid.
    The script should fall back to reading website/dashboard.json.
    """
    mock_file_data = {
        "threats_preempted": 77,
        "nodes_saved": 66,
        "cost_avoided": "$4.4M",
        "hours_saved": 80,
        "blast_radius_score": 0.35,
        "threshold": 0.1,
        "mode": "Cache Test Mode"
    }
    
    # Mock urlopen to raise a ConnectionRefused error
    # Mock open to return valid JSON
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")), \
         patch("builtins.open", mock_open(read_data=json.dumps(mock_file_data))):
        
        pdf = PitchDeck()
        
        # Verify Tier 2 fallback was used
        assert "Static Cache File" in pdf.telemetry_source
        assert pdf.threats_preempted == "77"
        assert pdf.nodes_saved == "66"
        assert pdf.cost_avoided == "$4.4M"
        assert pdf.hours_saved == "80"

def test_tier3_backend_offline_cache_missing():
    """
    Tier 3: FastAPI backend is offline and website/dashboard.json is missing.
    The script should fall back to Hardcoded Defaults.
    """
    # Mock urlopen to raise URLError
    # Mock open to raise FileNotFoundError
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")), \
         patch("builtins.open", side_effect=FileNotFoundError("dashboard.json not found")):
        
        pdf = PitchDeck()
        
        # Verify Tier 3 fallback was used (Hardcoded Defaults)
        assert "Hardcoded Defaults" in pdf.telemetry_source
        assert pdf.threats_preempted == "1"
        assert pdf.nodes_saved == "10"
        assert pdf.cost_avoided == "$8.9M"
        assert pdf.hours_saved == "140"

def test_tier3_backend_offline_cache_malformed():
    """
    Tier 3: FastAPI backend is offline and website/dashboard.json contains malformed JSON data.
    The script should fall back to Hardcoded Defaults.
    """
    # Mock urlopen to raise URLError
    # Mock open to return invalid JSON data (which raises json.JSONDecodeError)
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")), \
         patch("builtins.open", mock_open(read_data="{invalid_json_format:")):
        
        pdf = PitchDeck()
        
        # Verify Tier 3 fallback was used (Hardcoded Defaults)
        assert "Hardcoded Defaults" in pdf.telemetry_source
        assert pdf.threats_preempted == "1"
        assert pdf.nodes_saved == "10"
        assert pdf.cost_avoided == "$8.9M"
        assert pdf.hours_saved == "140"


def test_stix_scanning_0_indicators():
    """Verify scanning with 0 STIX indicators (empty directory)."""
    with patch("glob.glob", return_value=[]), \
         patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Refused")), \
         patch("builtins.open", side_effect=FileNotFoundError):
        
        pdf = PitchDeck()
        assert pdf.text_file_count == 0
        assert pdf.bin_file_count == 0
        assert pdf.img_file_count == 0
        assert pdf.total_stix_count == 0
        # Check fallbacks
        assert pdf.threat_names == ["Cobalt Strike", "Mimikatz", "TrickBot", "EKANS", "HDoor"]
        assert pdf.unauthorized_software_samples == ["TrickBot", "Mimikatz", "Cobalt Strike"]


def test_stix_scanning_5_indicators():
    """Verify scanning with exactly 5 STIX indicators."""
    text_files = [f"/mock/data/threat_intel/stix_unauthorized_software_{i}.txt" for i in range(5)]
    bin_files = ["/mock/data/threat_intel/threat_payload.bin"]
    png_files = ["/mock/data/threat_intel/threat_diagram.png"]
    
    def mock_glob_side_effect(pattern):
        if "stix_*.txt" in pattern or "*.txt" in pattern:
            return text_files
        elif "*.bin" in pattern:
            return bin_files
        elif "*.png" in pattern:
            return png_files
        elif "*.jpg" in pattern:
            return []
        return []

    mock_contents = {
        text_files[0]: "STIX Indicator: Mimikatz\nTTP: Unauthorized Software\n",
        text_files[1]: "STIX Indicator: Cobalt Strike\nTTP: Unauthorized Software\n",
        text_files[2]: "STIX Indicator: PhishingEmail\nTTP: Phishing\n",
        text_files[3]: "STIX Indicator: WannaCry\nTTP: Unauthorized Software\n",
        text_files[4]: "STIX Indicator: SQLInjection\nTTP: Vulnerability\n"
    }

    def mock_open_side_effect(filepath, *args, **kwargs):
        path_str = str(filepath)
        if path_str in mock_contents:
            return mock_open(read_data=mock_contents[path_str])(filepath, *args, **kwargs)
        raise FileNotFoundError(f"Mock open: file {filepath} not found")

    with patch("glob.glob", side_effect=mock_glob_side_effect), \
         patch("builtins.open", side_effect=mock_open_side_effect), \
         patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Refused")):
        
        pdf = PitchDeck()
        assert pdf.text_file_count == 5
        assert pdf.bin_file_count == 1
        assert pdf.img_file_count == 1
        assert pdf.total_stix_count == 7
        
        assert "WannaCry" in pdf.unauthorized_software_samples
        assert "Mimikatz" in pdf.unauthorized_software_samples
        assert "Cobalt Strike" in pdf.unauthorized_software_samples
        assert len(pdf.unauthorized_software_samples) == 3
        
        assert "PhishingEmail (Phishing)" in pdf.threat_vectors
        assert "SQLInjection (Vulnerability)" in pdf.threat_vectors
        assert len(pdf.threat_vectors) == 2


def test_stix_scanning_20_indicators():
    """Verify scanning with 20 STIX indicators."""
    text_files = [f"/mock/data/threat_intel/stix_unauthorized_software_{i}.txt" for i in range(20)]
    bin_files = []
    png_files = []
    
    def mock_glob_side_effect(pattern):
        if "stix_*.txt" in pattern or "*.txt" in pattern:
            return text_files
        return []

    mock_contents = {}
    for i in range(15):
        mock_contents[text_files[i]] = f"STIX Indicator: Unauthorized Software_{i}\nTTP: Unauthorized Software\n"
    for i in range(15, 20):
        mock_contents[text_files[i]] = f"STIX Indicator: Vector_{i}\nTTP: Exploitation\n"

    def mock_open_side_effect(filepath, *args, **kwargs):
        path_str = str(filepath)
        if path_str in mock_contents:
            return mock_open(read_data=mock_contents[path_str])(filepath, *args, **kwargs)
        raise FileNotFoundError(f"Mock open: file {filepath} not found")

    with patch("glob.glob", side_effect=mock_glob_side_effect), \
         patch("builtins.open", side_effect=mock_open_side_effect), \
         patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Refused")):
        
        pdf = PitchDeck()
        assert pdf.text_file_count == 20
        assert pdf.total_stix_count == 20
        
        assert len(pdf.unauthorized_software_samples) == 15
        assert pdf.unauthorized_software_samples[0] == "Unauthorized Software_0"
        
        assert len(pdf.threat_vectors) == 5
        assert pdf.threat_vectors[0] == "Vector_15 (Exploitation)"


def test_stix_scanning_robustness_on_failure():
    """Verify scanning handles corrupt files (IOError on one file) gracefully."""
    text_files = [
        "/mock/data/threat_intel/stix_unauthorized_software_ok1.txt",
        "/mock/data/threat_intel/stix_unauthorized_software_bad.txt",
        "/mock/data/threat_intel/stix_unauthorized_software_ok2.txt"
    ]
    
    def mock_glob_side_effect(pattern):
        if "stix_*.txt" in pattern or "*.txt" in pattern:
            return text_files
        return []

    mock_contents = {
        text_files[0]: "STIX Indicator: GoodUnauthorized Software1\nTTP: Unauthorized Software\n",
        text_files[2]: "STIX Indicator: GoodUnauthorized Software2\nTTP: Unauthorized Software\n"
    }

    def mock_open_side_effect(filepath, *args, **kwargs):
        path_str = str(filepath)
        if path_str == text_files[1]:
            raise IOError("Simulated read error on bad file")
        if path_str in mock_contents:
            return mock_open(read_data=mock_contents[path_str])(filepath, *args, **kwargs)
        raise FileNotFoundError(f"Mock open: file {filepath} not found")

    with patch("glob.glob", side_effect=mock_glob_side_effect), \
         patch("builtins.open", side_effect=mock_open_side_effect), \
         patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Refused")):
        
        pdf = PitchDeck()
        assert pdf.text_file_count == 3
        assert "GoodUnauthorized Software1" in pdf.unauthorized_software_samples
        assert "GoodUnauthorized Software2" in pdf.unauthorized_software_samples
        assert len(pdf.unauthorized_software_samples) == 2

