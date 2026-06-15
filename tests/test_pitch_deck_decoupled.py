import os
import sys
import json
import tempfile
import urllib.request
import pytest
from unittest.mock import patch, MagicMock

# Add project root and scripts directory to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))

from gen_pitch_deck import PitchDeck

def test_decoupled_mock_log_with_no_sudo():
    """Verify that when CYBERSTARTUP_NO_SUDO is set, subprocess is bypassed and mock log is used."""
    with patch.dict(os.environ, {"CYBERSTARTUP_NO_SUDO": "1"}), \
         patch("subprocess.run") as mock_run, \
         patch("glob.glob", return_value=[]):
         
        pdf = PitchDeck()
        
        # Verify subprocess was NOT run
        mock_run.assert_not_called()
        
        # Verify cli_output contains the expected mock log headers
        assert "CYBERSTARTUP: Hardware-Enforced Architecture for Preemptive Containment Redirection System with DPU Offloading" in pdf.cli_output
        assert "[!] ENTERPRISE MODE ACTIVATED: Hardware-Enforced TEE Engine Online" in pdf.cli_output
        assert "CYBERSTARTUP Execution Terminated Successfully." in pdf.cli_output

def test_decoupled_mock_log_with_build_step():
    """Verify that when CYBERSTARTUP_BUILD_STEP is set, subprocess is bypassed and mock log is used."""
    with patch.dict(os.environ, {"CYBERSTARTUP_BUILD_STEP": "1"}), \
         patch("subprocess.run") as mock_run, \
         patch("glob.glob", return_value=[]):
         
        pdf = PitchDeck()
        
        # Verify subprocess was NOT run
        mock_run.assert_not_called()
        
        # Verify cli_output contains the expected mock log headers
        assert "CYBERSTARTUP: Hardware-Enforced Architecture for Preemptive Containment Redirection System with DPU Offloading" in pdf.cli_output

def test_decoupled_mock_log_with_mock_telemetry():
    """Verify that when CYBERSTARTUP_MOCK_TELEMETRY is set, subprocess is bypassed and mock log is used."""
    with patch.dict(os.environ, {"CYBERSTARTUP_MOCK_TELEMETRY": "1"}), \
         patch("subprocess.run") as mock_run, \
         patch("glob.glob", return_value=[]):
         
        pdf = PitchDeck()
        
        # Verify subprocess was NOT run
        mock_run.assert_not_called()
        
        # Verify cli_output contains the expected mock log headers
        assert "CYBERSTARTUP: Hardware-Enforced Architecture for Preemptive Containment Redirection System with DPU Offloading" in pdf.cli_output

def test_decoupled_bypasses_live_fetch():
    """Verify that when decoupled mode is active, live urllib request is bypassed and falls back to static cache or default."""
    cache_data = {
        "threats_preempted": 42,
        "nodes_saved": 42,
        "cost_avoided": "$4.2M",
        "hours_saved": 42,
        "blast_radius_score": 0.42,
        "threshold": 0.42,
        "mode": "Decoupled Cache Mode"
    }
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_cache:
        json.dump(cache_data, temp_cache)
        temp_cache_path = temp_cache.name
        
    try:
        with patch.dict(os.environ, {
            "CYBERSTARTUP_NO_SUDO": "1",
            "DASHBOARD_JSON_PATH": temp_cache_path
        }), \
        patch("urllib.request.urlopen") as mock_urlopen, \
        patch("subprocess.run"), \
        patch("glob.glob", return_value=[]):
            
            pdf = PitchDeck()
            
            # Verify urlopen was NOT called to fetch the API (preventing connection timeout)
            mock_urlopen.assert_not_called()
            
            # Verify fallback to cache file succeeded
            assert "Static Cache File" in pdf.telemetry_source
            assert pdf.threats_preempted == "42"
            assert pdf.nodes_saved == "42"
            assert pdf.cost_avoided == "$4.2M"
            assert pdf.hours_saved == "42"
    finally:
        if os.path.exists(temp_cache_path):
            os.remove(temp_cache_path)
