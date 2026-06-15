import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from orchestration.roi_dashboard import ROIDashboard

def test_roi_mathematical_boundaries():
    # Test boundary where no nodes are saved
    metrics_none = ROIDashboard.calculate_roi(num_assets=10, compromised_nodes=[])
    assert metrics_none["nodes_saved"] == 0
    assert metrics_none["cost_avoided"] == "$0.0M"
    assert metrics_none["hours_saved"] == 0

    # Test boundary where 1 node is saved
    metrics_one = ROIDashboard.calculate_roi(num_assets=10, compromised_nodes=[1])
    assert metrics_one["nodes_saved"] == 1
    assert metrics_one["cost_avoided"] == "$0.4M"
    assert metrics_one["hours_saved"] == 14

    # Test mathematical mapping of 10 nodes for $4.6M claim
    brs_mock = [0.5143] * 10
    metrics_ten = ROIDashboard.calculate_roi(num_assets=10, compromised_nodes=[1,2,3,4,5,6,7,8,9,10], blast_radius_scores=brs_mock)
    assert metrics_ten["nodes_saved"] == 10
    assert metrics_ten["cost_avoided"] == "$4.6M"

def test_executive_roi_output(capsys, monkeypatch):
    # This is a legacy integration test but updated to reflect the dynamic math instead of mock strings.
    from main import main

    # Mock sys.argv to run main() correctly without arguments
    monkeypatch.setattr(sys, 'argv', ['main.py'])

    # Mock glob to return 5 dummy files so it bypasses the sys.exit(1) and matches dag edges
    import glob
    monkeypatch.setattr(glob, 'glob', lambda p: ['dummy1.txt', 'dummy2.txt', 'dummy3.txt', 'dummy4.txt', 'dummy5.txt'] if 'txt' in p else ['dummy.bin'])

    from orchestration.dynamic_compiler import PolymorphicCompiler

    # Mock CT_GODE call to always return a high fragility score
    from models.ct_gode import CT_GODE
    import torch
    monkeypatch.setattr(CT_GODE, '__call__', lambda self, h0, edge_index, threat_vector, t: torch.ones(10) * 0.99)

    # Mock LiveTelemetry PMU reading to avoid BCC module error
    from telemetry.linux_pmu import LiveTelemetry
    monkeypatch.setattr(LiveTelemetry, 'read_cpu_stats', lambda self: torch.zeros((10, 128)))
    monkeypatch.setattr(LiveTelemetry, 'read_network_topology', lambda self: torch.tensor([[0, 1], [1, 2]], dtype=torch.long))

    import ctypes
    from unittest.mock import MagicMock
    mock_libc = MagicMock()
    mock_libc.bpf_obj_get.return_value = 42
    original_cdll = ctypes.CDLL
    def custom_cdll(path, *args, **kwargs):
        if path is None:
            return mock_libc
        return original_cdll(path, *args, **kwargs)
    monkeypatch.setattr(ctypes, 'CDLL', custom_cdll)

    # Run main which should print the dashboard
    try:        main()
    except SystemExit:
        pass # In case main calls sys.exit
        
    captured = capsys.readouterr()
    output = captured.out
    
    # Assert the dynamic output string is present
    assert "Threats Preempted" in output
    assert "EXECUTION SUMMARY" in output
