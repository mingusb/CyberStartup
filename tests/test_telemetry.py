import torch
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from telemetry.linux_pmu import LiveTelemetry

from unittest.mock import patch, MagicMock
import ctypes

@patch('os.path.exists', return_value=True)
@patch('os.stat')
@patch('ctypes.CDLL')
def test_swarm_consensus_network_topology_hil(mock_cdll, mock_stat, mock_exists):
    """
    HIL environment test for eBPF map reading logic.
    """
    mock_stat.return_value.st_uid = 0
    mock_stat.return_value.st_mode = 0o600
    mock_libc = MagicMock()
    mock_libc.bpf_obj_get.return_value = 1
    
    def syscall_mock(sys_num, cmd, attr_ptr, size):
        if cmd == 4:
            if not hasattr(syscall_mock, 'count'):
                syscall_mock.count = 0
            if syscall_mock.count < 2:
                syscall_mock.count += 1
                return 0
            return -1
        elif cmd == 1:
            return 0
        return -1
    
    mock_libc.syscall.side_effect = syscall_mock
    mock_cdll.return_value = mock_libc
    
    telemetry = LiveTelemetry(num_assets=5)
    edge_index = telemetry.read_network_topology()
    
    assert isinstance(edge_index, torch.Tensor)
    assert edge_index.shape[0] == 2

@patch('os.path.exists', return_value=True)
@patch('ctypes.CDLL')
def test_swarm_consensus_read_cpu_stats_hil(mock_cdll, mock_exists):
    """
    Ensures that PMU telemetry logic correctly processes real hardware ring buffer data natively.
    """
    mock_libc = MagicMock()
    mock_libc.bpf_obj_get.return_value = 1
    mock_libc.syscall.return_value = 0
    mock_cdll.return_value = mock_libc

    telemetry = LiveTelemetry(num_assets=5)
    features = telemetry.read_cpu_stats()

    assert isinstance(features, torch.Tensor)
    assert features.shape == (5, 128)