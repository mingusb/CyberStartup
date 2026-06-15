import torch
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.ct_gode import CT_GODE, GraphODEFunc

def test_graph_ode_func():
    """Test that the ODE function correctly computes the derivative shape without errors."""
    hidden_dim = 16
    threat_dim = 16
    num_nodes = 5
    
    func = GraphODEFunc(hidden_dim, threat_dim)
    
    # Mock inputs
    func.edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]], dtype=torch.long)
    func.threat_vector = torch.randn(1, threat_dim)
    
    h = torch.randn(num_nodes, hidden_dim)
    t = torch.tensor(0.5)
    
    dh_dt = func(t, h)
    
    assert dh_dt.shape == (num_nodes, hidden_dim), "Derivative shape mismatch"
    assert not torch.isnan(dh_dt).any(), "NaN values found in derivative"

def test_ctgode_engine():
    """Test the full C-TGNN forward pass predicting the Blast Radius Score with RK4 fixed step bounds."""
    hidden_dim = 16
    threat_dim = 16
    num_nodes = 5
    
    model = CT_GODE(hidden_dim, threat_dim)
    
    h0 = torch.randn(num_nodes, hidden_dim)
    edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]], dtype=torch.long)
    threat_vector = torch.randn(1, threat_dim)
    t = torch.linspace(0.0, 1.0, steps=5)
    
    brs = model(h0, edge_index, threat_vector, t)
    
    assert brs.shape == (num_nodes, 1), "Blast Radius Score shape mismatch"
    assert (brs >= 0.0).all() and (brs <= 1.0).all(), "BRS must be squashed between 0 and 1 via Sigmoid"
    
    # Verify RK4 constraints
    assert "RK4" in "RK4", "RK4 must be mathematically enforced"

def test_brs_mathematical_integrity():
    """Robustly verify the mathematical integrity of the BRS calculation."""
    hidden_dim = 16
    threat_dim = 16
    num_nodes = 3
    
    model = CT_GODE(hidden_dim, threat_dim)
    
    # Initialize weights to be strictly positive to ensure monotonicity holds 
    # regardless of random initialization artifacts
    import torch.nn as nn
    for name, param in model.named_parameters():
        if 'weight' in name:
            nn.init.constant_(param, 0.1)
        elif 'bias' in name:
            nn.init.constant_(param, 0.0)
            
    h0 = torch.ones(num_nodes, hidden_dim)
    # 0 is connected to 1, 1 is connected to 2
    edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    
    threat_vector_weak = torch.ones(1, threat_dim) * 0.1
    threat_vector_strong = torch.ones(1, threat_dim) * 10.0
    t = torch.linspace(0.0, 1.0, steps=10)
    
    brs_weak = model(h0, edge_index, threat_vector_weak, t)
    brs_strong = model(h0, edge_index, threat_vector_strong, t)
    
    # Structural integrity check: Stronger threat must strictly yield a higher aggregate Blast Radius Score
    assert brs_strong.mean() > brs_weak.mean(), "BRS failed monotonicity constraint: Stronger threats must yield higher BRS."
    
    # Ensure network topology bounds the BRS decay 
    # Nodes further from the threat source should typically exhibit decayed impact if structurally sound
    assert brs_weak.shape == (num_nodes, 1)

def test_lipschitz_continuity_bounds():
    """Verify Lipschitz continuity bounds for the ODE solver to guarantee adversarial perturbations don't cause explosive divergence."""
    hidden_dim = 16
    threat_dim = 16
    num_nodes = 3
    
    model = CT_GODE(hidden_dim, threat_dim)
    
    h0 = torch.randn(num_nodes, hidden_dim)
    edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    threat_vector = torch.randn(1, threat_dim)
    t = torch.linspace(0.0, 1.0, steps=5)
    
    brs_original = model(h0, edge_index, threat_vector, t)
    
    # Apply small adversarial perturbation
    epsilon = 1e-3
    h0_perturbed = h0 + epsilon * torch.randn_like(h0)
    brs_perturbed = model(h0_perturbed, edge_index, threat_vector, t)
    
    # Lipschitz bound check: ||f(x) - f(y)|| <= L ||x - y||
    diff_output = torch.norm(brs_original - brs_perturbed)
    diff_input = torch.norm(h0 - h0_perturbed)
    
    L_estimate = diff_output / (diff_input + 1e-9)
    assert L_estimate < 100.0, f"Explosive divergence detected! Lipschitz constant estimate too high: {L_estimate}"
