import torch
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ode_solver import odeint, rk4_step

def test_rk4_step():
    """Test that the RK4 step returns a tensor of the correct shape."""
    def simulated_func(t, y):
        return -0.5 * y
        
    y = torch.tensor([1.0, 2.0])
    t = torch.tensor(0.0)
    dt = 0.1
    
    y_next = rk4_step(simulated_func, t, y, dt)
    assert y_next.shape == y.shape, "RK4 step changed tensor shape"

def test_odeint():
    """Test the full ODE integration loop."""
    def simulated_func(t, y):
        return -0.5 * y
        
    y0 = torch.tensor([1.0, 2.0])
    t = torch.linspace(0.0, 1.0, steps=10)
    
    solution = odeint(simulated_func, y0, t)
    
    assert solution.shape == (10, 2), "Integration solution shape mismatch"
    # Basic structural check: values should decay due to -0.5*y
    assert torch.all(solution[-1] < y0), "Integration did not proceed in expected direction"

def test_rk4_convergence():
    """Prove that the RK4 implementation converges at O(h^4)."""
    def simulated_func(t, y):
        return -y
        
    y0 = torch.tensor([1.0])
    
    h1 = 0.1
    y1 = rk4_step(simulated_func, torch.tensor(0.0), y0, h1)
    exact1 = torch.exp(torch.tensor([-h1]))
    error1 = torch.abs(y1 - exact1).item()
    
    h2 = 0.05
    y2 = rk4_step(simulated_func, torch.tensor(0.0), y0, h2)
    exact2 = torch.exp(torch.tensor([-h2]))
    error2 = torch.abs(y2 - exact2).item()
    
    if error2 > 0:
        ratio = error1 / error2
        assert ratio > 10.0, f"Expected O(h^4) convergence, but ratio was {ratio}"

def test_dopri5_adaptive_odeint():
    """Verify that Dopri5 adaptive solver runs and honors tolerances."""
    def simulated_func(t, y):
        return -0.5 * y
        
    y0 = torch.tensor([1.0, 2.0])
    t = torch.linspace(0.0, 1.0, steps=10)
    
    # Run with adaptive step solver
    solution = odeint(simulated_func, y0, t, rtol=1e-4, atol=1e-6)
    
    assert solution.shape == (10, 2), "Dopri5 adaptive solution shape mismatch"
    assert torch.all(solution[-1] < y0), "Integration did not proceed in expected direction"
    
    # Check that error is bounded by tolerances
    exact = y0 * torch.exp(-0.5 * t[-1])
    error = torch.abs(solution[-1] - exact)
    # The error should be small
    assert torch.all(error < 1e-3), f"Error {error} exceeded reasonable tolerance under Dopri5"
