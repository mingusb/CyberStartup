import torch
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.neuro_symbolic import NeuroSymbolicPipeline
from models.ct_gode import CT_GODE

def test_adversarial_poisoning_rejection():
    """
    Adversarial Robustness Testing:
    Deliberately attempt to inject poisoned unauthorized software dumps / inputs and verify 
    that the NeuroSymbolicPipeline structurally rejects them using Fast Gradient Sign Method (FGSM).
    """
    pipeline = NeuroSymbolicPipeline(text_dim=768, binary_dim=256, image_dim=512, hidden_dim=128)
    
    # 1. Simulate adversarial poisoning via FGSM
    text = torch.randn(3, 768, requires_grad=True)
    binary = torch.randn(3, 256, requires_grad=True)
    image = torch.randn(3, 512, requires_grad=True)
    threat_dag_edges = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    
    z_threat = pipeline(text, binary, image, threat_dag_edges)
    
    target = torch.randn_like(z_threat)
    loss = torch.nn.functional.mse_loss(z_threat, target)
    loss.backward()
    
    epsilon = 0.1
    adv_text = text + epsilon * text.grad.sign()
    adv_binary = binary + epsilon * binary.grad.sign()
    adv_image = image + epsilon * image.grad.sign()
    
    adv_z_threat = pipeline(adv_text, adv_binary, adv_image, threat_dag_edges)
    
    # Verify the output hasn't deviated beyond a safe bound (robustness)
    deviation = torch.norm(adv_z_threat - z_threat, p=float('inf')).item()
    assert deviation < 2.0, f"Adversarial deviation {deviation} is too large, pipeline not robust"
    
    # 2. Simulate injecting poisoned weights directly into CT-GODE
    model = CT_GODE(hidden_dim=128, threat_dim=128)
    with torch.no_grad():
        for param in model.parameters():
            param.copy_(torch.randn_like(param) * 10.0) # Poisoned weights
            
    # Verify BRS still bounds properly
    h0 = torch.randn(3, 128)
    t = torch.linspace(0.0, 1.0, steps=2)
    brs = model(h0, threat_dag_edges, adv_z_threat, t)
    
    assert (brs >= 0.0).all() and (brs <= 1.0).all(), "BRS must remain strictly bounded [0,1] even under poisoning"