import torch
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from models.ctse import CounterfactualThreatGAN
    HAS_CTSE = True
except ImportError:
    HAS_CTSE = False

@pytest.mark.skipif(not HAS_CTSE, reason="CounterfactualThreatGAN (CTSE) has been removed from the product")
def test_adversarial_fuzzing_gan():
    """
    Adversarial Fuzzing Framework for CTSE GAN to ensure structural integrity
    under malformed inputs and extreme noise conditions.
    """
    gan = CounterfactualThreatGAN(noise_dim=64, threat_dim=128, tag_dim=128)
    
    tag_nodes = torch.randn(3, 128)
    edge_index = torch.tensor([[0, 1], [1, 2]])
    # Fuzzing with extreme batch sizes
    extreme_batch = 1000
    try:
        synthetic_threat = gan.generate_counterfactual(tag_nodes, edge_index, num_samples=extreme_batch)
        assert synthetic_threat.shape == (extreme_batch, 128)
    except MemoryError:
        pass # Expected under extreme load, but should not crash Python

    # Fuzzing with invalid inputs to discriminator
    malformed_noise = torch.randn(10, 64) * 1e6 # Extreme values
    tag_context = tag_nodes.mean(dim=0, keepdim=True).repeat(10, 1)
    gen_input = torch.cat([malformed_noise, tag_context], dim=1)
    try:
        simulated_threat = gan.generator(gen_input)
        assert not torch.isnan(simulated_threat).any(), "Adversarial Fuzzing: NaN detected in GAN output"
    except Exception as e:
        pytest.fail(f"Adversarial fuzzing caused an unhandled exception: {e}")
