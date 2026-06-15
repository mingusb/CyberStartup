import torch
import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.parsers import TextParser, HexParser, ImageParser

def test_text_parser():
    parser = TextParser(embedding_dim=64)
    # Test string input
    out1 = parser.parse("malicious indicator")
    assert isinstance(out1, list)
    assert len(out1) == 1
    assert out1[0] == "malicious indicator"
    # Test list input
    out2 = parser.parse(["threat A", "threat B"])
    assert isinstance(out2, list)
    assert len(out2) == 2
    assert out2[0] == "threat A"

def test_hex_parser():
    parser = HexParser(embedding_dim=128)
    
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(os.urandom(256))
        f_name = f.name
        
    try:
        out = parser.parse([f_name])
        assert out.shape == (1, 128)
        assert not torch.isnan(out).any()
    finally:
        os.remove(f_name)

def test_image_parser():
    parser = ImageParser(embedding_dim=32)
    # Testing heuristic baseline raw bytes parsing if PIL isn't available, 
    # or PIL parsing if it is. Both should output the correct shape.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(os.urandom(1024))
        f_name = f.name
        
    try:
        out = parser.parse([f_name])
        assert out.shape == (1, 32)
    finally:
        os.remove(f_name)
