import os
os.environ["MOCK_HW"] = "1"

import pytest
import numpy
import torch
import gc

@pytest.fixture(autouse=True)
def run_gc():
    yield
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

