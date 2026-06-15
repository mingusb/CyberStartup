import pytest
import ctypes
import os
import sys

try:
    from cyberstartup.orchestration.bpf_injector import PythonSGXFallback
    HAS_FALLBACK = True
except ImportError:
    HAS_FALLBACK = False

# Load the shared library
sgx_lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src', 'sgx', 'sgx_enclave.so'))

def test_sgx_enclave_attestation():
    """
    Test the C-level SGX Enclave attestation logic to verify out-of-band hardware attestation.
    """
    if os.environ.get("REQUIRE_REAL_SGX") != "1":
        pytest.skip("Hardware-Simulation Boundary: Actual SGX hardware is not present. Set REQUIRE_REAL_SGX=1 to enforce strict hardware validation.")
        
    if not os.path.exists(sgx_lib_path):
        pytest.fail(f"Hardware-Simulation Boundary Breached: SGX enclave library not found at {sgx_lib_path}. Strict SGX hardware validation required.")
        
    sgx_lib = ctypes.CDLL(sgx_lib_path)
    sgx_lib.attest_enclave.restype = ctypes.c_int
    
    # attest_enclave should verify the simulated quote and return 1
    result = sgx_lib.attest_enclave()
    assert result == 1, "SGX Enclave cryptographic attestation failed."

def test_sgx_enclave_encryption():
    """
    Test the SGX Enclave's in-memory ChaCha20 encryption pipeline.
    """
    if os.environ.get("REQUIRE_REAL_SGX") != "1":
        pytest.skip("Hardware-Simulation Boundary: Actual SGX hardware is not present. Set REQUIRE_REAL_SGX=1 to enforce strict hardware validation.")
        
    if not os.path.exists(sgx_lib_path):
        pytest.fail(f"Hardware-Simulation Boundary Breached: SGX enclave library not found at {sgx_lib_path}. Strict SGX hardware validation required.")
        
    sgx_lib = ctypes.CDLL(sgx_lib_path)
    sgx_lib.encrypt_memory_page.argtypes = [ctypes.c_void_p, ctypes.c_int]
    sgx_lib.encrypt_memory_page.restype = ctypes.c_int
    sgx_lib.decrypt_memory_page.argtypes = [ctypes.c_void_p, ctypes.c_int]
    sgx_lib.decrypt_memory_page.restype = ctypes.c_int
    
    # Create a 128-byte buffer
    buffer_size = 128
    original_data = b"A" * buffer_size
    buffer = ctypes.create_string_buffer(original_data, buffer_size)
    
    # Encrypt
    res = sgx_lib.encrypt_memory_page(buffer, buffer_size)
    assert res == 1, "Encryption function returned failure."
    
    encrypted_data = bytes(buffer)
    assert encrypted_data != original_data, "Data was not encrypted."
    
    # Decrypt
    res = sgx_lib.decrypt_memory_page(buffer, buffer_size)
    assert res == 1, "Decryption function returned failure."
    
    decrypted_data = bytes(buffer)
    assert decrypted_data == original_data, "Data was not correctly decrypted."

@pytest.mark.skipif(not HAS_FALLBACK, reason="PythonSGXFallback is not available")
def test_python_sgx_fallback():
    """
    Verify the simulated PythonSGXFallback enclave logic (attestation, compilation check, in-memory encryption).
    """
    from cyberstartup.orchestration.bpf_injector import PythonSGXFallback
    import ctypes
    import tempfile
    import os
    
    fallback = PythonSGXFallback()
    
    # 1. Test Attestation
    assert fallback.attest_enclave(b"HOST_ASIC_test_host") == 1
    
    # 2. Test Compile in Enclave check
    with tempfile.NamedTemporaryFile(suffix='.o', delete=False) as f:
        f.write(b"dummy compiled elf bytes")
        temp_path = f.name
    try:
        assert fallback.compile_in_enclave(b"dummy.c", temp_path.encode('utf-8')) == 0
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
    # 3. Test Encryption / Decryption in-place
    original = b"Hello, secure memory page world!"
    buffer = ctypes.create_string_buffer(original, len(original))
    
    # Encrypt
    assert fallback.encrypt_memory_page(buffer, len(original)) == 1
    encrypted = buffer.raw
    assert encrypted != original
    
    # Decrypt
    assert fallback.decrypt_memory_page(buffer, len(original)) == 1
    decrypted = buffer.raw
    assert decrypted == original

