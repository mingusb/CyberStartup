#!/bin/bash
set -e

# Resolve directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "[*] Setting up isolated test environment..."
if [ ! -d "venv_test" ]; then
    python3 -m venv venv_test
fi

echo "[*] Upgrading pip and installing requirements..."
venv_test/bin/pip install --upgrade pip --quiet
venv_test/bin/pip install -r requirements.txt --quiet
venv_test/bin/pip install pytest --quiet

echo "[*] Provisioning threat intelligence data..."
PYTHONPATH=src venv_test/bin/python src/cyberstartup/ingestion/mitre_fetcher.py

echo "[*] Building eBPF and SGX binaries..."
make ebpf sgx

echo "[*] Running pytest suite..."
PYTHONPATH=src MOCK_HW=1 venv_test/bin/pytest tests/

echo "[*] Tests completed successfully!"
