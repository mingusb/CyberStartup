#!/bin/bash
set -e

# Resolve directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# 1. Setup virtual environment if not present and install dependencies
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[*] Upgrading pip and installing dependencies..."
venv/bin/pip install --upgrade pip --quiet
venv/bin/pip install --ignore-installed -r requirements.txt --quiet

# 2. Ingest threat intelligence from MITRE/STIX
echo "[*] Running threat intelligence fetcher..."
PYTHONPATH=src venv/bin/python src/cyberstartup/ingestion/mitre_fetcher.py

# 3. Start production FastAPI backend app
echo "[*] Starting Cyber Startup FastAPI production backend..."
PYTHONPATH=src venv/bin/python src/cyberstartup/api/production_api.py
