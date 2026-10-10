#!/usr/bin/env bash
set -e

echo "[*] Initializing Spectra MCP Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

pip install -r requirements.txt
playwright install chromium

echo "[*] Starting FastAPI Web Dashboard on http://127.0.0.1:8000..."
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload &
FASTAPI_PID=$!

echo "[*] Starting Spectra MCP Server..."
python3 mcp_server.py

kill $FASTAPI_PID
