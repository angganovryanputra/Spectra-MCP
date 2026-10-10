@echo off
echo [*] Initializing Spectra MCP Environment for Windows...

if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [*] Installing dependencies...
pip install -r requirements.txt
playwright install chromium

echo [*] Starting FastAPI Web Dashboard on http://127.0.0.1:8000 in background...
start "Spectra Dashboard" uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload

echo [*] Starting Spectra MCP Server (Stdio)...
python mcp_server.py
