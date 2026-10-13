# ==============================================================================
# Proxynth MCP - Application and MCP Runner for Windows (PowerShell)
# ==============================================================================

[CmdletBinding()]
param(
    [ValidateSet("dashboard", "mcp", "all", "install")]
    [string]$Mode = "dashboard"
)

$VenvPython = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

# If venv not found, auto-trigger installer
if (-not (Test-Path $VenvPython)) {
    Write-Host "[*] Proxynth virtual environment not detected. Running installer..." -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "install.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Installation failed. Aborting." -ForegroundColor Red
        exit 1
    }
}

switch ($Mode.ToLower()) {
    "dashboard" {
        Write-Host "========================================================================" -ForegroundColor Cyan
        Write-Host "  Starting Proxynth Web Dashboard" -ForegroundColor Cyan
        Write-Host "  URL: http://127.0.0.1:8000" -ForegroundColor Green
        Write-Host "========================================================================" -ForegroundColor Cyan
        & $VenvPython -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
    }
    "mcp" {
        # Pure silent execution for JSON-RPC MCP stdio compatibility
        & $VenvPython (Join-Path $PSScriptRoot "mcp_server.py")
    }
    "all" {
        Write-Host "[*] Starting Proxynth Dashboard in background process..." -ForegroundColor Cyan
        Start-Process -FilePath $VenvPython -ArgumentList "-m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload" -WindowStyle Normal
        Write-Host "[*] Starting Proxynth MCP Server in foreground..." -ForegroundColor Cyan
        & $VenvPython (Join-Path $PSScriptRoot "mcp_server.py")
    }
    "install" {
        & (Join-Path $PSScriptRoot "install.ps1")
    }
}
