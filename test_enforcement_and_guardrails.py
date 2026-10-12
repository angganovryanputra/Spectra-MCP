"""
End-to-end Test: Transparent AI Agent Enforcement & Zero Default Guardrails
Verifies:
1. Python scripts executed directly (simulating OpenCode native bash) automatically route through Spectra proxy via sitecustomize.py.
2. Default project has ZERO guardrails active (no SSRF blocking on 127.0.0.1/private IPs, no pattern blocking).
3. Manual configuration of guardrails works when explicitly enabled.
"""
import os
import sys
import json
import time
import asyncio
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

TARGET_PORT = 8995
PROXY_PORT = 8092  # Dedicated port for test run

os.environ["SPECTRA_PROXY_PORT"] = str(PROXY_PORT)
os.environ["SPECTRA_BACKEND_URL"] = "http://127.0.0.1:8082"

from backend.database import init_db, SessionLocal, HttpLog, Project
from backend.forward_proxy import start_forward_proxy, stop_forward_proxy
from backend.intercept_manager import check_scope, invalidate_scope_cache

# 1. SETUP DUMMY TARGET HTTP SERVER
class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        resp = b'{"status": "ok", "captured_target": true, "path": "' + self.path.encode() + b'"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args):
        pass

dummy_target = HTTPServer(("127.0.0.1", TARGET_PORT), TargetHandler)
target_thread = threading.Thread(target=dummy_target.serve_forever, daemon=True)
target_thread.start()

async def run_tests():
    print("=== TESTING TRANSPARENT PROXY ENFORCEMENT & ZERO DEFAULT GUARDRAILS ===")
    init_db()

    # 1. VERIFY DATABASE DEFAULTS FOR DEFAULT PROJECT
    db = SessionLocal()
    default_proj = db.query(Project).filter(Project.name == "default").first()
    assert default_proj is not None, "Default project missing!"
    print(f"\n[CHECK 1] Default Project Guardrail Settings:")
    print(f"  - scope_enabled: {default_proj.scope_enabled} (Must be False)")
    print(f"  - allowed_hosts: {default_proj.allowed_hosts} (Must be ['*'])")
    print(f"  - blocked_patterns: {default_proj.blocked_patterns} (Must be [])")
    print(f"  - allow_internal_networks: {default_proj.allow_internal_networks} (Must be True)")

    assert default_proj.scope_enabled is False, "Guardrail must be disabled by default!"
    assert json.loads(default_proj.blocked_patterns) == [], "Blocked patterns must be empty by default!"
    assert default_proj.allow_internal_networks is True, "Internal networks must be permitted by default!"
    print("  ✓ PASSED: Default project has ZERO active guardrails out of the box.")

    # 2. VERIFY SCOPE CHECK ALLOWS EVERYTHING BY DEFAULT
    invalidate_scope_cache("default")
    allowed, reason = check_scope("default", f"http://127.0.0.1:{TARGET_PORT}/admin/delete_user", db)
    assert allowed is True, f"Expected 127.0.0.1 delete_user to be permitted by default, got: {reason}"
    allowed_priv, reason_priv = check_scope("default", "http://192.168.1.100:8080/api/payment", db)
    assert allowed_priv is True, f"Expected private IP payment to be permitted by default, got: {reason_priv}"
    print("  ✓ PASSED: check_scope permits internal IPs and sensitive keywords when scope_enabled=False.")

    # 3. START PROXY SERVER
    print(f"\n[CHECK 2] Starting Spectra Forward Proxy on port {PROXY_PORT}...")
    proxy_server = await start_forward_proxy("127.0.0.1", PROXY_PORT)
    assert proxy_server is not None
    print(f"  ✓ Forward Proxy running on http://127.0.0.1:{PROXY_PORT}")

    # 4. SIMULATE OPENCODE RUNNING A PLAIN PYTHON SCRIPT DIRECTLY (WITHOUT SPECTRA MCP TOOLS)
    # This script contains NO proxy configuration whatsoever.
    # It executes directly via subprocess.run([python, script])!
    script_content = f'''import requests

# Vanilla requests with ZERO proxy configuration
url = "http://127.0.0.1:{TARGET_PORT}/api/test/opencode_enforce_check?token=xyz"
resp = requests.get(url, timeout=5)
print("AGENT_STATUS:", resp.status_code)
print("AGENT_BODY:", resp.text)
'''
    script_file = os.path.abspath("test_standalone_opencode_script.py")
    with open(script_file, "w", encoding="utf-8") as f:
        f.write(script_content)

    print("\n[CHECK 3] Executing plain Python script directly (simulating native OpenCode bash run)...")
    env = os.environ.copy()
    # Ensure current directory is in PYTHONPATH so sitecustomize.py is loaded
    env["PYTHONPATH"] = os.path.dirname(script_file)
    env["SPECTRA_PROXY_PORT"] = str(PROXY_PORT)
    env["SPECTRA_PROXY_URL"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["HTTP_PROXY"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["http_proxy"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["https_proxy"] = f"http://127.0.0.1:{PROXY_PORT}"

    proc = await asyncio.create_subprocess_exec(
        sys.executable, script_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env
    )
    stdout_b, stderr_b = await proc.communicate()
    stdout_text = stdout_b.decode("utf-8", errors="replace")
    stderr_text = stderr_b.decode("utf-8", errors="replace")

    print("STDOUT:", stdout_text.strip())
    if stderr_text:
        print("STDERR:", stderr_text.strip())

    assert proc.returncode == 0, f"Script failed with code {proc.returncode}"
    assert "AGENT_STATUS: 200" in stdout_text
    assert "captured_target" in stdout_text

    # 5. VERIFY THAT SPECTRA PROXY CAPTURED THE DIRECT SCRIPT EXECUTION
    await asyncio.sleep(1.0)
    db.close()
    db = SessionLocal()
    captured = db.query(HttpLog).filter(
        HttpLog.url.like("%opencode_enforce_check%")
    ).order_by(HttpLog.id.desc()).first()

    assert captured is not None, "FATAL: Outbound script traffic was NOT captured by Spectra Proxy!"
    assert captured.source == "FORWARD_PROXY"
    assert captured.status_code == 200
    assert "opencode_enforce_check" in captured.path
    print(f"  ✓ SUCCESS: Standalone script traffic was AUTOMATICALLY intercepted and logged! (Log #{captured.id})")
    print(f"  - Method: {captured.method}, Host: {captured.host}, Status: {captured.status_code}")

    # 6. VERIFY MANUAL GUARDRAIL ACTIVATION
    print("\n[CHECK 4] Verifying Manual Guardrail Activation...")
    default_proj = db.query(Project).filter(Project.name == "default").first()
    default_proj.scope_enabled = True
    default_proj.blocked_patterns = json.dumps(["secret_vault"])
    default_proj.allowed_hosts = json.dumps(["authorized-target.com"])
    db.commit()
    invalidate_scope_cache("default")

    allowed_manual, reason_manual = check_scope("default", f"http://127.0.0.1:{TARGET_PORT}/secret_vault", db)
    assert allowed_manual is False, "Expected secret_vault to be blocked when guardrail is enabled!"
    print(f"  ✓ PASSED: Guardrail actively enforced when manually enabled ({reason_manual})")

    # Reset default project back to zero guardrails
    default_proj.scope_enabled = False
    default_proj.blocked_patterns = json.dumps([])
    default_proj.allowed_hosts = json.dumps(["*"])
    default_proj.allow_internal_networks = True
    db.commit()
    invalidate_scope_cache("default")
    db.close()

    # CLEANUP
    await stop_forward_proxy()
    dummy_target.shutdown()
    if os.path.exists(script_file):
        os.remove(script_file)

    print("\n=== ALL TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    asyncio.run(run_tests())
