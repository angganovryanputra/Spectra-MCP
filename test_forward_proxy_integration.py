import os
import sys
import json
import time
import asyncio
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure environment uses alternate ports so port 8000 in WSL2 is not touched!
TARGET_MOCK_PORT = 8999
PROXY_TEST_PORT = 8090

os.environ["SPECTRA_PROXY_PORT"] = str(PROXY_TEST_PORT)
os.environ["SPECTRA_BACKEND_URL"] = "http://127.0.0.1:8081" # Not 8000!

from backend.database import init_db, SessionLocal, HttpLog, Project, TargetAsset
from backend.forward_proxy import start_forward_proxy, stop_forward_proxy
import mcp_server

# 1. SETUP DUMMY TARGET HTTP SERVER (Port 8999)
class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Target-Server", "TargetApp/v2.1")
        self.end_headers()
        self.wfile.write(b'{"status": "vulnerable", "flag": "SPECTRA_PROXY_CAPTURED_SUCCESS", "path": "' + self.path.encode() + b'"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "received_exploit", "echo": "' + body + b'"}')

    def log_message(self, format, *args):
        pass  # Suppress console log noise

dummy_target = HTTPServer(("127.0.0.1", TARGET_MOCK_PORT), TargetHandler)
target_thread = threading.Thread(target=dummy_target.serve_forever, daemon=True)
target_thread.start()

async def main():
    print("=== STARTING FORWARD PROXY INTEGRATION & DEBUGGING ===")
    init_db()

    # Create test project with scope configured for the mock target
    db = SessionLocal()
    proj = db.query(Project).filter(Project.name == "auto_proxy_proj").first()
    if not proj:
        proj = Project(
            name="auto_proxy_proj",
            scope_enabled=True,
            allowed_hosts=json.dumps(["127.0.0.1", "localhost"]),
            blocked_patterns=json.dumps(["restricted_admin_secret"]),
            allow_internal_networks=True
        )
        db.add(proj)
    else:
        proj.scope_enabled = True
        proj.allowed_hosts = json.dumps(["127.0.0.1", "localhost"])
        proj.blocked_patterns = json.dumps(["restricted_admin_secret"])
        proj.allow_internal_networks = True
    db.commit()
    db.close()

    from backend.intercept_manager import invalidate_scope_cache
    invalidate_scope_cache("auto_proxy_proj")

    # 2. START SPECTRA FORWARD PROXY ON PORT 8088
    print(f"\n[TEST 1] Starting Spectra Forward Proxy on port {PROXY_TEST_PORT}...")
    proxy_server = await start_forward_proxy("127.0.0.1", PROXY_TEST_PORT)
    assert proxy_server is not None
    print(f"  ✓ Forward Proxy listening on http://127.0.0.1:{PROXY_TEST_PORT}")

    # 3. CREATE STANDALONE PYTHON SCRIPT (SIMULATING OPENCODE WRITING AN EXPLOIT POC)
    script_content = f'''import requests

# This script has NO proxy configured manually! Pure vanilla requests!
url = "http://127.0.0.1:{TARGET_MOCK_PORT}/api/v1/auth/sqli-test?id=1' OR 1=1--"
resp = requests.get(url, timeout=5)
print("SCRIPT_STATUS_CODE:", resp.status_code)
print("SCRIPT_BODY:", resp.text)
'''
    script_path = os.path.abspath("test_opencode_poc.py")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_content)

    print("\n[TEST 2] Executing OpenCode script via mcp_server.run_pentest_command...")
    python_exe = sys.executable
    cmd = f'"{python_exe}" "{script_path}"'

    res_cmd_str = await mcp_server.run_pentest_command(
        command=cmd,
        reasoning="Testing SQL injection via standalone exploit script",
        project="auto_proxy_proj",
        output_format="json"
    )
    res_cmd = json.loads(res_cmd_str)
    assert res_cmd["status"] == "SUCCESS", f"Command failed: {res_cmd}"
    print("STDOUT:", res_cmd.get("stdout"))
    print("STDERR:", res_cmd.get("stderr"))
    assert "SCRIPT_STATUS_CODE: 200" in res_cmd["stdout"]
    assert "SPECTRA_PROXY_CAPTURED_SUCCESS" in res_cmd["stdout"]
    print("  ✓ OpenCode script executed successfully through subprocess!")

    # 4. VERIFY THAT SPECTRA AUTOMATICALLY CAPTURED AND LOGGED THE HTTP TRAFFIC
    print("\n[TEST 3] Verifying that Spectra Proxy intercepted and recorded the script traffic...")
    db = SessionLocal()
    captured_log = db.query(HttpLog).filter(
        HttpLog.project == "auto_proxy_proj",
        HttpLog.url.like(f"%{TARGET_MOCK_PORT}/api/v1/auth/sqli-test%")
    ).order_by(HttpLog.id.desc()).first()

    assert captured_log is not None, "FATAL: Outbound script traffic was NOT captured by Spectra Proxy!"
    assert captured_log.source == "FORWARD_PROXY"
    assert captured_log.status_code == 200
    assert "SPECTRA_PROXY_CAPTURED_SUCCESS" in captured_log.response_body
    print(f"  ✓ Traffic verified in Spectra Database (Log #{captured_log.id}, Method: {captured_log.method}, Status: {captured_log.status_code})")
    print(f"  ✓ Log Source correctly flagged as '{captured_log.source}'")

    # 5. VERIFY TARGET KNOWLEDGE GRAPH AUTO-INGESTION
    print("\n[TEST 4] Verifying Target Knowledge Graph Ingestion from Script Traffic...")
    asset = db.query(TargetAsset).filter(TargetAsset.project == "auto_proxy_proj").first()
    assert asset is not None, "Target host was not ingested into Target Knowledge Graph!"
    print(f"  ✓ Host '{asset.host}' automatically mapped in Knowledge Graph from script traffic!")
    db.close()

    # 6. TEST SCOPE GUARDRAIL PROTECTION ON SCRIPT EXECUTION
    print("\n[TEST 5] Verifying Scope Guardrail blocking on malicious script attempt...")
    blocked_script_content = f'''import requests
url = "http://127.0.0.1:{TARGET_MOCK_PORT}/restricted_admin_secret"
resp = requests.get(url, timeout=5)
print("BLOCKED_SCRIPT_CODE:", resp.status_code)
print("BLOCKED_SCRIPT_BODY:", resp.text)
'''
    blocked_script_path = os.path.abspath("test_blocked_script.py")
    with open(blocked_script_path, "w", encoding="utf-8") as f:
        f.write(blocked_script_content)

    res_blocked_cmd_str = await mcp_server.run_pentest_command(
        command=f'"{python_exe}" "{blocked_script_path}"',
        reasoning="Attempting access to out-of-scope restricted path",
        project="auto_proxy_proj",
        output_format="json"
    )
    res_blocked = json.loads(res_blocked_cmd_str)
    assert "BLOCKED_SCRIPT_CODE: 403" in res_blocked["stdout"]
    assert "BLOCKED BY SPECTRA SCOPE GUARD" in res_blocked["stdout"]
    print("  ✓ Forward Proxy successfully intercepted and BLOCKED out-of-scope script attempt with HTTP 403!")

    # 6. TEST HTTPS TLS MITM INTERCEPTION & DECRYPTION
    print("\n[TEST 6] Verifying HTTPS TLS MITM Interception & Request Decryption...")
    from backend.forward_proxy import get_ssl_context_for_host

    class TargetHttpsHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "https_vulnerable", "flag": "SPECTRA_HTTPS_DECRYPTED_SUCCESS", "path": "' + self.path.encode() + b'"}')
        def log_message(self, format, *args): pass

    https_target = HTTPServer(("127.0.0.1", 9443), TargetHttpsHandler)
    mock_https_ctx = get_ssl_context_for_host("127.0.0.1")
    https_target.socket = mock_https_ctx.wrap_socket(https_target.socket, server_side=True)
    https_thread = threading.Thread(target=https_target.serve_forever, daemon=True)
    https_thread.start()

    https_script_content = f'''import requests
url = "https://127.0.0.1:9443/api/v1/auth/https-sqli-test?id=admin'%20OR%201=1--"
resp = requests.get(url, timeout=5, verify=False)
print("HTTPS_SCRIPT_STATUS_CODE:", resp.status_code)
print("HTTPS_SCRIPT_BODY:", resp.text)
'''
    https_script_path = os.path.abspath("test_https_script.py")
    with open(https_script_path, "w", encoding="utf-8") as f:
        f.write(https_script_content)

    res_https_cmd_str = await mcp_server.run_pentest_command(
        command=f'"{python_exe}" "{https_script_path}"',
        reasoning="Executing HTTPS exploit script through proxy",
        project="auto_proxy_proj",
        output_format="json"
    )
    res_https_cmd = json.loads(res_https_cmd_str)
    assert res_https_cmd["status"] == "SUCCESS", f"HTTPS script failed: {res_https_cmd}"
    assert "HTTPS_SCRIPT_STATUS_CODE: 200" in res_https_cmd["stdout"]
    assert "SPECTRA_HTTPS_DECRYPTED_SUCCESS" in res_https_cmd["stdout"]

    # Verify that Spectra captured the DECRYPTED GET request (NOT just a blind CONNECT)
    db = SessionLocal()
    https_captured_log = db.query(HttpLog).filter(
        HttpLog.project == "auto_proxy_proj",
        HttpLog.url.like("%https-sqli-test%")
    ).order_by(HttpLog.id.desc()).first()

    assert https_captured_log is not None, "FATAL: Decrypted HTTPS traffic was NOT logged!"
    assert https_captured_log.method == "GET", f"Expected GET, got {https_captured_log.method}"
    assert https_captured_log.status_code == 200
    assert "SPECTRA_HTTPS_DECRYPTED_SUCCESS" in https_captured_log.response_body
    print(f"  ✓ Decrypted HTTPS Request verified in DB! (Log #{https_captured_log.id}, Method: {https_captured_log.method}, Path: {https_captured_log.path})")
    print(f"  ✓ Full Decrypted Response Body captured: {https_captured_log.response_body[:80]}...")

    # Ensure NO dummy CONNECT log with path '/9443' was recorded
    dummy_connect_log = db.query(HttpLog).filter(
        HttpLog.project == "auto_proxy_proj",
        HttpLog.method == "CONNECT"
    ).first()
    assert dummy_connect_log is None, f"Found unwanted dummy CONNECT log: {dummy_connect_log.id}"
    print("  ✓ Confirmed: Zero noisy 'CONNECT' logs recorded in database!")
    db.close()
    https_target.shutdown()
    if os.path.exists(https_script_path):
        os.remove(https_script_path)

    # 7. CLEANUP
    await stop_forward_proxy()
    dummy_target.shutdown()
    if os.path.exists(script_path):
        os.remove(script_path)
    if os.path.exists(blocked_script_path):
        os.remove(blocked_script_path)

    print("\n=== ALL FORWARD PROXY TESTS PASSED WITH 0 ERRORS! ===")

if __name__ == "__main__":
    asyncio.run(main())
