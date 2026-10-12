import os
import sys
import json
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient

from backend.app import app
from backend.database import init_db

print("=== STARTING FULL SUITE VALIDATION & DEBUGGING ===")

# Initialize db
init_db()
client = TestClient(app)

# 1. TEST STATIC ASSETS & INDEX
print("\n[TEST 1] Verifying Static Files & Index Serving...")
res_index = client.get("/")
assert res_index.status_code == 200, f"Index failed: {res_index.status_code}"
assert "SPECTRA // Security Testing Gateway" in res_index.text
assert "/static/css/style.css" in res_index.text
assert "/static/js/attack_surface.js" in res_index.text
assert "/static/js/oast.js" in res_index.text
print("  ✓ Index HTML serves correctly with modular asset links.")

res_css = client.get("/static/css/style.css")
assert res_css.status_code == 200, f"CSS failed: {res_css.status_code}"
assert ".glow-rose" in res_css.text
print("  ✓ CSS stylesheet serves correctly.")

res_as_js = client.get("/static/js/attack_surface.js")
assert res_as_js.status_code == 200, f"attack_surface.js failed: {res_as_js.status_code}"
assert "AttackSurfaceModule" in res_as_js.text
print("  ✓ attack_surface.js serves correctly.")

res_oast_js = client.get("/static/js/oast.js")
assert res_oast_js.status_code == 200, f"oast.js failed: {res_oast_js.status_code}"
assert "OastModule" in res_oast_js.text
print("  ✓ oast.js serves correctly.")

# 2. TEST TARGET KNOWLEDGE GRAPH ENDPOINTS
print("\n[TEST 2] Verifying Target Knowledge Graph Endpoints...")
asset_payload = {
    "project": "test_suite_proj",
    "host": "api.testtarget.local",
    "ip": "192.168.1.50",
    "os_info": "Linux Ubuntu 22.04",
    "tags": ["cloud", "internal", "api"],
    "notes": "Primary target API host"
}
res_asset = client.post("/api/targets/assets", json=asset_payload)
assert res_asset.status_code == 200, f"Asset create failed: {res_asset.text}"
asset_data = res_asset.json()
asset_id = asset_data["id"]
print(f"  ✓ Target Asset upserted (ID: {asset_id}, host: {asset_data['host']})")

svc_payload = {
    "project": "test_suite_proj",
    "host": "api.testtarget.local",
    "port": 443,
    "protocol": "tcp",
    "service_name": "https",
    "banner": "nginx/1.22.0",
    "state": "open"
}
res_svc = client.post("/api/targets/services", json=svc_payload)
assert res_svc.status_code == 200, f"Service create failed: {res_svc.text}"
svc_data = res_svc.json()
svc_id = svc_data["id"]
print(f"  ✓ Target Service recorded (ID: {svc_id}, port: {svc_data['port']})")

ep_payload = {
    "project": "test_suite_proj",
    "host": "api.testtarget.local",
    "url": "https://api.testtarget.local/v1/auth/login",
    "method": "POST",
    "parameters": ["username", "password"],
    "auth_required": False,
    "tested_status": "VULNERABLE",
    "notes": "SQL injection detected in username parameter"
}
res_ep = client.post("/api/targets/endpoints", json=ep_payload)
assert res_ep.status_code == 200, f"Endpoint create failed: {res_ep.text}"
ep_data = res_ep.json()
print(f"  ✓ Target Endpoint recorded (ID: {ep_data['id']}, path: {ep_data['path']})")

res_graph = client.get("/api/targets/graph?project=test_suite_proj")
assert res_graph.status_code == 200, f"Graph failed: {res_graph.text}"
graph_data = res_graph.json()
assert len(graph_data["assets"]) >= 1
assert graph_data["summary"]["total_assets"] >= 1
assert graph_data["summary"]["total_services"] >= 1
assert graph_data["summary"]["total_endpoints"] >= 1
print(f"  ✓ Knowledge Graph verified (Summary: {graph_data['summary']})")

# 3. TEST OAST ENGINE & ENDPOINTS
print("\n[TEST 3] Verifying OAST Engine...")
res_gen = client.post("/api/oast/generate", json={
    "project": "test_suite_proj",
    "description": "Blind SSRF test on webhook param",
    "vuln_type": "SSRF"
})
assert res_gen.status_code == 200, f"OAST generate failed: {res_gen.text}"
oast_info = res_gen.json()
token = oast_info["token"]
callback_url = oast_info["http_url"]
print(f"  ✓ OAST Token generated: {token}")

# Simulate external target server sending Out-Of-Band callback to spectra
res_callback = client.post(
    f"/oast/{token}/admin-leak",
    headers={"X-Forwarded-For": "10.0.0.1", "User-Agent": "VulnerableInternalService/2.0"},
    json={"exfiltrated_key": "SECRET_TOKEN_XYZ_123"}
)
assert res_callback.status_code == 200, f"OAST callback failed: {res_callback.text}"
cb_data = res_callback.json()
assert cb_data["status"] == "captured"
print(f"  ✓ OAST Callback successfully captured from target!")

# Verify event listing
res_events = client.get("/api/oast/events?project=test_suite_proj")
assert res_events.status_code == 200
events = res_events.json()["events"]
assert any(e["token"] == token for e in events)
print(f"  ✓ OAST Event successfully listed in captured events feed.")

# 4. TEST WEBSOCKET BROADCAST
print("\n[TEST 4] Verifying WebSocket Real-time Broadcast...")
with client.websocket_connect("/ws") as websocket:
    greeting = websocket.receive_json()
    assert greeting.get("type") == "CONNECTED"
    print(f"  ✓ WebSocket greeting verified: {greeting}")

    # Trigger another OAST hit
    res_gen2 = client.post("/api/oast/generate", json={
        "project": "ws_test_proj",
        "description": "Blind XXE Out-of-band test",
        "vuln_type": "XXE"
    })
    token2 = res_gen2.json()["token"]
    
    # Hit callback
    client.get(f"/oast/{token2}")
    
    # Receive WS message
    ws_msg = websocket.receive_json()
    assert ws_msg.get("type") == "OAST_HIT", f"Expected OAST_HIT, got: {ws_msg}"
    assert ws_msg["event"]["token"] == token2
    print(f"  ✓ WebSocket received OAST_HIT event broadcast in real time!")

print("\n=== ALL TEST SUITE CHECKS PASSED WITH 0 ERRORS! ===")
