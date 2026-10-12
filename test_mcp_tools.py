import os
import sys
import json
import asyncio

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

import mcp_server

async def main():
    print("=== STARTING MCP TOOLS VALIDATION & DEBUGGING ===")

    # 1. TEST RECORD TARGET ASSET
    print("\n[MCP TEST 1] record_target_asset...")
    res_asset_str = await mcp_server.record_target_asset(
        host="staging.targetcorp.io",
        ip="10.10.14.20",
        os_info="Debian Linux 12",
        tags=["staging", "cloud", "api"],
        notes="Target corp staging environment",
        project="mcp_test_proj"
    )
    res_asset = json.loads(res_asset_str)
    assert res_asset["status"] == "success"
    assert res_asset["asset"]["host"] == "staging.targetcorp.io"
    print(f"  ✓ record_target_asset succeeded: {res_asset['asset']['host']}")

    # 2. TEST RECORD TARGET SERVICE
    print("\n[MCP TEST 2] record_target_service...")
    res_svc_str = await mcp_server.record_target_service(
        host="staging.targetcorp.io",
        port=8443,
        service_name="https-alt",
        protocol="tcp",
        banner="OpenSSL/1.1.1w",
        state="open",
        project="mcp_test_proj"
    )
    res_svc = json.loads(res_svc_str)
    assert res_svc["status"] == "success"
    assert res_svc["service"]["port"] == 8443
    print(f"  ✓ record_target_service succeeded: port {res_svc['service']['port']}")

    # 3. TEST RECORD TARGET ENDPOINT
    print("\n[MCP TEST 3] record_target_endpoint...")
    res_ep_str = await mcp_server.record_target_endpoint(
        host="staging.targetcorp.io",
        url="https://staging.targetcorp.io:8443/api/v2/users/export",
        method="GET",
        parameters=["format", "token"],
        auth_required=True,
        tested_status="TESTED_CLEAN",
        notes="Endpoint checked for IDOR, properly enforced with tenant isolation",
        project="mcp_test_proj"
    )
    res_ep = json.loads(res_ep_str)
    assert res_ep["status"] == "success"
    assert res_ep["endpoint"]["tested_status"] == "TESTED_CLEAN"
    print(f"  ✓ record_target_endpoint succeeded: {res_ep['endpoint']['path']}")

    # 4. TEST GET ATTACK SURFACE GRAPH
    print("\n[MCP TEST 4] get_attack_surface...")
    res_graph_str = await mcp_server.get_attack_surface(project="mcp_test_proj")
    res_graph = json.loads(res_graph_str)
    assert "summary" in res_graph
    assert res_graph["summary"]["total_assets"] >= 1
    assert res_graph["summary"]["total_services"] >= 1
    assert res_graph["summary"]["total_endpoints"] >= 1
    print(f"  ✓ get_attack_surface returned knowledge graph: {res_graph['summary']}")

    # 5. TEST GENERATE OAST TOKEN
    print("\n[MCP TEST 5] generate_oast_token...")
    res_oast_str = await mcp_server.generate_oast_token(
        vuln_type="SSRF",
        description="Verify blind SSRF via webhook parameter",
        project="mcp_test_proj"
    )
    res_oast = json.loads(res_oast_str)
    assert "token" in res_oast
    assert "callback_url" in res_oast
    token = res_oast["token"]
    print(f"  ✓ generate_oast_token generated token: {token}")

    # 6. TEST POLL OAST EVENTS (BEFORE HIT - SHOULD BE EMPTY)
    print("\n[MCP TEST 6] poll_oast_events (before hit)...")
    res_poll_empty_str = await mcp_server.poll_oast_events(token=token, timeout_seconds=1)
    res_poll_empty = json.loads(res_poll_empty_str)
    assert res_poll_empty["callbacks_count"] == 0
    assert res_poll_empty["callback_received"] is False
    print(f"  ✓ poll_oast_events timed out gracefully as expected (0 hits).")

    # Simulate callback
    from backend.oast_engine import record_oast_hit
    record_oast_hit(
        token=token,
        client_ip="203.0.113.42",
        method="POST",
        path=f"/oast/{token}",
        headers={"User-Agent": "curl/7.88.1"},
        body='{"flag": "SSRF_CONFIRMED"}',
        protocol="HTTP",
        project="mcp_test_proj"
    )

    # 7. TEST POLL OAST EVENTS (AFTER HIT - SHOULD CAPTURE EVENT)
    print("\n[MCP TEST 7] poll_oast_events (after hit)...")
    res_poll_hit_str = await mcp_server.poll_oast_events(token=token, timeout_seconds=2)
    res_poll_hit = json.loads(res_poll_hit_str)
    assert res_poll_hit["callbacks_count"] >= 1
    assert res_poll_hit["callback_received"] is True
    hit_event = res_poll_hit["events"][0]
    assert hit_event["client_ip"] == "203.0.113.42"
    assert hit_event["method"] == "POST"
    print(f"  ✓ poll_oast_events verified callback received from {hit_event['client_ip']}!")

    # 8. TEST RUN PENTEST COMMAND WITH OUTPUT_FORMAT="json"
    print("\n[MCP TEST 8] run_pentest_command with output_format='json'...")
    cmd_res_str = await mcp_server.run_pentest_command(
        command="python --version",
        reasoning="Probe Python interpreter version",
        project="mcp_test_proj",
        output_format="json"
    )
    cmd_res = json.loads(cmd_res_str)
    assert "command" in cmd_res
    assert "stdout" in cmd_res or "stderr" in cmd_res
    assert cmd_res["status"] in ["SUCCESS", "FAILED", "BLOCKED"]
    print(f"  ✓ run_pentest_command JSON output validated: status {cmd_res['status']}")

    # 9. TEST SEND_HTTP_REQUEST SCOPE BLOCKED JSON OUTPUT
    print("\n[MCP TEST 9] send_http_request (scope blocked) JSON output...")
    req_res_str = await mcp_server.send_http_request(
        method="GET",
        url="http://127.0.0.1:8000/api/health",
        project="default",
        output_format="json"
    )
    req_res = json.loads(req_res_str)
    assert req_res.get("status") == "blocked"
    assert req_res.get("error") == "SCOPE_GUARD_BLOCKED"
    print(f"  ✓ send_http_request returned clean JSON for blocked request.")

    # 10. TEST SEND_HTTP_REQUEST ALLOWED (HTTP 200) & DIFF BASELINE
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading

    class DummyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "version": "1.0", "data": "target server response"}')
        def log_message(self, format, *args):
            pass

    dummy_server = HTTPServer(("127.0.0.1", 8999), DummyHandler)
    server_thread = threading.Thread(target=dummy_server.serve_forever, daemon=True)
    server_thread.start()

    from backend.database import SessionLocal, Project
    db = SessionLocal()
    proj = db.query(Project).filter(Project.name == "http_test_proj").first()
    if not proj:
        proj = Project(name="http_test_proj", scope_enabled=False, allow_internal_networks=True)
        db.add(proj)
    else:
        proj.scope_enabled = False
        proj.allow_internal_networks = True
    db.commit()
    db.close()
    from backend.intercept_manager import invalidate_scope_cache
    invalidate_scope_cache("http_test_proj")

    print("\n[MCP TEST 10] send_http_request (allowed) HTTP 200 JSON...")
    req2_str = await mcp_server.send_http_request(
        method="GET",
        url="http://127.0.0.1:8999/api/info",
        project="http_test_proj",
        output_format="json"
    )
    req2 = json.loads(req2_str)
    assert req2.get("http_status") == 200
    baseline_id = req2.get("log_id")
    print(f"  ✓ send_http_request HTTP 200 JSON validated (log_id: #{baseline_id}, status: {req2.get('http_status')})")

    print("\n[MCP TEST 11] send_http_request with diff_baseline_id...")
    diff_res_str = await mcp_server.send_http_request(
        method="GET",
        url="http://127.0.0.1:8999/api/info",
        project="http_test_proj",
        diff_baseline_id=baseline_id,
        output_format="json"
    )
    diff_res = json.loads(diff_res_str)
    assert "diff_with_baseline" in diff_res
    print(f"  ✓ send_http_request differential analysis verified against baseline #{baseline_id}")

    dummy_server.shutdown()

    print("\n=== ALL MCP TOOLS TESTS PASSED WITH 0 ERRORS! ===")

if __name__ == "__main__":
    asyncio.run(main())
