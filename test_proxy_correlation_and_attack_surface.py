"""
Test Suite: Spectra Proxy History Correlation & Attack Surface Deletion
Tests:
1. Attack Surface CRUD & Deletion (Assets, Services, Endpoints, and Project Clear).
2. FastMCP Tools 29 & 30 (delete_attack_surface_node, clear_attack_surface_graph).
3. auto_ingest_url_to_target_graph port resolution verification.
4. run_pentest_command automatic proxy startup and traffic correlation into HttpLog.
5. Multi-Tool Traffic Correlation (Workflow Engine, Race Engine, JWT Tester, Fuzzer -> HttpLog).
"""

import os
import sys
import json
import time
import asyncio
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

import mcp_server
from backend.database import SessionLocal, HttpLog, TargetAsset, TargetService, TargetEndpoint, Project
from backend.target_manager import (
    upsert_target_asset,
    add_or_update_service,
    add_or_update_endpoint,
    get_attack_surface_graph,
    delete_target_asset,
    delete_target_endpoint,
    delete_target_service,
    clear_target_graph,
    auto_ingest_url_to_target_graph
)
from backend.forward_proxy import ensure_forward_proxy_running, stop_forward_proxy, _dispatch_log


class MockTargetServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","message":"Target server responded"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "received", "echo": body}).encode("utf-8"))

    def log_message(self, format, *args):
        pass


class TestProxyCorrelationAndAttackSurface(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.target_port = 8998
        cls.server = HTTPServer(("127.0.0.1", cls.target_port), MockTargetServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    async def test_01_attack_surface_deletion_features(self):
        """Test attack surface deletion of endpoints, services, assets, and project clear."""
        print("\n[TEST 1] Verifying Attack Surface Deletion Features...")
        proj = "test_del_proj"

        # 1. Create target asset, service, and endpoint
        asset = upsert_target_asset(project=proj, host="api.corp.local", ip="10.0.0.50", os_info="Linux")
        self.assertEqual(asset["host"], "api.corp.local")

        svc = add_or_update_service(project=proj, host="api.corp.local", port=8080, service_name="http-alt")
        self.assertEqual(svc["port"], 8080)

        ep1 = add_or_update_endpoint(project=proj, host="api.corp.local", url="http://api.corp.local:8080/v1/auth", method="POST")
        ep2 = add_or_update_endpoint(project=proj, host="api.corp.local", url="http://api.corp.local:8080/v1/users", method="GET")

        graph = get_attack_surface_graph(project=proj)
        self.assertEqual(graph["summary"]["total_assets"], 1)
        self.assertEqual(graph["summary"]["total_endpoints"], 2)
        print("  [+] Assets, services, and endpoints successfully seeded.")

        # 2. Delete single endpoint
        del_ep_ok = delete_target_endpoint(ep1["id"], project=proj)
        self.assertTrue(del_ep_ok)
        graph_after_ep = get_attack_surface_graph(project=proj)
        self.assertEqual(graph_after_ep["summary"]["total_endpoints"], 1)
        print("  [+] Single endpoint deleted successfully.")

        # 3. Delete single service
        del_svc_ok = delete_target_service(svc["id"], project=proj)
        self.assertTrue(del_svc_ok)
        graph_after_svc = get_attack_surface_graph(project=proj)
        self.assertEqual(graph_after_svc["summary"]["total_services"], 0)
        print("  [+] Single service deleted successfully.")

        # 4. Delete asset (and all cascading remaining endpoints)
        del_asset_ok = delete_target_asset(asset["id"], project=proj)
        self.assertTrue(del_asset_ok)
        graph_after_asset = get_attack_surface_graph(project=proj)
        self.assertEqual(graph_after_asset["summary"]["total_assets"], 0)
        self.assertEqual(graph_after_asset["summary"]["total_endpoints"], 0)
        print("  [+] Asset cascade deletion verified.")

        # 5. Clear project attack surface
        upsert_target_asset(project=proj, host="sub1.corp.local")
        upsert_target_asset(project=proj, host="sub2.corp.local")
        cleared_count = clear_target_graph(project=proj)
        self.assertEqual(cleared_count, 2)
        graph_empty = get_attack_surface_graph(project=proj)
        self.assertEqual(graph_empty["summary"]["total_assets"], 0)
        print("  [+] Full project attack surface clear verified.")

    async def test_02_fastmcp_tools_29_and_30(self):
        """Test FastMCP Tool 29 (delete_attack_surface_node) and Tool 30 (clear_attack_surface_graph)."""
        print("\n[TEST 2] Verifying FastMCP Tools 29 & 30...")
        proj = "test_mcp_del_proj"

        asset = upsert_target_asset(project=proj, host="node1.internal.local")
        ep = add_or_update_endpoint(project=proj, host="node1.internal.local", url="http://node1.internal.local/health", method="GET")

        # Call Tool 29: delete endpoint
        del_ep_res = await mcp_server.delete_attack_surface_node(
            node_type="endpoint",
            node_id=ep["id"],
            project=proj
        )
        data = json.loads(del_ep_res)
        self.assertEqual(data["status"], "deleted")
        self.assertEqual(data["node_type"], "endpoint")
        print("  [+] FastMCP Tool 29 (delete_attack_surface_node: endpoint) verified.")

        # Call Tool 29: delete asset
        del_asset_res = await mcp_server.delete_attack_surface_node(
            node_type="asset",
            node_id=asset["id"],
            project=proj
        )
        data_a = json.loads(del_asset_res)
        self.assertEqual(data_a["status"], "deleted")
        self.assertEqual(data_a["node_type"], "asset")
        print("  [+] FastMCP Tool 29 (delete_attack_surface_node: asset) verified.")

        # Seed and call Tool 30: clear attack surface
        upsert_target_asset(project=proj, host="clear1.local")
        clear_res = await mcp_server.clear_attack_surface_graph(project=proj)
        clear_data = json.loads(clear_res)
        self.assertEqual(clear_data["status"], "cleared")
        self.assertEqual(clear_data["deleted_assets"], 1)
        print("  [+] FastMCP Tool 30 (clear_attack_surface_graph) verified.")

    async def test_03_auto_ingest_url_to_target_graph_fix(self):
        """Test that auto_ingest_url_to_target_graph correctly resolves port without UnboundLocalError."""
        print("\n[TEST 3] Verifying auto_ingest_url_to_target_graph port resolution...")
        proj = "test_ingest_proj"
        test_url = f"http://127.0.0.1:{self.target_port}/api/v1/resource?id=123"

        # Call auto_ingest
        auto_ingest_url_to_target_graph(proj, test_url, "GET")

        graph = get_attack_surface_graph(project=proj)
        self.assertGreaterEqual(graph["summary"]["total_assets"], 1)
        self.assertGreaterEqual(graph["summary"]["total_endpoints"], 1)
        print(f"  [+] Ingested successfully into attack surface: {graph['summary']}")

    async def test_04_run_pentest_command_proxy_and_history_correlation(self):
        """Test that run_pentest_command guarantees proxy readiness and routes traffic into Proxy History."""
        print("\n[TEST 4] Verifying run_pentest_command and Proxy History correlation...")
        proj = "test_cmd_proxy_proj"

        # Ensure database project exists
        db = SessionLocal()
        try:
            p = db.query(Project).filter(Project.name == proj).first()
            if not p:
                db.add(Project(name=proj, description="Test project"))
                db.commit()
        finally:
            db.close()

        # Execute a Python script via run_pentest_command that makes an HTTP request
        target_url = f"http://127.0.0.1:{self.target_port}/api/from-pentest-command"
        cmd = f"python -c \"import urllib.request; resp=urllib.request.urlopen('{target_url}', timeout=5); print('HTTP_STATUS:' + str(resp.status))\""

        res_json = await mcp_server.run_pentest_command(
            command=cmd,
            project=proj,
            agent_id="agent_recon_1",
            reasoning="Testing command proxy history capture"
        )
        res_data = json.loads(res_json)
        self.assertEqual(res_data["status"], "SUCCESS", f"Command failed: {res_data}")
        self.assertIn("HTTP_STATUS:200", res_data["stdout"])
        print(f"  [+] Command executed cleanly. Exit code: {res_data['exit_code']}")

        # Verify that the traffic was recorded in HttpLog with project=proj!
        time.sleep(0.3)
        db = SessionLocal()
        try:
            logs = db.query(HttpLog).filter(
                HttpLog.project == proj,
                HttpLog.url == target_url
            ).all()
            self.assertTrue(len(logs) > 0, f"Expected request to {target_url} to be logged in HttpLog for project '{proj}'")
            print(f"  [+] Confirmed! {len(logs)} request(s) captured into Proxy History (HttpLog id={logs[0].id}, source={logs[0].source}).")
        finally:
            db.close()

    async def test_05_multi_tool_traffic_correlation(self):
        """Test that workflow, race, and jwt audit tools dispatch their traffic to HttpLog."""
        print("\n[TEST 5] Verifying Workflow Engine, Race Engine, and JWT Tester traffic logging...")
        proj = "test_tool_corr_proj"

        # 1. Workflow Engine
        from backend.workflow_engine import execute_workflow
        wf_res = await execute_workflow(
            sequence=[
                {"name": "Step A", "method": "GET", "url": f"http://127.0.0.1:{self.target_port}/api/stepA"}
            ],
            project=proj,
            agent_id="wf_agent"
        )
        self.assertTrue(wf_res["all_steps_succeeded"])

        # 2. Race Engine
        from backend.race_engine import run_race_attack
        race_res = await run_race_attack(
            url=f"http://127.0.0.1:{self.target_port}/api/race-claim",
            concurrency=4,
            project=proj,
            agent_id="race_agent"
        )
        self.assertEqual(race_res["status"], "COMPLETED")

        # 3. JWT Tester
        from backend.jwt_tester import audit_jwt_security
        token_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        jwt_res = await audit_jwt_security(
            token=token_sample,
            test_url=f"http://127.0.0.1:{self.target_port}/api/jwt-auth",
            project=proj,
            agent_id="jwt_agent"
        )
        self.assertIn("live_replay_results", jwt_res)

        # Check database HttpLog
        time.sleep(0.3)
        db = SessionLocal()
        try:
            wf_logs = db.query(HttpLog).filter(HttpLog.project == proj, HttpLog.source == "WORKFLOW_ENGINE").all()
            race_logs = db.query(HttpLog).filter(HttpLog.project == proj, HttpLog.source == "RACE_ENGINE").all()
            jwt_logs = db.query(HttpLog).filter(HttpLog.project == proj, HttpLog.source == "JWT_AUDIT").all()

            self.assertGreater(len(wf_logs), 0, "Workflow requests must be recorded in HttpLog")
            self.assertGreater(len(race_logs), 0, "Race burst requests must be recorded in HttpLog")
            self.assertGreater(len(jwt_logs), 0, "JWT live audit requests must be recorded in HttpLog")
            print(f"  [+] Verified HttpLog records: Workflow={len(wf_logs)}, Race={len(race_logs)}, JWT={len(jwt_logs)}")
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
