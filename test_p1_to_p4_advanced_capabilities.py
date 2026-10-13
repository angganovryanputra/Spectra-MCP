"""
Test Suite: Spectra P1-P4 Advanced AI Offensive Capabilities
Tests:
1. P1: LLM Semantic Response Body Distiller (HTML & JSON token compaction, forms, and reflections).
2. P2: Autonomous Out-of-Band (OAST) Canary Sprayer.
3. P3: Agent Working Memory & Hypothesis Ledger.
4. P4: Browser DOM Execution Oracle Sandbox (Headless Chromium alert verification).
5. FastMCP Tools 32-37 Execution.
"""

import os
import json
import time
import asyncio
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

from backend.database import init_db, SessionLocal, HttpLog, Project, TestingHypothesis
from backend.body_distiller import distill_response_body
from backend.oast_sprayer import spray_oast_canaries
from backend.hypothesis_manager import (
    create_hypothesis,
    list_hypotheses,
    update_hypothesis,
    delete_hypothesis,
    get_testing_agenda
)
from backend.browser_oracle import verify_dom_execution
import mcp_server


class MockOracleAndOastServer(BaseHTTPRequestHandler):
    def do_GET(self):
        import urllib.parse
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        # If q contains alert(1), output page with executable script
        if "q" in qs and "alert" in qs["q"][0]:
            payload = qs["q"][0]
            html = f"<html><head><title>Test Oracle</title></head><body><h1>Reflected</h1><script>{payload}</script></body></html>"
            self.wfile.write(html.encode("utf-8"))
        elif "test_canary" in qs or "param" in qs or "id" in qs:
            self.wfile.write(b'{"status":"received_canary"}')
        else:
            self.wfile.write(b"<html><head><title>OK</title></head><body>Hello</body></html>")

    def log_message(self, format, *args):
        pass


class TestP1ToP4Capabilities(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.port = 8995
        cls.server = HTTPServer(("127.0.0.1", cls.port), MockOracleAndOastServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_body_distiller_html(self):
        """P1: Verify HTML distillation extracts forms, inputs, endpoints, comments, and reflections."""
        print("\n[TEST 1] Testing P1: HTML Response Body Distiller...")
        sample_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Portal - Dashboard</title>
            <style>.bg { color: red; } /* Huge CSS boilerplate */</style>
            <script src="/static/analytics.js"></script>
        </head>
        <body>
            <svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" /></svg>
            <!-- TODO: internal secret key is sec_test_9999 for staging -->
            <form action="/api/v1/login" method="POST">
                <input type="text" name="username" value="admin" />
                <input type="password" name="password" placeholder="Password" />
                <input type="hidden" name="csrf_token" value="abc123nonce" />
                <button type="submit">Sign In</button>
            </form>
            <a href="/api/v1/users?role=admin">View Admin Users</a>
            <div class="banner">Search query: <span class="highlight">test_payload_val</span></div>
        </body>
        </html>
        """
        distilled = distill_response_body(
            body=sample_html,
            content_type="text/html",
            reflected_query="test_payload_val"
        )
        self.assertEqual(distilled["content_type"], "html")
        self.assertGreater(distilled["forms_count"], 0)
        self.assertGreater(distilled["endpoints_count"], 0)
        self.assertIn("/api/v1/login", distilled["compact_summary"])
        self.assertIn("username", distilled["compact_summary"])
        self.assertIn("password", distilled["compact_summary"])
        self.assertIn("sec_test_9999", str(distilled["comments"]))
        self.assertGreater(len(distilled["reflections"]), 0)
        print(f"  [+] HTML Distillation successful! Original: {distilled['original_size']} bytes -> Distilled: {distilled['distilled_size']} bytes ({distilled['token_reduction_percent']}% reduction)")

    def test_02_body_distiller_json(self):
        """P1: Verify JSON distillation summarizes deep structures and highlights high-value keys."""
        print("\n[TEST 2] Testing P1: JSON API Response Body Distiller...")
        huge_json = json.dumps([
            {"id": i, "user_id": f"usr_{i}", "email": f"user{i}@example.com", "role": "member", "jwt_token": f"token_{i}", "data": {"meta": "val"}}
            for i in range(50)
        ])
        distilled = distill_response_body(body=huge_json, content_type="application/json")
        self.assertEqual(distilled["content_type"], "json")
        self.assertIn("jwt", distilled["sensitive_indicators"])
        self.assertIn("high-value identifier", distilled["compact_summary"])
        self.assertGreater(distilled["token_reduction_percent"], 50.0)
        print(f"  [+] JSON Distillation successful! Token reduction: {distilled['token_reduction_percent']}%")

    async def test_03_oast_canary_spraying(self):
        """P2: Verify autonomous OAST canary spraying across target parameters."""
        print("\n[TEST 3] Testing P2: Autonomous OAST Canary Sprayer...")
        proj = "test_oast_spray_proj"
        target_url = f"http://127.0.0.1:{self.port}/api/endpoint?id=1&redirect=http://google.com"

        res = await spray_oast_canaries(
            target_url=target_url,
            method="GET",
            vuln_types=["ssrf", "dns", "log4j"],
            project=proj,
            agent_id="canary_agent"
        )
        self.assertEqual(res["status"], "COMPLETED")
        self.assertGreaterEqual(res["total_canaries_sprayed"], 4)
        self.assertIn("id", res["parameters_tested"])
        self.assertIn("redirect", res["parameters_tested"])

        # Check HttpLog correlation
        time.sleep(0.3)
        db = SessionLocal()
        try:
            logs = db.query(HttpLog).filter(HttpLog.project == proj, HttpLog.source == "OAST_SPRAYER").all()
            self.assertGreater(len(logs), 0, "OAST canary requests must be logged to HttpLog")
            print(f"  [+] Sprayed {res['total_canaries_sprayed']} canaries successfully. Correlated {len(logs)} HttpLog entries.")
        finally:
            db.close()

    def test_04_agent_hypothesis_working_memory(self):
        """P3: Verify persistent Agent Hypothesis Ledger and Agenda tracking."""
        print("\n[TEST 4] Testing P3: Agent Working Memory & Hypothesis Ledger...")
        proj = "test_hypothesis_proj"

        # 0. Clean prior state
        db = SessionLocal()
        try:
            db.query(TestingHypothesis).filter(TestingHypothesis.project == proj).delete()
            db.commit()
        finally:
            db.close()

        # 1. Create hypotheses
        h1 = create_hypothesis(
            project=proj,
            target="/api/users/profile",
            vuln_type="BOLA",
            hypothesis="Endpoint accepts id parameter in JSON body; test tampering with victim ID",
            status="PLANNED",
            evidence_notes="Observed response returns full PII"
        )
        self.assertIsNotNone(h1["id"])
        self.assertEqual(h1["status"], "PLANNED")

        h2 = create_hypothesis(
            project=proj,
            target="/api/orders/export",
            vuln_type="SSRF",
            hypothesis="Export parameter accepts callback URL; test cloud metadata 169.254.169.254",
            status="TESTING"
        )

        # 2. List & Get Agenda
        agenda = get_testing_agenda(project=proj)
        self.assertEqual(agenda["total_hypotheses"], 2)
        self.assertEqual(agenda["planned_count"], 1)
        self.assertEqual(agenda["in_progress_count"], 1)

        # 3. Update status to CONFIRMED
        up = update_hypothesis(
            hypothesis_id=h1["id"],
            status="CONFIRMED",
            evidence_notes="Horizontal privilege escalation verified; accessed admin order #412",
            project=proj
        )
        self.assertEqual(up["status"], "CONFIRMED")

        # 4. Delete hypothesis
        deleted = delete_hypothesis(hypothesis_id=h2["id"], project=proj)
        self.assertTrue(deleted)

        remaining = list_hypotheses(project=proj)
        self.assertEqual(len(remaining), 1)
        print("  [+] Agent Working Memory CRUD, state transitions, and agenda synthesis verified.")

    async def test_05_browser_dom_oracle(self):
        """P4: Verify Browser DOM Execution Oracle Sandbox catches alerts in Chromium."""
        print("\n[TEST 5] Testing P4: Browser DOM Execution Oracle Sandbox...")
        target_url = f"http://127.0.0.1:{self.port}/test-oracle"

        # 1. Test XSS execution via param injection
        res = await verify_dom_execution(
            url=target_url,
            payload="alert('spectra_pwned_1337')",
            param_name="q",
            wait_timeout_ms=3000
        )
        self.assertTrue(res["execution_confirmed"])
        self.assertEqual(res["verdict"], "CONFIRMED_VULNERABLE_DOM_EXECUTION")
        self.assertEqual(res["dialog_events"][0]["message"], "spectra_pwned_1337")
        print(f"  [+] DOM Execution Verified deterministically! Event: {res['dialog_events'][0]}")

        # 2. Test benign non-executing page
        benign_res = await verify_dom_execution(
            url=f"http://127.0.0.1:{self.port}/benign",
            wait_timeout_ms=2000
        )
        self.assertFalse(benign_res["execution_confirmed"])
        self.assertEqual(benign_res["verdict"], "NO_DOM_EXECUTION")
        print("  [+] Benign page correctly evaluated as NO_DOM_EXECUTION.")

    async def test_06_fastmcp_tools_32_to_37(self):
        """Verify FastMCP Tools 32 to 37 are callable and return structured JSON."""
        print("\n[TEST 6] Testing FastMCP Tools 32-37 Execution...")

        db = SessionLocal()
        try:
            db.query(TestingHypothesis).filter(TestingHypothesis.project == "test_mcp_hyp").delete()
            db.commit()
        finally:
            db.close()

        # Tool 32: distill_http_response
        t32 = await mcp_server.distill_http_response(
            body="<html><form action='/login'><input name='u'/></form></html>"
        )
        self.assertIn("compact_summary", json.loads(t32))
        print("  [+] FastMCP Tool 32 (distill_http_response) verified.")

        # Tool 34: record_testing_hypothesis
        t34 = await mcp_server.record_testing_hypothesis(
            target="/api/cart/checkout",
            vuln_type="RACE",
            hypothesis="Double-spend coupon via concurrent requests",
            project="test_mcp_hyp"
        )
        t34_data = json.loads(t34)
        hyp_id = t34_data["hypothesis"]["id"]
        print("  [+] FastMCP Tool 34 (record_testing_hypothesis) verified.")

        # Tool 35: get_testing_agenda
        t35 = await mcp_server.get_testing_agenda(project="test_mcp_hyp")
        self.assertGreater(json.loads(t35)["total_hypotheses"], 0)
        print("  [+] FastMCP Tool 35 (get_testing_agenda) verified.")

        # Tool 36: update_hypothesis_status
        t36 = await mcp_server.update_hypothesis_status(
            hypothesis_id=hyp_id,
            status="TESTING",
            project="test_mcp_hyp"
        )
        self.assertEqual(json.loads(t36)["hypothesis"]["status"], "TESTING")
        print("  [+] FastMCP Tool 36 (update_hypothesis_status) verified.")

        # Tool 37: verify_dom_execution
        t37 = await mcp_server.verify_dom_execution(
            url=f"http://127.0.0.1:{self.port}/oracle?q=alert(1337)"
        )
        self.assertTrue(json.loads(t37)["execution_confirmed"])
        print("  [+] FastMCP Tool 37 (verify_dom_execution) verified.")


if __name__ == "__main__":
    unittest.main()
