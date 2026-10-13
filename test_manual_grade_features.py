"""
Test Suite: Manual-Grade Pentesting & Bug Bounty Capabilities Verification
Verifies:
1. Multi-Step Stateful Workflow Sequence Engine (backend/workflow_engine.py & MCP Tool 24).
2. Turbo Race Condition Engine with asyncio.Barrier (backend/race_engine.py & MCP Tool 25).
3. Passive & Active JavaScript Recon & Secret Miner (backend/js_miner.py & MCP Tool 26).
4. Semantic Structural Diffing & Soft-403/404 Heuristics (backend/diff_engine.py & MCP Tool 27).
5. Autonomous JWT Security Audit Suite (backend/jwt_tester.py & MCP Tool 28).
"""

import os
import sys
import json
import time
import hmac
import hashlib
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from backend.workflow_engine import execute_workflow, substitute_variables, extract_value_from_response
from backend.race_engine import run_race_attack
from backend.js_miner import mine_javascript, extract_routes, extract_parameters, extract_secrets, extract_sourcemaps
from backend.diff_engine import clean_dynamic_tokens, detect_soft_errors, compute_semantic_diff
from backend.jwt_tester import (
    parse_jwt, crack_weak_secret, forge_jwt, generate_jwt_attack_variants,
    audit_jwt_security, b64url_encode
)
from mcp_server import (
    execute_workflow_sequence,
    test_race_condition,
    mine_javascript_assets,
    compare_http_responses,
    audit_jwt_security as mcp_audit_jwt_security
)


class MockManualGradeServer(BaseHTTPRequestHandler):
    coupon_claims = 0
    coupon_lock = threading.Lock()

    def do_GET(self):
        if self.path == "/static/app.bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            dummy_slack = "https://" + "hooks." + "slack.com/services/T" + "12345678/B12345678/0123456789abcdef01234567"
            dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
            js_code = f"""
            // Frontend Web Application Bundle
            const API_ROOT = "/api/v2/users";
            function fetchAdminConfig() {{
                return fetch("/api/v2/admin/secret-settings?debug=true&impersonate=admin", {{
                    headers: {{ "X-API-Key": "{dummy_aws}" }}
                }});
            }}
            const slackHook = "{dummy_slack}";
            const hardcodedJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
            //# sourceMappingURL=/static/app.bundle.js.map
            """
            self.wfile.write(js_code.encode("utf-8"))

        elif self.path == "/api/soft-403":
            # HTTP 200 but body indicates Soft-403 Access Denied
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","message":"Access Denied: You do not have permission to view this resource."}')

        elif self.path == "/api/soft-404":
            # HTTP 200 but body indicates Soft-404 Page Not Found
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","message":"Item not found: The requested object does not exist."}')

        elif self.path == "/api/protected-dashboard":
            auth = self.headers.get("Authorization", "")
            if "Bearer " in auth:
                token = auth.split("Bearer ")[-1].strip()
                try:
                    parsed = parse_jwt(token)
                    alg = (parsed.get("header", {}).get("alg") or "").lower()
                    if alg == "none":
                        # Vulnerable to alg: none!
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status":"authenticated","role":"admin","secret_data":"FLAG{JWT_NONE_BYPASS}"}')
                        return
                    elif alg == "hs256":
                        calc = hmac.new(b"secret", parsed["signing_input"].encode("utf-8"), hashlib.sha256).digest()
                        if hmac.compare_digest(parsed["signature_bytes"], calc):
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status":"authenticated","role":"user","data":"regular_content"}')
                            return
                except Exception:
                    pass
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"Unauthorized"}')

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""

        if self.path == "/api/cart":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Workflow-Token", "wf-token-998877")
            self.end_headers()
            self.wfile.write(b'{"status":"cart_created","data":{"order_id":"ORD-445566"}}')

        elif self.path == "/api/checkout":
            token = self.headers.get("X-Workflow-Token", "")
            if "wf-token-998877" in token:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"checkout_approved","invoice_id":"INV-1122"}')
            else:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"error":"Missing workflow token"}')

        elif self.path == "/api/pay":
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            # If order_id is present, payment succeeds!
            if data.get("order_id") == "ORD-445566":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"success","paid":true}')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"Invalid order ID"}')

        elif self.path == "/api/coupon/claim":
            # Simulate a race condition where multiple concurrent requests succeed before lock/delay
            with self.coupon_lock:
                MockManualGradeServer.coupon_claims += 1
                current = MockManualGradeServer.coupon_claims

            if current <= 5:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "coupon_applied", "claim_number": current}).encode("utf-8"))
            else:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"Coupon already fully claimed"}')

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class TestManualGradeFeatures(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = 8996
        cls.server = HTTPServer(("127.0.0.1", cls.port), MockManualGradeServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    def setUp(self):
        MockManualGradeServer.coupon_claims = 0

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    async def test_01_workflow_engine_execution_and_step_skipping(self):
        """Test Multi-Step Workflow Engine: variable interpolation, token extraction, and step skip bypass detection."""
        print("\n[TEST 1] Verifying Multi-Step Workflow Engine...")
        base = f"http://127.0.0.1:{self.port}"

        sequence = [
            {
                "name": "Create Cart",
                "method": "POST",
                "url": f"{base}/api/cart",
                "extract": {
                    "order_id": "json.data.order_id",
                    "wf_token": "header.x-workflow-token"
                }
            },
            {
                "name": "Checkout Stage",
                "method": "POST",
                "url": f"{base}/api/checkout",
                "headers": {
                    "X-Workflow-Token": "{{wf_token}}"
                },
                "extract": {
                    "invoice": "json.invoice_id"
                }
            },
            {
                "name": "Execute Payment",
                "method": "POST",
                "url": f"{base}/api/pay",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({"order_id": "{{order_id}}", "invoice": "{{invoice}}"})
            }
        ]

        result = await execute_workflow(
            sequence=sequence,
            initial_context={"user": "attacker"},
            project="default",
            test_step_skipping=True
        )

        self.assertTrue(result["all_steps_succeeded"], f"Expected all steps to succeed: {result}")
        self.assertEqual(result["context_extracted"].get("order_id"), "ORD-445566")
        self.assertEqual(result["context_extracted"].get("wf_token"), "wf-token-998877")
        self.assertEqual(result["context_extracted"].get("invoice"), "INV-1122")
        self.assertEqual(len(result["step_results"]), 3)
        print("  [+] Multi-step sequential execution with dynamic token chaining passed.")

        # Check step-skipping detection
        skip_tests = result.get("step_skip_tests", [])
        self.assertTrue(len(skip_tests) > 0, "Step skip tests should have executed.")
        # Step 2 was skipped (Step 1 -> Step 3 directly). Since Step 3 only requires order_id, it succeeded!
        bypass_confirmed = any(t.get("potential_logic_bypass") for t in skip_tests)
        self.assertTrue(bypass_confirmed, "Step skipping should have detected business logic bypass.")
        print("  [+] Business logic step-skipping bypass detection verified.")

    async def test_02_turbo_race_condition_engine(self):
        """Test Turbo Race Condition Engine: Barrier synchronization and concurrent burst dispatch."""
        print("\n[TEST 2] Verifying Turbo Race Condition Engine...")
        target_url = f"http://127.0.0.1:{self.port}/api/coupon/claim"

        result = await run_race_attack(
            url=target_url,
            method="POST",
            body="{}",
            concurrency=10
        )

        self.assertEqual(result["concurrency"], 10)
        self.assertEqual(result["total_sent"], 10)
        self.assertIn("POTENTIAL_RACE_CONDITION", result["verdict"])
        self.assertGreater(result["status_distribution"].get("200", 0), 1)
        print(f"  [+] Race burst finished in {result['burst_duration_ms']:.2f}ms. Status distribution: {result['status_distribution']}")

    async def test_03_javascript_recon_and_secret_miner(self):
        """Test JavaScript Recon & Secret Miner: AST/regex endpoint, query param, and secret extraction."""
        print("\n[TEST 3] Verifying JavaScript Recon & Secret Miner...")
        target_js_url = f"http://127.0.0.1:{self.port}/static/app.bundle.js"

        res = await mine_javascript(
            content_or_url=target_js_url,
            auto_register=False,
            project="default"
        )

        self.assertIn("/api/v2/users", res["endpoints_found"])
        self.assertIn("/api/v2/admin/secret-settings", res["endpoints_found"])
        self.assertIn("debug", res["parameters_found"])
        self.assertIn("impersonate", res["parameters_found"])

        secrets = res["secrets_leaked"]
        titles = [s["title"] for s in secrets]
        self.assertIn("AWS Access Key ID Exposure", titles)
        self.assertIn("Hardcoded JWT Token", titles)
        self.assertIn("Slack Webhook URL Exposure", titles)

        sourcemaps = res["sourcemaps"]
        self.assertTrue(any(".map" in sm for sm in sourcemaps))
        print(f"  [+] Discovered {len(res['endpoints_found'])} endpoints, {len(res['parameters_found'])} params, {len(secrets)} secrets, {len(sourcemaps)} sourcemaps.")

    def test_04_diff_engine_noise_reduction_and_soft_errors(self):
        """Test Semantic Diffing Engine: Volatile token stripping and Soft-403/404 heuristics."""
        print("\n[TEST 4] Verifying Semantic Structural Diffing Engine...")

        # 1. Noise cleaning
        noisy_text = '{"timestamp":"2026-10-13T09:23:29.123Z","uuid":"123e4567-e89b-12d3-a456-426614174000","csrf_token":"a1b2c3d4e5f6g7h8","user":"alice"}'
        cleaned = clean_dynamic_tokens(noisy_text)
        self.assertNotIn("2026-10-13T09:23:29.123Z", cleaned)
        self.assertIn("<TIMESTAMP>", cleaned)
        self.assertIn("<UUID>", cleaned)
        self.assertIn("<CSRF>", cleaned)
        print("  [+] Dynamic timestamp, UUID, and CSRF token stripping verified.")

        # 2. Soft-403 heuristic
        soft_403 = detect_soft_errors(200, '{"message":"Access Denied: You do not have permission"}')
        self.assertTrue(soft_403["is_soft_403"])
        self.assertFalse(soft_403["is_soft_404"])

        # 3. Soft-404 heuristic
        soft_404 = detect_soft_errors(200, '{"message":"Item not found: 404 not found"}')
        self.assertTrue(soft_404["is_soft_404"])
        self.assertFalse(soft_404["is_soft_403"])

        # 4. Semantic diffing
        resp_a = {"status_code": 200, "body": '{"time":"2026-10-13T09:00:00Z","user":"alice"}'}
        resp_b = {"status_code": 200, "body": '{"time":"2026-10-13T09:05:00Z","user":"alice"}'}
        diff = compute_semantic_diff(resp_a, resp_b)
        self.assertEqual(diff["normalized_similarity_ratio"], 1.0)
        self.assertFalse(diff["is_substantively_different"])
        print("  [+] Noise normalization yielded 100% normalized similarity across dynamic timestamps.")

    async def test_05_jwt_security_audit_suite(self):
        """Test Autonomous JWT Audit Suite: Alg-none, weak secret cracking, claim tampering, and live replay."""
        print("\n[TEST 5] Verifying Autonomous JWT Audit Suite...")

        # Craft baseline token signed with weak secret "secret"
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "12345", "role": "user", "name": "Alice"}
        raw_token = forge_jwt(header, payload, secret="secret")

        # Offline dictionary cracking
        cracked = crack_weak_secret(raw_token)
        self.assertIsNotNone(cracked)
        self.assertEqual(cracked[0], "secret")
        print("  [+] Offline dictionary cracking successfully recovered weak secret 'secret'.")

        # Live replay against protected dashboard
        protected_url = f"http://127.0.0.1:{self.port}/api/protected-dashboard"
        report = await audit_jwt_security(
            token=raw_token,
            test_url=protected_url,
            method="GET"
        )

        self.assertEqual(report["weak_secret_cracked"], "secret")
        finding_titles = [f["title"] for f in report["findings"]]
        self.assertIn("JWT Weak HMAC Secret Key Exposure", finding_titles)
        self.assertIn("JWT Signature Verification Bypass (Algorithm None Flaw)", finding_titles)
        print(f"  [+] Live replay confirmed JWT algorithm none bypass vulnerability against target.")

    async def test_06_fastmcp_tools_24_to_28(self):
        """Test FastMCP Tools 24-28 exposed in mcp_server.py."""
        print("\n[TEST 6] Verifying FastMCP Tools 24-28...")
        base = f"http://127.0.0.1:{self.port}"

        # FastMCP Tool 24: execute_workflow_sequence
        seq = [
            {"name": "Init", "url": f"{base}/api/cart", "method": "POST", "extract": {"oid": "json.data.order_id"}}
        ]
        res_tool24 = await execute_workflow_sequence(sequence=seq)
        data24 = json.loads(res_tool24)
        self.assertTrue(data24["all_steps_succeeded"])
        print("  [+] FastMCP Tool 24 (execute_workflow_sequence) callable and returned valid JSON.")

        # FastMCP Tool 25: test_race_condition
        res_tool25 = await test_race_condition(url=f"{base}/api/coupon/claim", concurrency=5)
        data25 = json.loads(res_tool25)
        self.assertEqual(data25["concurrency"], 5)
        print("  [+] FastMCP Tool 25 (test_race_condition) callable and returned valid JSON.")

        # FastMCP Tool 26: mine_javascript_assets
        res_tool26 = await mine_javascript_assets(content_or_url=f"{base}/static/app.bundle.js", auto_register=False)
        data26 = json.loads(res_tool26)
        self.assertIn("/api/v2/users", data26["endpoints_found"])
        print("  [+] FastMCP Tool 26 (mine_javascript_assets) callable and returned valid JSON.")

        # FastMCP Tool 27: compare_http_responses
        res_tool27 = await compare_http_responses(
            response_a={"status_code": 200, "body": "Alpha"},
            response_b={"status_code": 200, "body": "Alpha"}
        )
        data27 = json.loads(res_tool27)
        self.assertEqual(data27["normalized_similarity_ratio"], 1.0)
        print("  [+] FastMCP Tool 27 (compare_http_responses) callable and returned valid JSON.")

        # FastMCP Tool 28: audit_jwt_security
        token = forge_jwt({"alg": "HS256"}, {"user": "bob"}, secret="password")
        res_tool28 = await mcp_audit_jwt_security(token=token)
        data28 = json.loads(res_tool28)
        self.assertEqual(data28["weak_secret_cracked"], "password")
        print("  [+] FastMCP Tool 28 (audit_jwt_security) callable and returned valid JSON.")


if __name__ == "__main__":
    unittest.main()
