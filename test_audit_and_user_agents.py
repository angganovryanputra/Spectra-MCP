"""
Test Suite: Codebase Audit & Rotating User-Agents Verification
Verifies:
1. Rotating legitimate browser User-Agents and Client Hints.
2. Dual-Track Vulnerability Analyzer enhancements (LFI, Cookie Security, Clickjacking).
3. Parameter Fuzzer (fuzz_endpoint) marker injection and anomaly detection.
4. FastMCP Tool 23: fuzz_endpoint.
"""

import os
import sys
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import unittest

# Ensure current directory is on pythonpath
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from backend.user_agents import (
    get_rotating_user_agent,
    get_browser_headers,
    is_bot_user_agent,
    apply_rotating_user_agent,
    DESKTOP_BROWSER_PROFILES
)
from backend.analyzer import analyze_traffic
from backend.database import HttpLog
from backend.fuzzer import run_fuzz_attack, MARKER_REGEX, replace_markers


class MockFuzzServer(BaseHTTPRequestHandler):
    def do_GET(self):
        query = self.path.split("?")[-1] if "?" in self.path else ""
        if "1=1" in query or "sleep" in query.lower():
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Database Error: You have an error in your SQL syntax near '1=1'")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","items":["alpha","beta"]}')

    def log_message(self, format, *args):
        pass


class TestAuditAndUserAgents(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 8997), MockFuzzServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_rotating_user_agents_diversity_and_client_hints(self):
        print("\n[TEST 1] Verifying Rotating Legitimate Browser User-Agents...")
        seen_uas = set()
        seen_browsers = set()

        for _ in range(50):
            profile = get_rotating_user_agent()
            ua = profile["user_agent"]
            browser = profile["browser"]
            seen_uas.add(ua)
            seen_browsers.add(browser)

            # Ensure all profiles contain legitimate modern browser signatures
            self.assertTrue(any(b in ua for b in ["Chrome", "Safari", "Firefox", "Edg"]))
            # Ensure none contain bot keywords
            self.assertFalse(is_bot_user_agent(ua))

            # Verify Client Hints
            hdrs = get_browser_headers(profile)
            self.assertIn("User-Agent", hdrs)
            if profile.get("sec_ch_ua"):
                self.assertIn("Sec-Ch-Ua", hdrs)
                self.assertIn("Sec-Ch-Ua-Mobile", hdrs)
                self.assertIn("Sec-Ch-Ua-Platform", hdrs)

        # Ensure multiple distinct browsers and UAs are cycled through
        self.assertGreaterEqual(len(seen_browsers), 4)
        self.assertGreaterEqual(len(seen_uas), 5)
        print(f"  [+] Successfully verified {len(seen_uas)} distinct UAs across {len(seen_browsers)} browser families: {list(seen_browsers)}")

    def test_02_bot_user_agent_detection_and_auto_replacement(self):
        print("\n[TEST 2] Verifying Bot Detection & In-Place Replacement...")
        bot_uas = [
            "python-requests/2.31.0",
            "python-httpx/0.27.0",
            "Python-urllib/3.11",
            "curl/7.68.0",
            "Wget/1.20.3",
            "SpectraMCP/1.3 (Autonomous Pentest Agent)",
            "sqlmap/1.5",
            "aiohttp/3.8.4"
        ]
        for bot_ua in bot_uas:
            self.assertTrue(is_bot_user_agent(bot_ua), f"Should flag {bot_ua} as bot")

            headers = {"User-Agent": bot_ua, "Accept": "*/*"}
            updated, rotated = apply_rotating_user_agent(headers)
            self.assertTrue(rotated)
            new_ua = headers["User-Agent"]

            self.assertNotEqual(new_ua, bot_ua)
            self.assertFalse(is_bot_user_agent(new_ua))
            self.assertTrue(any(b in new_ua for b in ["Chrome", "Safari", "Firefox", "Edg"]))

        # Also test with empty headers
        empty_headers = {}
        apply_rotating_user_agent(empty_headers)
        self.assertIn("User-Agent", empty_headers)
        self.assertFalse(is_bot_user_agent(empty_headers["User-Agent"]))
        print("  [+] All bot User-Agents and empty headers automatically sanitized with legitimate desktop browser profiles.")

    def test_03_lfi_deterministic_analysis(self):
        print("\n[TEST 3] Verifying LFI Deterministic Signatures in Analyzer...")

        # Case A: Linux /etc/passwd leak
        passwd_body = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        )
        log_lfi_linux = HttpLog(
            url="http://target.local/view?file=../../../../etc/passwd",
            path="/view",
            status_code=200,
            response_body=passwd_body
        )
        status, findings = analyze_traffic(log_lfi_linux)
        self.assertEqual(status, "CONFIRMED")
        self.assertTrue(any("passwd" in f["title"].lower() for f in findings))
        print(f"  [+] Linux /etc/passwd disclosure correctly confirmed as CRITICAL finding: {findings[0]['title']}")

        # Case B: Windows win.ini leak
        winini_body = "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n"
        log_lfi_win = HttpLog(
            url="http://target.local/download?path=..\\..\\windows\\win.ini",
            path="/download",
            status_code=200,
            response_body=winini_body
        )
        status_win, findings_win = analyze_traffic(log_lfi_win)
        self.assertEqual(status_win, "CONFIRMED")
        self.assertTrue(any("windows" in f["title"].lower() or "ini" in f["title"].lower() for f in findings_win))
        print(f"  [+] Windows win.ini disclosure correctly confirmed as CRITICAL finding: {findings_win[0]['title']}")

    def test_04_cookie_security_and_clickjacking_heuristics(self):
        print("\n[TEST 4] Verifying Cookie Security Flags & Clickjacking Checks...")

        # Case A: Missing HttpOnly and Secure on session cookie
        log_cookie = HttpLog(
            url="http://target.local/api/login",
            path="/api/login",
            status_code=200,
            response_headers=json.dumps({
                "Content-Type": "application/json",
                "Set-Cookie": "session_id=abc123xyz; Path=/"
            }),
            response_body='{"status":"authenticated"}'
        )
        status, findings = analyze_traffic(log_cookie)
        cookie_finding = next((f for f in findings if "Insecure Session Cookie" in f["title"]), None)
        self.assertIsNotNone(cookie_finding)
        self.assertIn("HttpOnly", cookie_finding["title"])
        self.assertIn("Secure", cookie_finding["title"])
        print(f"  [+] Insecure cookie flagged: {cookie_finding['title']}")

        # Case B: Missing Clickjacking protection on HTML page
        log_html = HttpLog(
            url="http://target.local/dashboard",
            path="/dashboard",
            status_code=200,
            response_headers=json.dumps({
                "Content-Type": "text/html; charset=utf-8"
            }),
            response_body="<!DOCTYPE html><html><head><title>Admin Panel</title></head><body>Welcome</body></html>"
        )
        status_html, findings_html = analyze_traffic(log_html)
        clickjack_finding = next((f for f in findings_html if "Clickjacking" in f["title"]), None)
        self.assertIsNotNone(clickjack_finding)
        print(f"  [+] Clickjacking vulnerability flagged: {clickjack_finding['title']}")

    async def test_05_fuzzer_engine_and_anomaly_detection(self):
        print("\n[TEST 5] Verifying Parameter Fuzzer Engine (§...§)...")
        target_url = "http://127.0.0.1:8997/api/products?cat=§shoes§"
        fuzz_results = await run_fuzz_attack(
            base_url=target_url,
            method="GET",
            payloads=["books", "' OR 1=1--", "<script>alert(1)</script>"],
            concurrency=2
        )

        self.assertIn("baseline", fuzz_results)
        self.assertEqual(fuzz_results["baseline"]["status_code"], 200)

        attacks = fuzz_results["results"]
        self.assertEqual(len(attacks), 3)

        # Check that SQLi payload triggered SQL error anomaly
        sqli_attack = next(a for a in attacks if a["payload"] == "' OR 1=1--")
        self.assertEqual(sqli_attack["status_code"], 500)
        self.assertTrue(any("SQL_ERROR_LEAK" in anom for anom in sqli_attack["anomalies"]))
        print("  [+] Parameter Fuzzer accurately executed baseline and flagged SQL injection syntax breakdown.")

    async def test_06_fastmcp_fuzz_endpoint_tool(self):
        print("\n[TEST 6] Verifying FastMCP Tool 23: fuzz_endpoint...")
        from mcp_server import fuzz_endpoint

        res_str = await fuzz_endpoint(
            url="http://127.0.0.1:8997/api/search?q=§test§",
            method="GET",
            payload_type="sqli",
            custom_payloads=["test1", "test2"],
            concurrency=2,
            project="default"
        )
        res_json = json.loads(res_str)
        self.assertIn("baseline", res_json)
        self.assertIn("results", res_json)
        self.assertEqual(len(res_json["results"]), 2)
        print("  [+] FastMCP fuzz_endpoint tool callable and returned structured JSON analysis.")


if __name__ == "__main__":
    unittest.main()
