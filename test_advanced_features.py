"""
Spectra Test Suite - Advanced Cyber Warfare & Agentic Offensive Capabilities
Tests:
  1. Autonomous Multi-Identity BOLA/IDOR Shadow Matrix
  2. Multi-Protocol OAST Listeners (DNS UDP & LDAP TCP)
  3. Adaptive WAF Evasion & Payload Mutator Engine
  4. Exploit Path Chaining Graph & Kill Chain Synthesizer
  5. Semantic API Spec Reconstructor & Endpoint Inferrer
  6. Standalone One-Click Exploit PoC & Dossier Generator
  7. Advanced MCP Offensive Tools Registration & Execution
"""

import sys
import os
import json
import socket
import asyncio
import unittest

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from backend.database import init_db, SessionLocal, HttpLog, Finding, Project, ActiveSession, OastEvent
from backend.bola_matrix import is_candidate_for_bola, set_identity_session, get_identities_for_project, execute_bola_shadow_replay
from backend.dns_server import start_dns_server, stop_dns_server, get_dns_server_status
from backend.ldap_server import start_ldap_server, stop_ldap_server, get_ldap_server_status
from backend.waf_mutator import analyze_waf_response, mutate_payload
from backend.attack_path import build_attack_path_graph
from backend.api_spec_inferrer import infer_endpoints_from_observed
from backend.poc_generator import generate_finding_dossier, generate_standalone_python_poc, generate_curl_command
from backend.oast_engine import generate_oast_token, poll_oast_events


class TestSpectraAdvancedCapabilities(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_01_bola_candidate_detection(self):
        print("\n[TEST 1] Testing BOLA/IDOR Candidate Detection Logic...")
        # Positive candidates
        self.assertTrue(is_candidate_for_bola("http://target.local/api/users/42", "GET"))
        self.assertTrue(is_candidate_for_bola("http://target.local/api/documents/55/download", "GET"))
        self.assertTrue(is_candidate_for_bola("http://target.local/api/account?user_id=123", "GET"))
        self.assertTrue(is_candidate_for_bola("http://target.local/api/orders?order_uuid=abc-123", "GET"))
        self.assertTrue(is_candidate_for_bola("http://target.local/api/profile", "POST", req_body='{"account_id": 99}'))

        # Negative candidates
        self.assertFalse(is_candidate_for_bola("http://target.local/static/style.css", "GET"))
        self.assertFalse(is_candidate_for_bola("http://target.local/login", "GET"))
        self.assertFalse(is_candidate_for_bola("http://target.local/healthz", "GET"))
        print("  [OK] PASSED: Candidate detection accurately flags object-level identifier requests.")

    def test_02_multi_identity_vault(self):
        print("\n[TEST 2] Testing Multi-Identity Vault...")
        set_identity_session(
            project="test_proj",
            domain="bank.local",
            identity_role="victim",
            raw_cookie_str="auth_token=victim_token_123; user_id=101"
        )
        set_identity_session(
            project="test_proj",
            domain="bank.local",
            identity_role="attacker",
            raw_cookie_str="auth_token=attacker_token_999; user_id=999"
        )

        identities = get_identities_for_project("test_proj", "bank.local")
        self.assertGreaterEqual(len(identities), 2)
        roles = [i["identity_role"] for i in identities]
        self.assertIn("victim", roles)
        self.assertIn("attacker", roles)
        print(f"  [OK] PASSED: Multi-identity sessions registered successfully ({roles}).")

    async def test_03_dns_oast_listener(self):
        print("\n[TEST 3] Testing Multi-Protocol OAST DNS Listener (UDP)...")
        test_port = 5354
        started = await start_dns_server(port=test_port)
        self.assertTrue(started, "DNS server should start on port 5354 or fallback")
        status = get_dns_server_status()
        active_port = status["port"]
        print(f"  - DNS listener active on UDP port {active_port}")

        # Generate unique token
        oast_token = generate_oast_token(project="test_proj", vuln_type="BLIND_SSRF")["token"]

        # Craft raw DNS query for <token>.oast.spectra.local
        domain_query = f"{oast_token}.oast.spectra.local"
        header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for part in domain_query.split("."):
            question += bytes([len(part)]) + part.encode("ascii")
        question += b"\x00"
        question += b"\x00\x01\x00\x01"
        dns_packet = header + question

        # Send packet to DNS listener using loop create_datagram_endpoint
        loop = asyncio.get_running_loop()
        received_event = asyncio.Event()

        class ClientProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
                transport.sendto(dns_packet, ("127.0.0.1", active_port))

            def datagram_received(self, data, addr):
                received_event.set()
                self.transport.close()

        tr, pr = await loop.create_datagram_endpoint(lambda: ClientProtocol(), local_addr=("127.0.0.1", 0))
        try:
            await asyncio.wait_for(received_event.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        # Poll OAST engine for callback hit
        events = await poll_oast_events(oast_token, timeout_seconds=1.5)
        self.assertGreater(len(events), 0)
        self.assertEqual(events[0]["protocol"], "DNS")
        print(f"  [OK] PASSED: DNS query captured and correlated via OAST engine! (Hit: {events[0]['path']})")

        stop_dns_server()

    async def test_04_ldap_oast_listener(self):
        print("\n[TEST 4] Testing Multi-Protocol OAST LDAP / JNDI Listener (TCP)...")
        test_port = 1390
        started = await start_ldap_server(port=test_port)
        self.assertTrue(started, "LDAP server should start on port 1390 or fallback")
        status = get_ldap_server_status()
        active_port = status["port"]
        print(f"  - LDAP listener active on TCP port {active_port}")

        # Generate unique token
        oast_token = generate_oast_token(project="test_proj", vuln_type="JNDI_INJECTION")["token"]

        # Simulate JNDI client connection sending token in LDAP bind payload
        reader, writer = await asyncio.open_connection("127.0.0.1", active_port)
        sample_jndi_payload = f"0\x84\x00\x00\x00(\x02\x01\x01`#\x02\x01\x03\x04\x12{oast_token}\x80\x00".encode("latin-1")
        writer.write(sample_jndi_payload)
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()
        await writer.wait_closed()

        # Poll OAST engine for callback hit
        events = await poll_oast_events(oast_token, timeout_seconds=1.5)
        self.assertGreater(len(events), 0)
        self.assertEqual(events[0]["protocol"], "LDAP")
        print(f"  [OK] PASSED: JNDI/LDAP callback captured and correlated! (Token: {oast_token})")

        stop_ldap_server()

    def test_05_waf_analyzer_and_mutator(self):
        print("\n[TEST 5] Testing Adaptive WAF Analyzer & Payload Mutator...")
        # 1. Fingerprint Cloudflare
        cf_analysis = analyze_waf_response(
            status_code=403,
            headers={"Server": "cloudflare", "cf-ray": "847291a1e0b-SIN"},
            body="<html><title>Attention Required! | Cloudflare</title><body>Error 1020 Access Denied</body></html>"
        )
        self.assertTrue(cf_analysis["waf_detected"])
        self.assertEqual(cf_analysis["vendors"][0]["vendor"], "Cloudflare")
        self.assertTrue(cf_analysis["is_blocked_response"])
        print(f"  - Detected WAF: {cf_analysis['vendors'][0]['vendor']}")

        # 2. Mutate SQLi payload
        raw_sqli = "' UNION SELECT username, password FROM users WHERE id=1--"
        sqli_mutations = mutate_payload(raw_sqli, vuln_type="SQLI")
        self.assertGreaterEqual(sqli_mutations["mutation_count"], 3)
        self.assertIn("evasion_headers", sqli_mutations)
        print(f"  - Generated {sqli_mutations['mutation_count']} evasive SQLi mutations with header spoofing.")

        # 3. Mutate XSS payload
        raw_xss = "<script>alert(1)</script>"
        xss_mutations = mutate_payload(raw_xss, vuln_type="XSS")
        self.assertGreaterEqual(xss_mutations["mutation_count"], 3)
        print("  [OK] PASSED: WAF fingerprinting and mutation synthesis verified.")

    def test_06_semantic_api_inference(self):
        print("\n[TEST 6] Testing Semantic API Spec Reconstructor & Endpoint Inference...")
        from backend.target_manager import add_or_update_endpoint
        add_or_update_endpoint(
            project="test_proj",
            host="app.target.local",
            url="https://app.target.local/api/v1/users/42",
            method="GET"
        )

        inferred = infer_endpoints_from_observed(
            host="app.target.local",
            project="test_proj",
            auto_register_to_graph=True
        )

        self.assertGreater(inferred["inferred_endpoint_count"], 5)
        paths = [p["path"] for p in inferred["predictions"]]
        self.assertIn("/api/v1/users", paths)
        self.assertIn("/swagger.json", paths)
        print(f"  [OK] PASSED: Successfully inferred {inferred['inferred_endpoint_count']} hidden endpoints and registered to attack graph.")

    def test_07_attack_path_kill_chain(self):
        print("\n[TEST 7] Testing Exploit Path Chaining Graph...")
        db = SessionLocal()
        try:
            log = HttpLog(
                project="test_proj",
                method="POST",
                url="https://app.target.local/api/upload",
                host="app.target.local",
                path="/api/upload",
                status_code=200,
                flag_status="CONFIRMED"
            )
            db.add(log)
            db.commit()
            db.refresh(log)

            f = Finding(
                log_id=log.id,
                title="Unauthenticated File Upload to Remote Code Execution (RCE)",
                severity="CRITICAL",
                category="Remote Code Execution",
                evidence="Uploaded webshell.php -> executed whoami -> root"
            )
            db.add(f)
            db.commit()
        finally:
            db.close()

        graph = build_attack_path_graph(project="test_proj")
        self.assertGreater(graph["total_nodes"], 2)
        self.assertGreater(len(graph["chains"]), 0)
        self.assertIn("flowchart LR", graph["mermaid"])
        print(f"  [OK] PASSED: Synthesized {len(graph['chains'])} attack chains leading to Crown Jewels.")
        print(f"  - Target Impact: {graph['chains'][0]['target_impact']}")

    def test_08_poc_generator(self):
        print("\n[TEST 8] Testing One-Click Standalone PoC Generator...")
        db = SessionLocal()
        finding_id = None
        try:
            f = db.query(Finding).join(HttpLog).filter(HttpLog.project == "test_proj").first()
            if f:
                finding_id = f.id
        finally:
            db.close()

        self.assertIsNotNone(finding_id)
        dossier = generate_finding_dossier(finding_id)
        self.assertIsNotNone(dossier)
        self.assertIn("import urllib.request", dossier["python_poc"])
        self.assertIn("curl", dossier["curl_command"])
        self.assertIn("CVSS:3.1", dossier["cvss_vector"])
        print(f"  [OK] PASSED: Standalone Python PoC and cURL command successfully generated.")
        print(f"  - CWE: {dossier['cwe_id']} | CVSS: {dossier['cvss_score']}")

    async def test_09_mcp_tools_execution(self):
        print("\n[TEST 9] Testing MCP Tools Execution (Tools 15-22)...")
        from mcp_server import (
            set_identity_session as mcp_set_identity,
            mutate_payload as mcp_mutate,
            analyze_waf_response as mcp_analyze_waf,
            infer_hidden_endpoints as mcp_infer,
            get_attack_paths as mcp_attack_paths,
            generate_exploit_poc as mcp_poc
        )

        # 1. MCP Set Identity
        res_ident = await mcp_set_identity(domain="test.local", identity_role="attacker", raw_cookies="admin=1")
        self.assertIn("success", res_ident)

        # 2. MCP Mutate Payload
        res_mut = await mcp_mutate(raw_payload="' OR '1'='1", vuln_type="SQLI")
        self.assertIn("mutations", res_mut)

        # 3. MCP Analyze WAF
        res_waf = await mcp_analyze_waf(status_code=403, headers={"server": "cloudflare"}, body="cloudflare error")
        self.assertIn("Cloudflare", res_waf)

        # 4. MCP Infer Endpoints
        res_inf = await mcp_infer(host="app.target.local", project="test_proj")
        self.assertIn("predictions", res_inf)

        # 5. MCP Attack Paths
        res_paths = await mcp_attack_paths(project="test_proj")
        self.assertIn("mermaid", res_paths)

        # 6. MCP PoC Generation
        db = SessionLocal()
        finding_id = None
        try:
            f = db.query(Finding).first()
            if f:
                finding_id = f.id
        finally:
            db.close()

        if finding_id:
            res_poc = await mcp_poc(finding_id=finding_id)
            self.assertIn("python_poc", res_poc)

        print("  [OK] PASSED: All newly registered MCP Offensive Security tools executed cleanly.")


if __name__ == "__main__":
    unittest.main()
