"""
Spectra MCP - Security Testing Gateway & Observability Platform
Model Context Protocol (MCP) Server Entrypoint (Stdio & SSE Transport)
Features: Scope Guardrails, Interactive Intercept Proxy Trap, AI Reasoning Correlation, & Multi-Project Isolation.
"""

import os
import sys
import json
import time
import asyncio
import urllib.parse
from typing import Optional, Dict, Any
import httpx

try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        from mcp.server import Server as FastMCP

# Ensure current directory is on pythonpath
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from backend.database import init_db, SessionLocal, ActiveSession, HttpLog, Finding, Project, AgentCommandLog, CapturedPayload
from backend.analyzer import analyze_traffic
from backend.browser_handler import render_page, spawn_interactive_login
from backend.intercept_manager import (
    is_intercept_enabled,
    create_intercept_trap,
    pop_intercept_result,
    check_scope
)
from backend.security_utils import check_command_safe_mode, check_ssrf_safety

# Initialize FastMCP Server
mcp = FastMCP("spectra_mcp")

BACKEND_URL = os.getenv("SPECTRA_BACKEND_URL", "http://127.0.0.1:8000")
DEFAULT_PROJECT = os.getenv("SPECTRA_PROJECT", "default").strip().lower()

# Ensure DB is created
init_db()


# Persistent connection pools for high-throughput concurrency
_dashboard_client: Optional[httpx.AsyncClient] = None
_client_loop = None
_outbound_clients: Dict[str, httpx.AsyncClient] = {}
_outbound_loop = None

async def _get_dashboard_client() -> httpx.AsyncClient:
    global _dashboard_client, _client_loop
    current_loop = asyncio.get_running_loop()
    if _dashboard_client is None or _dashboard_client.is_closed or _client_loop != current_loop:
        if _dashboard_client and not _dashboard_client.is_closed:
            try:
                await _dashboard_client.aclose()
            except Exception:
                pass
        _dashboard_client = httpx.AsyncClient(
            timeout=2.0,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=30.0)
        )
        _client_loop = current_loop
    return _dashboard_client

async def _get_outbound_client(proxy_cfg: str = "") -> httpx.AsyncClient:
    global _outbound_clients, _outbound_loop
    current_loop = asyncio.get_running_loop()
    if _outbound_loop != current_loop:
        _outbound_clients.clear()
        _outbound_loop = current_loop
    key = proxy_cfg.strip() if proxy_cfg else "direct"
    verify_ssl = os.getenv("SPECTRA_VERIFY_SSL", "false").lower() == "true"
    if key not in _outbound_clients or _outbound_clients[key].is_closed:
        kwargs = {
            "verify": verify_ssl,
            "follow_redirects": True,
            "timeout": 30.0,
            "limits": httpx.Limits(max_keepalive_connections=30, max_connections=100, keepalive_expiry=60.0)
        }
        if proxy_cfg and proxy_cfg.strip():
            kwargs["proxy"] = proxy_cfg.strip()
        _outbound_clients[key] = httpx.AsyncClient(**kwargs)
    return _outbound_clients[key]


async def _persist_and_stream_log(log_payload: Dict[str, Any], flag_status: str, findings: list) -> Optional[int]:
    """
    Dispatches log to running FastAPI dashboard via HTTP POST so it broadcasts over WebSockets.
    Falls back to direct SQLite database write if dashboard is offline.
    Returns the recorded log_id for programmatic chaining.
    """
    try:
        client = await _get_dashboard_client()
        resp = await client.post(f"{BACKEND_URL}/api/logs", json=log_payload)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and "id" in data:
                return data["id"]
    except Exception:
        pass

    db = SessionLocal()
    try:
        proj = (log_payload.get("project") or DEFAULT_PROJECT).strip().lower()
        if not db.query(Project).filter(Project.name == proj).first():
            db.add(Project(name=proj, description="Auto-created workspace"))
            db.commit()

        entry = HttpLog(
            project=proj,
            agent_id=log_payload.get("agent_id", "primary_agent") or "primary_agent",
            source=log_payload.get("source", "HTTP_CLIENT"),
            method=log_payload.get("method", "GET"),
            url=log_payload.get("url", ""),
            host=log_payload.get("host", ""),
            path=log_payload.get("path", "/"),
            status_code=log_payload.get("status_code"),
            duration_ms=log_payload.get("duration_ms", 0),
            request_headers=json.dumps(log_payload.get("request_headers", {})),
            request_body=(log_payload.get("request_body") or "")[:5242880],
            response_headers=json.dumps(log_payload.get("response_headers", {})),
            response_body=(log_payload.get("response_body") or "")[:5242880],
            reasoning=log_payload.get("reasoning", "") or "",
            flag_status=flag_status
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        for f in findings:
            finding = Finding(
                log_id=entry.id,
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                evidence=f.get("evidence", ""),
                description=f.get("description", ""),
                remediation=f.get("remediation", "")
            )
            db.add(finding)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


async def _persist_and_stream_command(cmd_payload: Dict[str, Any]) -> Optional[int]:
    """Dispatches command log to dashboard or writes directly to SQLite. Returns command_id."""
    try:
        client = await _get_dashboard_client()
        resp = await client.post(f"{BACKEND_URL}/api/commands", json=cmd_payload)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and "id" in data:
                return data["id"]
    except Exception:
        pass

    db = SessionLocal()
    try:
        proj = (cmd_payload.get("project") or DEFAULT_PROJECT).strip().lower()
        entry = AgentCommandLog(
            project=proj,
            agent_id=cmd_payload.get("agent_id", "primary_agent") or "primary_agent",
            command=cmd_payload.get("command", ""),
            tool_name=cmd_payload.get("tool_name", "terminal"),
            reasoning=cmd_payload.get("reasoning", ""),
            exit_code=cmd_payload.get("exit_code"),
            stdout=cmd_payload.get("stdout", "")[:5242880],
            stderr=cmd_payload.get("stderr", "")[:5242880],
            duration_ms=cmd_payload.get("duration_ms", 0),
            status=cmd_payload.get("status", "SUCCESS"),
            linked_log_id=cmd_payload.get("linked_log_id")
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.id
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


async def _persist_and_stream_payload(payload_data: Dict[str, Any]) -> Optional[int]:
    """Dispatches captured payload to dashboard or writes directly to SQLite. Returns payload_id."""
    try:
        client = await _get_dashboard_client()
        resp = await client.post(f"{BACKEND_URL}/api/payloads", json=payload_data)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and "id" in data:
                return data["id"]
    except Exception:
        pass

    db = SessionLocal()
    try:
        proj = (payload_data.get("project") or DEFAULT_PROJECT).strip().lower()
        entry = CapturedPayload(
            project=proj,
            agent_id=payload_data.get("agent_id", "primary_agent") or "primary_agent",
            vuln_type=(payload_data.get("vuln_type", "CUSTOM") or "CUSTOM").upper(),
            target_param=payload_data.get("target_param", ""),
            raw_payload=payload_data.get("raw_payload", ""),
            mutation_type=payload_data.get("mutation_type", "DIRECT"),
            target_url=payload_data.get("target_url", ""),
            http_method=(payload_data.get("http_method", "GET") or "GET").upper(),
            http_log_id=payload_data.get("http_log_id"),
            outcome=payload_data.get("outcome", "TESTED"),
            http_status=payload_data.get("http_status"),
            response_signature=payload_data.get("response_signature", ""),
            notes=payload_data.get("notes", "")
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.id
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


def _extract_domain_cookies(url: str, project: str = "default") -> Dict[str, str]:
    """Retrieves active session cookies for the target domain and project from SQLite."""
    cookies = {}
    try:
        parsed = urllib.parse.urlparse(url)
        target_host = (parsed.netloc or "").split(":")[0].strip().lower()
        db = SessionLocal()
        try:
            # First match sessions for this project
            sessions = db.query(ActiveSession).filter(ActiveSession.project == project).all()
            if not sessions:
                sessions = db.query(ActiveSession).all()

            for s in sessions:
                stored_dom = (s.domain or "").strip().lower()
                if "://" in stored_dom:
                    stored_dom = urllib.parse.urlparse(stored_dom).netloc
                stored_dom = stored_dom.split(":")[0].strip("/")

                # Robust Bidirectional domain match (exact, subdomain, or root domain)
                is_match = (
                    target_host == stored_dom or
                    target_host.endswith("." + stored_dom) or
                    stored_dom.endswith("." + target_host) or
                    (stored_dom in target_host and len(stored_dom) > 3)
                )

                if is_match:
                    try:
                        state_data = s.get_decrypted_state()
                        for c in state_data.get("cookies", []):
                            c_name = c.get("name")
                            c_val = c.get("value")
                            if c_name and c_val:
                                cookies[c_name] = c_val
                    except Exception:
                        pass
        finally:
            db.close()
    except Exception:
        pass
    return cookies


# ==============================================================================
# MCP Tool 1: send_http_request
# ==============================================================================

@mcp.tool()
async def send_http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    project: Optional[str] = None,
    agent_id: Optional[str] = "primary_agent",
    reasoning: Optional[str] = None,
    max_body_chars: Optional[int] = 5000
) -> str:
    """
    Executes an HTTP/HTTPS request, routes it through the Spectra security proxy,
    logs traffic, performs real-time vulnerability triage, AND AUTOMATICALLY INJECTS
    active session cookies configured in Spectra for the target domain.
    Returns Log ID for chaining and body preview. Use get_log_detail(log_id) for full uncompressed body.
    
    NOTE FOR AI AGENTS (Opencode / Hermes):
    You DO NOT need to ask the user for session cookies or authenticate manually.
    Spectra automatically injects the authenticated session tokens for the target application!
    
    Parameters:
      - method: HTTP Method (GET, POST, PUT, DELETE, etc.)
      - url: Full target URL
      - headers: Optional custom HTTP headers dict
      - body: Optional request body string
      - project: Workspace scope (e.g. 'client-alpha')
      - agent_id: Identifier of the AI agent instance (e.g. 'primary_agent')
      - reasoning: The AI agent's hypothesis or intent (e.g. 'Testing SQL injection on parameter id')
    """
    target_project = (project or DEFAULT_PROJECT).strip().lower()
    target_agent = (agent_id or "primary_agent").strip()
    method = method.upper().strip()
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    # --------------------------------------------------------------------------
    # 1. SCOPE & GUARDRAIL CHECK, THROTTLING, & PROXY LOOKUP
    # --------------------------------------------------------------------------
    db = SessionLocal()
    proj_delay_ms = 0
    proj_proxy = ""
    try:
        is_allowed, block_reason = check_scope(target_project, url, db)
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_delay_ms = proj_obj.delay_ms or 0
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    if not is_allowed:
        # Log blocked attempt for auditing
        blocked_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "source": "HTTP_CLIENT",
            "method": method,
            "url": url,
            "host": host,
            "path": path,
            "status_code": 403,
            "duration_ms": 0,
            "request_headers": headers,
            "request_body": body or "",
            "response_headers": {},
            "response_body": f"<BLOCKED BY SPECTRA SCOPE GUARD: {block_reason}>",
            "reasoning": reasoning or ""
        }
        await _persist_and_stream_log(blocked_payload, "BLOCKED", [])
        return (
            f"[!] BLOCKED BY SPECTRA SCOPE GUARD:\n"
            f"The target '{url}' was blocked because: {block_reason}.\n"
            f"Please restrict testing exclusively to authorized domains defined in project '{target_project}'."
        )

    # Optional Rate Limiting / Delay
    if proj_delay_ms > 0:
        await asyncio.sleep(proj_delay_ms / 1000.0)

    # --------------------------------------------------------------------------
    # 2. INTERACTIVE INTERCEPT PROXY TRAP
    # --------------------------------------------------------------------------
    if is_intercept_enabled():
        req_trap_data = {
            "project": target_project,
            "agent_id": target_agent,
            "method": method,
            "url": url,
            "headers": headers,
            "body": body or "",
            "reasoning": reasoning or ""
        }
        intercept_id, trap_event = create_intercept_trap(req_trap_data)
        
        # Notify running dashboard via HTTP so it pops up in Intercept UI
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                await client.post(f"{BACKEND_URL}/api/logs", json={
                    "project": target_project,
                    "agent_id": target_agent,
                    "source": "HTTP_CLIENT",
                    "method": method,
                    "url": url,
                    "host": host,
                    "path": path,
                    "status_code": None,
                    "duration_ms": 0,
                    "request_headers": headers,
                    "request_body": body or "",
                    "response_headers": {},
                    "response_body": "<WAITING IN INTERCEPT TRAP>",
                    "reasoning": f"[INTERCEPT #{intercept_id}] {reasoning or ''}"
                })
        except Exception:
            pass

        # Wait for human pentester decision (or 180s timeout)
        try:
            await asyncio.wait_for(trap_event.wait(), timeout=180.0)
        except asyncio.TimeoutError:
            pop_intercept_result(intercept_id)
            return "[!] INTERCEPT TIMEOUT: Request paused for 180s without human response. Execution resumed."

        result_item = pop_intercept_result(intercept_id)
        if result_item:
            if result_item.get("decision") == "drop":
                return "[!] REQUEST DROPPED: The request was dropped by the human operator in the Spectra Intercept Console."
            elif result_item.get("modified_data"):
                # Apply modifications made by human operator
                mod = result_item["modified_data"]
                method = mod.get("method", method).upper().strip()
                url = mod.get("url", url)
                headers = mod.get("headers", headers)
                body = mod.get("body", body)
                parsed = urllib.parse.urlparse(url)
                host = parsed.netloc
                path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

    # --------------------------------------------------------------------------
    # 3. SESSION COOKIE INJECTION
    # --------------------------------------------------------------------------
    active_cookies = _extract_domain_cookies(url, project=target_project)
    if active_cookies:
        cookie_header = "; ".join([f"{k}={v}" for k, v in active_cookies.items()])
        if "Cookie" in headers:
            headers["Cookie"] += f"; {cookie_header}"
        elif "cookie" in headers:
            headers["cookie"] += f"; {cookie_header}"
        else:
            headers["Cookie"] = cookie_header

    # --------------------------------------------------------------------------
    # 4. REQUEST EXECUTION (With Upstream Proxy Chaining)
    # --------------------------------------------------------------------------
    start_time = time.time()
    status_code = None
    res_headers = {}
    res_body = ""
    error_note = None

    proxy_cfg = proj_proxy.strip() if proj_proxy else (os.getenv("SPECTRA_UPSTREAM_PROXY") or "").strip()

    try:
        client = await _get_outbound_client(proxy_cfg)
        content_bytes = body.encode("utf-8") if body else None
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=content_bytes
        )
        status_code = response.status_code
        res_headers = dict(response.headers)
        try:
            res_body = response.text
        except Exception:
            res_body = f"<Binary data: {len(response.content)} bytes>"
    except Exception as ex:
        error_note = f"Network/Transport Error: {str(ex)}"
        res_body = error_note

    duration_ms = int((time.time() - start_time) * 1000)

    log_payload = {
        "project": target_project,
        "agent_id": target_agent,
        "source": "HTTP_CLIENT",
        "method": method,
        "url": url,
        "host": host,
        "path": path,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "request_headers": headers,
        "request_body": body or "",
        "response_headers": res_headers,
        "response_body": res_body,
        "reasoning": reasoning or ""
    }

    in_memory_log = HttpLog(
        project=target_project,
        agent_id=target_agent,
        source="HTTP_CLIENT",
        method=method,
        url=url,
        host=host,
        path=path,
        status_code=status_code,
        duration_ms=duration_ms,
        request_headers=json.dumps(headers),
        request_body=(body or "")[:5242880],
        response_headers=json.dumps(res_headers),
        response_body=res_body[:5242880],
        reasoning=reasoning or ""
    )
    flag_status, findings_list = analyze_traffic(in_memory_log)

    logged_id = await _persist_and_stream_log(log_payload, flag_status, findings_list)

    max_preview = max(100, min(max_body_chars or 5000, 50000))
    body_snippet = res_body[:max_preview] if res_body else "[Empty response body]"
    log_id_str = f"#{logged_id}" if logged_id else "#untracked"

    triage_info = ""
    if flag_status == "CONFIRMED":
        triage_info = f"\n[!] ALERT: CONFIRMED FINDING DETECTED: {[f['title'] for f in findings_list]}"
    elif flag_status == "POTENTIAL":
        triage_info = f"\n[*] NOTICE: POTENTIAL ANOMALY DETECTED: {[f['title'] for f in findings_list]}"

    session_tag = f" | [Spectra: Auto-injected {len(active_cookies)} cookies]" if active_cookies else ""
    return (
        f"Project: [{target_project}] | Log ID: {log_id_str} | Agent: [{target_agent}] | HTTP/{status_code or 'ERR'} | Latency: {duration_ms}ms{session_tag} | Flag: {flag_status}{triage_info}\n"
        f"Headers: {json.dumps(res_headers)}\n\n"
        f"Body Preview (showing {min(len(body_snippet), len(res_body))} of {len(res_body)} chars. Call tool get_log_detail({logged_id or 0}) to read complete uncompressed body):\n{body_snippet}"
    )


# ==============================================================================
# MCP Tool 2: browser_navigate_and_render
# ==============================================================================

@mcp.tool()
async def browser_navigate_and_render(
    url: str,
    click_selector: Optional[str] = None,
    fill_inputs: Optional[Dict[str, str]] = None,
    project: Optional[str] = None,
    agent_id: Optional[str] = "primary_agent",
    reasoning: Optional[str] = None,
    max_dom_chars: Optional[int] = 10000
) -> str:
    """
    Renders a dynamic webpage headlessly via Playwright, executes automated actions,
    intercepts background asynchronous network requests (AJAX/fetch/scripts), and extracts visible DOM content.
    Returns Log ID, list of intercepted API endpoints/scripts, and DOM content preview.
    """
    target_project = (project or DEFAULT_PROJECT).strip().lower()
    target_agent = (agent_id or "primary_agent").strip()

    # Scope & Settings check
    db = SessionLocal()
    proj_delay_ms = 0
    proj_proxy = ""
    try:
        is_allowed, block_reason = check_scope(target_project, url, db)
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            proj_delay_ms = proj_obj.delay_ms or 0
            proj_proxy = proj_obj.upstream_proxy or ""
    finally:
        db.close()

    if not is_allowed:
        return f"[!] BLOCKED BY SPECTRA SCOPE GUARD: {block_reason}"

    if proj_delay_ms > 0:
        await asyncio.sleep(proj_delay_ms / 1000.0)

    proxy_cfg = proj_proxy.strip() if proj_proxy else (os.getenv("SPECTRA_UPSTREAM_PROXY") or "").strip()

    try:
        result = await render_page(
            url=url,
            click_selector=click_selector,
            fill_inputs=fill_inputs,
            upstream_proxy=proxy_cfg if proxy_cfg else None
        )
        
        log_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "source": "BROWSER_RENDER",
            "method": "GET",
            "url": url,
            "host": result.get("domain", ""),
            "path": urllib.parse.urlparse(url).path or "/",
            "status_code": 200,
            "duration_ms": 1500,
            "request_headers": {"User-Agent": "SpectraMCP Playwright Headless"},
            "request_body": json.dumps({"click_selector": click_selector, "fill_inputs": fill_inputs}),
            "response_headers": {"Content-Type": "text/html"},
            "response_body": result.get("dom_text", "")[:50000],
            "reasoning": reasoning or ""
        }
        logged_id = await _persist_and_stream_log(log_payload, "CLEAN", [])

        # Log intercepted background AJAX/fetch sub-requests
        intercepted = result.get("intercepted_requests", [])
        intercepted_summary = []
        for sub_req in intercepted:
            if sub_req.get("resource_type") in ["xhr", "fetch", "script"]:
                sub_parsed = urllib.parse.urlparse(sub_req.get("url", ""))
                sub_payload = {
                    "project": target_project,
                    "agent_id": target_agent,
                    "source": "BROWSER_RENDER",
                    "method": sub_req.get("method", "GET"),
                    "url": sub_req.get("url", ""),
                    "host": sub_parsed.netloc,
                    "path": sub_parsed.path or "/",
                    "status_code": 200,
                    "duration_ms": 50,
                    "request_headers": sub_req.get("headers", {}),
                    "request_body": "",
                    "response_headers": {},
                    "response_body": f"<Intercepted {sub_req.get('resource_type')} request>",
                    "reasoning": "Sub-request captured during headless render"
                }
                await _persist_and_stream_log(sub_payload, "CLEAN", [])

        # Extract top 30 endpoints for agent reconnaissance
        for sub in intercepted[:30]:
            intercepted_summary.append(f"  [{sub.get('method', 'GET')}] {sub.get('url')} ({sub.get('resource_type')})")
        intercepted_str = "\n".join(intercepted_summary) if intercepted_summary else "  [No sub-requests intercepted]"

        max_dom = max(500, min(max_dom_chars or 10000, 100000))
        full_dom = result.get("dom_text", "")
        dom_preview = full_dom[:max_dom]
        log_id_str = f"#{logged_id}" if logged_id else "#untracked"

        return (
            f"Project: [{target_project}] | Log ID: {log_id_str} | Agent: [{target_agent}] | Page: '{result.get('title')}'\n"
            f"Final URL: {result.get('url')}\n"
            f"Intercepted Endpoints ({len(intercepted)} captured):\n{intercepted_str}\n\n"
            f"DOM Text Preview (showing {min(len(dom_preview), len(full_dom))} of {len(full_dom)} chars. Use get_log_detail({logged_id or 0}) to read complete body):\n{dom_preview}"
        )
    except Exception as ex:
        return f"Browser render failure: {str(ex)}"


@mcp.tool()
async def render_webpage(
    url: str,
    click_selector: Optional[str] = None,
    fill_inputs: Optional[Dict[str, str]] = None,
    project: Optional[str] = None,
    agent_id: Optional[str] = "primary_agent",
    reasoning: Optional[str] = None,
    max_dom_chars: Optional[int] = 10000
) -> str:
    """
    Renders a dynamic webpage headlessly via Playwright, executes automated actions,
    intercepts background asynchronous network requests, and extracts visible DOM content.
    (Alias for browser_navigate_and_render).
    """
    return await browser_navigate_and_render(
        url=url,
        click_selector=click_selector,
        fill_inputs=fill_inputs,
        project=project,
        agent_id=agent_id,
        reasoning=reasoning,
        max_dom_chars=max_dom_chars
    )


# ==============================================================================
# MCP Tool 3: request_manual_login
# ==============================================================================

@mcp.tool()
async def request_manual_login(
    login_url: str,
    domain: str,
    project: Optional[str] = None
) -> str:
    """
    Spawns an interactive headed browser window for Human-in-the-Loop (HITL) authentication.
    Suspends autonomous execution until the human pentester logs in or completes CAPTCHA.
    Extracted cookies and storage tokens are automatically synced to the gateway database.
    """
    target_project = (project or DEFAULT_PROJECT).strip().lower()
    try:
        result = await spawn_interactive_login(login_url, domain)
        cookie_count = result.get("cookie_count", 0)
        return (
            f"Project: [{target_project}] | Authentication successful. Sockets/cookies updated and active for domain '{domain}'. "
            f"Captured {cookie_count} session cookies. Subsequent requests will auto-inject credentials."
        )
    except Exception as ex:
        return f"Interactive login failed: {str(ex)}"


# ==============================================================================
# MCP Tool 4: run_pentest_command
# ==============================================================================

DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\/",
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\*",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"format\s+[a-zA-Z]:",
    r"DROP\s+DATABASE",
    r"DROP\s+TABLE",
    r"shutdown(\.exe)?\s+",
    r"reboot(\.exe)?"
]

@mcp.tool()
async def run_pentest_command(
    command: str,
    reasoning: Optional[str] = None,
    tool_name: Optional[str] = "terminal",
    project: Optional[str] = None,
    agent_id: Optional[str] = "primary_agent",
    timeout: Optional[int] = 60,
    cwd: Optional[str] = None
) -> str:
    """
    Executes a security testing command in the local shell environment (e.g. nmap, curl, sqlmap, custom scripts),
    streams the command and outputs to Spectra for full operator observability and audit history,
    and applies automated safety guardrails to prevent destructive system commands and SSRF metadata exfiltration.
    """
    target_project = (project or DEFAULT_PROJECT).strip().lower()
    target_agent = (agent_id or "primary_agent").strip()
    cmd_clean = command.strip()

    # Query project settings for internal network scope allowance
    db = SessionLocal()
    allow_internal = False
    try:
        proj_obj = db.query(Project).filter(Project.name == target_project).first()
        if proj_obj:
            allow_internal = bool(proj_obj.allow_internal_networks)
    finally:
        db.close()

    # Hardened Cross-Platform Safety Guardrail & SSRF Check
    is_safe_cmd, block_reason = check_command_safe_mode(cmd_clean, allow_internal=allow_internal)
    if not is_safe_cmd:
        blocked_payload = {
            "project": target_project,
            "agent_id": target_agent,
            "command": cmd_clean,
            "tool_name": tool_name or "terminal",
            "reasoning": reasoning or "",
            "exit_code": -1,
            "stdout": "",
            "stderr": block_reason,
            "duration_ms": 0,
            "status": "BLOCKED"
        }
        cmd_id = await _persist_and_stream_command(blocked_payload)
        cmd_id_str = f"#{cmd_id}" if cmd_id else "#untracked"
        return (
            f"[!] BLOCKED BY SPECTRA CLI SAFE-MODE / SSRF GUARD (Command ID: {cmd_id_str}):\n"
            f"{block_reason}\n"
            f"Please restrict commands to authorized non-destructive reconnaissance and assessment utilities."
        )

    # Resolve execution working directory
    work_dir = CURRENT_DIR
    if cwd and os.path.isdir(cwd):
        work_dir = os.path.abspath(cwd)

    start_time = time.time()
    stdout_text = ""
    stderr_text = ""
    exit_code = 0
    status = "SUCCESS"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_clean,
            cwd=work_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            out_bytes, err_bytes = await asyncio.wait_for(proc.communicate(), timeout=float(timeout or 60))
            stdout_text = out_bytes.decode("utf-8", errors="replace")
            stderr_text = err_bytes.decode("utf-8", errors="replace")
            exit_code = proc.returncode or 0
            if exit_code != 0:
                status = "FAILED"
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            exit_code = -1
            status = "TIMEOUT"
            stderr_text = f"Execution timed out after {timeout} seconds."
    except Exception as ex:
        exit_code = 1
        status = "FAILED"
        stderr_text = f"Subprocess invocation failure: {str(ex)}"

    duration_ms = int((time.time() - start_time) * 1000)

    cmd_log_payload = {
        "project": target_project,
        "agent_id": target_agent,
        "command": cmd_clean,
        "tool_name": tool_name or "terminal",
        "reasoning": reasoning or "",
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "duration_ms": duration_ms,
        "status": status
    }
    cmd_id = await _persist_and_stream_command(cmd_log_payload)
    cmd_id_str = f"#{cmd_id}" if cmd_id else "#untracked"

    stdout_snippet = stdout_text[:5000] if stdout_text else "[No standard output]"
    stderr_snippet = f"\nSTDERR:\n{stderr_text[:2000]}" if stderr_text else ""
    return (
        f"Project: [{target_project}] | Command ID: {cmd_id_str} | Agent: [{target_agent}] | Exit Code: {exit_code} | Duration: {duration_ms}ms | CWD: [{work_dir}] | Status: {status}\n"
        f"Command: {cmd_clean}\n\n"
        f"STDOUT:\n{stdout_snippet}{stderr_snippet}"
    )


# ==============================================================================
# MCP Tool 5: record_test_payload
# ==============================================================================

@mcp.tool()
async def record_test_payload(
    target_url: str,
    vuln_type: str,
    raw_payload: str,
    target_param: Optional[str] = "",
    mutation_type: Optional[str] = "DIRECT",
    outcome: Optional[str] = "TESTED",
    http_method: Optional[str] = "GET",
    response_signature: Optional[str] = "",
    http_status: Optional[int] = None,
    reasoning: Optional[str] = None,
    project: Optional[str] = None,
    agent_id: Optional[str] = "primary_agent"
) -> str:
    """
    Explicitly catalogs a specialized pentest payload (SQLi, XSS, SSRF, SSTI, RCE, IDOR, etc.)
    crafted or tested by the AI into the Spectra Payload Vault for operator review, verification, and 1-click replay.
    Returns Payload ID for programmatic chaining.
    """
    target_project = (project or DEFAULT_PROJECT).strip().lower()
    target_agent = (agent_id or "primary_agent").strip()

    payload_data = {
        "project": target_project,
        "agent_id": target_agent,
        "vuln_type": vuln_type.upper(),
        "target_param": target_param or "",
        "raw_payload": raw_payload,
        "mutation_type": mutation_type or "DIRECT",
        "target_url": target_url,
        "http_method": (http_method or "GET").upper(),
        "outcome": outcome or "TESTED",
        "response_signature": response_signature or "",
        "http_status": http_status,
        "notes": reasoning or ""
    }
    payload_id = await _persist_and_stream_payload(payload_data)
    payload_id_str = f"#{payload_id}" if payload_id else "#untracked"

    return (
        f"Project: [{target_project}] | Payload ID: {payload_id_str} | Captured {http_method.upper()} payload '{raw_payload[:80]}' for {vuln_type} on param '{target_param}'. "
        f"Logged in Spectra Payload Vault (Use Payload ID for chained replay/verification)."
    )


# ==============================================================================
# MCP Tool 6: get_log_detail (Full Request/Response Body Inspection)
# ==============================================================================

@mcp.tool()
async def get_log_detail(
    log_id: int,
    max_body_chars: Optional[int] = 100000
) -> str:
    """
    Retrieves complete headers, full request body, full response body, and triaged findings
    for a specific HTTP transaction by its Log ID.
    Essential for bug bounty research to inspect reflected XSS, deep JSON responses, or sensitive leaks without truncation.
    """
    db = SessionLocal()
    try:
        log_entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        if not log_entry:
            return f"[!] Log ID #{log_id} was not found in the Spectra database."

        findings = db.query(Finding).filter(Finding.log_id == log_id).all()
        findings_str = ""
        if findings:
            findings_str = "\nFindings Detected on this Request:\n" + "\n".join([
                f"- [{f.severity}] {f.title} ({f.category})\n  Evidence: {f.evidence}\n  Remediation: {f.remediation}"
                for f in findings
            ])
        else:
            findings_str = "\nFindings: None (Clean)"

        max_len = max(500, min(max_body_chars or 100000, 1000000))
        req_body = log_entry.request_body or "[Empty Request Body]"
        res_body = log_entry.response_body or "[Empty Response Body]"

        req_body_prev = req_body[:max_len]
        res_body_prev = res_body[:max_len]

        return (
            f"=== SPECTRA HTTP LOG DETAIL #{log_entry.id} ===\n"
            f"Project: [{log_entry.project}] | Agent: [{log_entry.agent_id}] | Source: {log_entry.source}\n"
            f"Target: {log_entry.method} {log_entry.url}\n"
            f"Status Code: {log_entry.status_code} | Latency: {log_entry.duration_ms}ms | Flag: {log_entry.flag_status}\n"
            f"Timestamp: {log_entry.timestamp}\n"
            f"Hypothesis / Reasoning: {log_entry.reasoning or '[None]'}\n\n"
            f"--- Request Headers ---\n{log_entry.request_headers}\n\n"
            f"--- Request Body ({len(req_body)} bytes) ---\n{req_body_prev}\n\n"
            f"--- Response Headers ---\n{log_entry.response_headers}\n\n"
            f"--- Response Body ({len(res_body)} bytes) ---\n{res_body_prev}\n"
            f"{findings_str}"
        )
    finally:
        db.close()


# ==============================================================================
# MCP Tool 7: get_traffic_history (Traffic Index & Search)
# ==============================================================================

@mcp.tool()
async def get_traffic_history(
    project: Optional[str] = None,
    limit: Optional[int] = 20
) -> str:
    """
    Lists recent HTTP traffic entries recorded in Spectra for the selected project.
    Returns Log IDs, HTTP methods, status codes, URLs, and triage flags so the agent can select IDs for deep inspection.
    """
    target_project = (project or DEFAULT_PROJECT).strip().lower()
    db = SessionLocal()
    try:
        query = db.query(HttpLog)
        if target_project and target_project.upper() != "ALL":
            query = query.filter(HttpLog.project == target_project)
        logs = query.order_by(HttpLog.id.desc()).limit(min(max(limit or 20, 1), 100)).all()
        if not logs:
            return f"No traffic logs recorded for project [{target_project}]."

        lines = [f"=== RECENT TRAFFIC HISTORY (Project: {target_project}) ==="]
        for l in logs:
            lines.append(f"#{l.id:04d} | {l.method:<5} | {str(l.status_code or 'ERR'):<4} | {l.duration_ms:>4}ms | [{l.flag_status:<9}] | {l.url}")
        lines.append(f"\nTip: Call get_log_detail(log_id) to read complete headers, full body, or vulnerability findings.")
        return "\n".join(lines)
    finally:
        db.close()


if __name__ == "__main__":
    mcp.run()
