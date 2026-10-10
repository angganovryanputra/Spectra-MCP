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

from backend.database import init_db, SessionLocal, ActiveSession, HttpLog, Finding, Project
from backend.analyzer import analyze_traffic
from backend.browser_handler import render_page, spawn_interactive_login
from backend.intercept_manager import (
    is_intercept_enabled,
    create_intercept_trap,
    pop_intercept_result,
    check_scope
)

# Initialize FastMCP Server
mcp = FastMCP("spectra_mcp")

BACKEND_URL = os.getenv("SPECTRA_BACKEND_URL", "http://127.0.0.1:8000")
DEFAULT_PROJECT = os.getenv("SPECTRA_PROJECT", "default").strip().lower()

# Ensure DB is created
init_db()


async def _persist_and_stream_log(log_payload: Dict[str, Any], flag_status: str, findings: list):
    """
    Dispatches log to running FastAPI dashboard via HTTP POST so it broadcasts over WebSockets.
    Falls back to direct SQLite database write if dashboard is offline.
    """
    notified = False
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.post(f"{BACKEND_URL}/api/logs", json=log_payload)
            if resp.status_code == 200:
                notified = True
    except Exception:
        notified = False

    if not notified:
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
        except Exception:
            db.rollback()
        finally:
            db.close()


def _extract_domain_cookies(url: str, project: str = "default") -> Dict[str, str]:
    """Retrieves active session cookies for the target domain and project from SQLite."""
    cookies = {}
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(":")[0]
        db = SessionLocal()
        try:
            session_rec = db.query(ActiveSession).filter(
                ActiveSession.project == project,
                ActiveSession.domain.ilike(f"%{domain}%")
            ).first()
            if not session_rec:
                session_rec = db.query(ActiveSession).filter(ActiveSession.domain.ilike(f"%{domain}%")).first()

            if session_rec and session_rec.storage_state:
                state_data = json.loads(session_rec.storage_state)
                for c in state_data.get("cookies", []):
                    c_name = c.get("name")
                    c_val = c.get("value")
                    if c_name and c_val:
                        cookies[c_name] = c_val
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
    reasoning: Optional[str] = None
) -> str:
    """
    Executes an HTTP/HTTPS request, routes it through the Spectra security proxy,
    injects active session authentication tokens, logs traffic, and performs real-time
    vulnerability triage.
    
    Parameters:
      - method: HTTP Method (GET, POST, PUT, DELETE, etc.)
      - url: Full target URL
      - headers: Optional custom HTTP headers dict
      - body: Optional request body string
      - project: Workspace scope (e.g. 'client-alpha')
      - agent_id: Identifier of the AI agent or collaborative agent instance (e.g. 'recon_agent')
      - reasoning: The AI agent's hypothesis or intent (e.g. 'Testing SQL injection on search parameter')
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
        asyncio.create_task(_persist_and_stream_log(blocked_payload, "BLOCKED", []))
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
    client_kwargs = {
        "verify": False,
        "follow_redirects": True,
        "timeout": 30.0
    }
    if proxy_cfg:
        client_kwargs["proxy"] = proxy_cfg

    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
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

    asyncio.create_task(_persist_and_stream_log(log_payload, flag_status, findings_list))

    body_snippet = res_body[:1500] if res_body else "[Empty response body]"
    triage_info = ""
    if flag_status == "CONFIRMED":
        triage_info = f"\n[!] ALERT: CONFIRMED FINDING DETECTED: {[f['title'] for f in findings_list]}"
    elif flag_status == "POTENTIAL":
        triage_info = f"\n[*] NOTICE: POTENTIAL ANOMALY DETECTED: {[f['title'] for f in findings_list]}"

    return (
        f"Project: [{target_project}] | Agent: [{target_agent}] | HTTP/{status_code or 'ERR'} | Latency: {duration_ms}ms | Flag: {flag_status}{triage_info}\n"
        f"Headers: {json.dumps(res_headers)}\n\n"
        f"Body Preview:\n{body_snippet}"
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
    reasoning: Optional[str] = None
) -> str:
    """
    Renders a dynamic webpage headlessly via Playwright, executes automated actions,
    intercepts background asynchronous network requests, and extracts visible DOM content.
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
        asyncio.create_task(_persist_and_stream_log(log_payload, "CLEAN", []))

        # Log intercepted background AJAX/fetch sub-requests
        for sub_req in result.get("intercepted_requests", []):
            if sub_req.get("resource_type") in ["xhr", "fetch"]:
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
                asyncio.create_task(_persist_and_stream_log(sub_payload, "CLEAN", []))

        dom_preview = result.get("dom_text", "")[:2500]
        return (
            f"Project: [{target_project}] | Agent: [{target_agent}] | Page Rendered: '{result.get('title')}'\n"
            f"Final URL: {result.get('url')}\n"
            f"Sub-requests intercepted: {result.get('intercepted_count')}\n\n"
            f"DOM Text:\n{dom_preview}"
        )
    except Exception as ex:
        return f"Browser render failure: {str(ex)}"


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


if __name__ == "__main__":
    mcp.run()
