"""
Spectra MCP - FastAPI Application, REST API, & WebSocket Broadcaster
Full-featured Offensive Security Gateway with Intercept Proxy Trap, Scope Guardrails,
Repeater, HAR/Markdown Exporter, and Multi-Project Observability.
"""

import os
import json
import asyncio
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
import urllib.parse
from sqlalchemy.orm import Session, defer
from sqlalchemy import desc, func, or_

from backend.database import init_db, get_db, HttpLog, Finding, ActiveSession, Project, AgentCommandLog, CapturedPayload
from backend.analyzer import analyze_traffic
from backend.browser_handler import (
    spawn_interactive_login,
    signal_login_confirmation,
    get_active_login_status,
    import_session_cookies,
    parse_cookie_input
)
from backend.intercept_manager import (
    is_intercept_enabled,
    set_intercept_mode,
    get_intercept_status,
    create_intercept_trap,
    resolve_intercept_trap,
    pop_intercept_result,
    check_scope,
    invalidate_scope_cache
)
from backend.report_generator import generate_har_export, generate_markdown_report
from backend.openapi_generator import generate_openapi_spec
from backend.fuzzer import run_fuzz_attack, BUILTIN_PAYLOADS
from backend.session_keeper import start_session_keeper, stop_session_keeper, get_session_keeper_status
from backend.security_utils import sanitize_attachment_filename

# Initialize SQLite database
init_db()

app = FastAPI(
    title="Spectra MCP Platform",
    description="Security Testing Gateway & Real-Time Observability Engine for AI Agents",
    version="1.3.0"
)

@app.on_event("startup")
async def startup_event():
    start_session_keeper(interval=120)

# Security Configuration from Environment
ALLOWED_ORIGINS_ENV = os.getenv(
    "SPECTRA_ALLOWED_ORIGINS",
    "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:3000,http://localhost:3000"
)
SPECTRA_ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_ENV.split(",") if o.strip()]
SPECTRA_API_KEY = os.getenv("SPECTRA_API_KEY", "").strip()
SPECTRA_ALLOW_REMOTE = os.getenv("SPECTRA_ALLOW_REMOTE", "false").lower() == "true"
SPECTRA_MAX_BODY = int(os.getenv("SPECTRA_MAX_BODY_SIZE", "524288"))  # 512 KB default limit per body

app.add_middleware(
    CORSMiddleware,
    allow_origins=SPECTRA_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

@app.middleware("http")
async def host_and_auth_security_middleware(request, call_next):
    client_host = request.client.host if request.client else "unknown"
    # 1. Localhost enforcement: if remote access is not explicitly enabled, block remote IPs
    if not SPECTRA_ALLOW_REMOTE:
        is_local_client = (
            client_host in ["127.0.0.1", "localhost", "::1", "testclient"] or
            client_host.startswith("172.")  # Permit WSL2 virtual hyper-v bridge NAT
        )
        if not is_local_client:
            return JSONResponse(
                {"detail": f"Remote access forbidden for {client_host}: Spectra dashboard is restricted to localhost (127.0.0.1) or WSL2. Set SPECTRA_ALLOW_REMOTE=true in environment to permit external remote IPs."},
                status_code=403
            )

    # 2. API Key enforcement (if SPECTRA_API_KEY is configured in env)
    if SPECTRA_API_KEY and request.url.path.startswith("/api/") and request.url.path != "/api/health":
        provided_key = (
            request.headers.get("X-Spectra-Key") or
            request.query_params.get("api_key") or
            ""
        )
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            provided_key = auth_hdr[7:].strip()
        
        if provided_key != SPECTRA_API_KEY:
            return JSONResponse(
                {"detail": "Unauthorized: Invalid or missing Spectra API Key (X-Spectra-Key header)."},
                status_code=401
            )

    return await call_next(request)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")


# ==============================================================================
# WebSocket Connection Manager
# ==============================================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ConnectionManager()


# ==============================================================================
# Schemas
# ==============================================================================

class LogRecordRequest(BaseModel):
    project: str = "default"
    agent_id: Optional[str] = "primary_agent"
    source: str = "HTTP_CLIENT"
    method: str = "GET"
    url: str
    host: str
    path: str
    status_code: Optional[int] = None
    duration_ms: int = 0
    request_headers: Dict[str, Any] = {}
    request_body: str = ""
    response_headers: Dict[str, Any] = {}
    response_body: str = ""
    reasoning: Optional[str] = ""


class CreateProjectRequest(BaseModel):
    name: str
    description: Optional[str] = ""


class UpdateScopeRequest(BaseModel):
    scope_enabled: bool
    allowed_hosts: List[str]
    blocked_patterns: List[str]
    allow_internal_networks: Optional[bool] = False
    verify_ssl: Optional[bool] = False
    delay_ms: Optional[int] = 0
    upstream_proxy: Optional[str] = ""


class SpawnAuthRequest(BaseModel):
    project: str = "default"
    login_url: str
    target_domain: Optional[str] = None
    browser_choice: Optional[str] = "chrome"  # "chrome", "msedge", "chromium", "system"


class ImportCookiesRequest(BaseModel):
    project: Optional[str] = "default"
    domain: str
    raw_cookie: Optional[str] = None
    raw_input: Optional[str] = None


class ConfirmAuthRequest(BaseModel):
    domain: Optional[str] = None


class InterceptToggleRequest(BaseModel):
    enabled: bool


class InterceptActionRequest(BaseModel):
    action: str  # "forward" or "drop"
    modified_data: Optional[Dict[str, Any]] = None


class RepeaterSendRequest(BaseModel):
    project: str = "default"
    method: str = "GET"
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = ""


class RunFuzzRequest(BaseModel):
    project: str = "default"
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[str] = ""
    category: Optional[str] = "sqli"
    custom_payloads: Optional[List[str]] = None
    concurrency: int = 5


class RecordCommandRequest(BaseModel):
    project: Optional[str] = "default"
    agent_id: Optional[str] = "primary_agent"
    command: str
    tool_name: Optional[str] = "terminal"
    reasoning: Optional[str] = ""
    exit_code: Optional[int] = 0
    stdout: Optional[str] = ""
    stderr: Optional[str] = ""
    duration_ms: Optional[int] = 0
    status: Optional[str] = "SUCCESS"
    linked_log_id: Optional[int] = None


class RecordPayloadRequest(BaseModel):
    project: Optional[str] = "default"
    agent_id: Optional[str] = "primary_agent"
    vuln_type: Optional[str] = "CUSTOM"
    target_param: Optional[str] = ""
    raw_payload: str
    mutation_type: Optional[str] = "DIRECT"
    target_url: Optional[str] = ""
    http_method: Optional[str] = "GET"
    http_log_id: Optional[int] = None
    outcome: Optional[str] = "TESTED"
    http_status: Optional[int] = None
    response_signature: Optional[str] = ""
    notes: Optional[str] = ""


class ClearRequest(BaseModel):
    project: Optional[str] = None


# ==============================================================================
# In-memory known projects cache & stats cache for high concurrency
_KNOWN_PROJECTS = {"default"}
_STATS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}

def _invalidate_stats_cache():
    _STATS_CACHE.clear()

async def record_and_broadcast_log(log_data: dict, db: Session) -> HttpLog:
    """Stores HttpLog, executes analyzer, and notifies WebSocket subscribers with single atomic commit."""
    project_name = (log_data.get("project") or "default").strip().lower()

    # Fast in-memory check to avoid database query on every log
    if project_name not in _KNOWN_PROJECTS:
        existing_proj = db.query(Project).filter(Project.name == project_name).first()
        if not existing_proj:
            db.add(Project(name=project_name, description="Auto-created workspace"))
            db.commit()
        _KNOWN_PROJECTS.add(project_name)

    req_body = (log_data.get("request_body") or "")[:SPECTRA_MAX_BODY]
    res_body = (log_data.get("response_body") or "")[:SPECTRA_MAX_BODY]
    agent_id = (log_data.get("agent_id") or "primary_agent").strip()

    log_entry = HttpLog(
        project=project_name,
        agent_id=agent_id,
        source=log_data.get("source", "HTTP_CLIENT"),
        method=log_data.get("method", "GET").upper(),
        url=log_data.get("url", ""),
        host=log_data.get("host", ""),
        path=log_data.get("path", "/"),
        status_code=log_data.get("status_code"),
        duration_ms=log_data.get("duration_ms", 0),
        request_headers=json.dumps(log_data.get("request_headers", {})),
        request_body=req_body,
        response_headers=json.dumps(log_data.get("response_headers", {})),
        response_body=res_body,
        reasoning=log_data.get("reasoning", "") or "",
        timestamp=datetime.now(timezone.utc)
    )

    flag_status, findings_data = analyze_traffic(log_entry)
    log_entry.flag_status = flag_status

    db.add(log_entry)
    db.flush()  # Populates log_entry.id for findings relationship without committing transaction yet

    for f in findings_data:
        finding = Finding(
            log_id=log_entry.id,
            title=f["title"],
            severity=f["severity"],
            category=f["category"],
            evidence=f.get("evidence", ""),
            description=f.get("description", ""),
            remediation=f.get("remediation", "")
        )
        db.add(finding)

    db.commit()

    # Invalidate stats cache on new log
    _invalidate_stats_cache()

    # Broadcast lightweight log entry (without multi-MB body strings) to keep WebSocket snappy
    payload = {
        "type": "NEW_LOG",
        "project": project_name,
        "log": log_entry.to_dict(include_body=False),
        "alert": flag_status in ["CONFIRMED", "POTENTIAL"]
    }
    await ws_manager.broadcast(payload)
    return log_entry


# ==============================================================================
# WebSocket Endpoint
# ==============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "CONNECTED", "server": "SPECTRA_MCP_V1"})
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ==============================================================================
# Project Management & Scope Guardrails Endpoints
# ==============================================================================

@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.id).all()
    results = []
    for p in projects:
        req_count = db.query(func.count(HttpLog.id)).filter(HttpLog.project == p.name).scalar() or 0
        confirmed_count = db.query(func.count(Finding.id)).join(HttpLog).filter(
            HttpLog.project == p.name,
            Finding.severity.in_(["HIGH", "CRITICAL"])
        ).scalar() or 0
        potential_count = db.query(func.count(Finding.id)).join(HttpLog).filter(
            HttpLog.project == p.name,
            Finding.severity.in_(["LOW", "MEDIUM", "INFO"])
        ).scalar() or 0

        p_dict = p.to_dict()
        p_dict["requests_count"] = req_count
        p_dict["confirmed_count"] = confirmed_count
        p_dict["potential_count"] = potential_count
        results.append(p_dict)
    return {"projects": results}


@app.post("/api/projects")
async def create_project(data: CreateProjectRequest, db: Session = Depends(get_db)):
    clean_name = data.name.strip().lower()
    if not clean_name:
        raise HTTPException(status_code=400, detail="Project name cannot be empty")
    
    existing = db.query(Project).filter(Project.name == clean_name).first()
    if existing:
        return existing.to_dict()

    new_p = Project(
        name=clean_name,
        description=data.description or "",
        scope_enabled=False,
        allowed_hosts=json.dumps(["*"]),
        blocked_patterns=json.dumps(["logout", "delete.*user", "payment", "checkout"])
    )
    db.add(new_p)
    db.commit()
    db.refresh(new_p)

    await ws_manager.broadcast({"type": "PROJECT_CREATED", "project": new_p.to_dict()})
    return new_p.to_dict()


@app.delete("/api/projects/{name}")
async def delete_project(name: str, db: Session = Depends(get_db)):
    clean_name = name.strip().lower()
    if clean_name == "default":
        raise HTTPException(status_code=400, detail="Cannot delete default project")

    proj = db.query(Project).filter(Project.name == clean_name).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")

    db.query(HttpLog).filter(HttpLog.project == clean_name).delete()
    db.query(ActiveSession).filter(ActiveSession.project == clean_name).delete()
    db.delete(proj)
    db.commit()

    await ws_manager.broadcast({"type": "PROJECT_DELETED", "name": clean_name})
    return {"status": "deleted", "name": clean_name}


@app.get("/api/projects/{name}/scope")
def get_project_scope(name: str, db: Session = Depends(get_db)):
    proj = db.query(Project).filter(Project.name == name.lower()).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj.to_dict()


@app.put("/api/projects/{name}/scope")
async def update_project_scope(name: str, req: UpdateScopeRequest, db: Session = Depends(get_db)):
    proj = db.query(Project).filter(Project.name == name.lower()).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")

    proj.scope_enabled = req.scope_enabled
    proj.allowed_hosts = json.dumps(req.allowed_hosts)
    proj.blocked_patterns = json.dumps(req.blocked_patterns)
    if req.allow_internal_networks is not None:
        proj.allow_internal_networks = req.allow_internal_networks
    if req.verify_ssl is not None:
        proj.verify_ssl = req.verify_ssl
    if req.delay_ms is not None:
        proj.delay_ms = max(0, req.delay_ms)
    if req.upstream_proxy is not None:
        proj.upstream_proxy = req.upstream_proxy.strip()
    db.commit()
    db.refresh(proj)
    invalidate_scope_cache(name)

    await ws_manager.broadcast({"type": "SCOPE_UPDATED", "project": proj.to_dict()})
    return proj.to_dict()


# ==============================================================================
# Proxy Trap (Interactive Breakpoint / Intercept) Endpoints
# ==============================================================================

@app.get("/api/intercept/status")
def get_intercept_info():
    """Returns current intercept mode and any requests waiting in the trap."""
    return get_intercept_status()


@app.post("/api/intercept/toggle")
async def toggle_intercept(req: InterceptToggleRequest):
    """Enable or disable interactive intercept proxy trap."""
    new_state = set_intercept_mode(req.enabled)
    await ws_manager.broadcast({"type": "INTERCEPT_TOGGLED", "enabled": new_state})
    return {"enabled": new_state}


@app.post("/api/intercept/{intercept_id}/action")
async def handle_intercept_decision(intercept_id: str, req: InterceptActionRequest):
    """Releases a trapped request by either forwarding (original/modified) or dropping."""
    success = resolve_intercept_trap(intercept_id, req.action, req.modified_data)
    if not success:
        raise HTTPException(status_code=404, detail="Intercept ID not found or already released")
    
    await ws_manager.broadcast({"type": "INTERCEPT_RESOLVED", "intercept_id": intercept_id, "action": req.action})
    return {"status": "resolved", "intercept_id": intercept_id, "action": req.action}


_repeater_clients: Dict[str, Any] = {}

async def _get_repeater_client(proxy_cfg: str = "", verify_ssl: bool = False):
    import httpx
    verify_env = os.getenv("SPECTRA_VERIFY_SSL", "false").lower() == "true"
    final_verify = verify_ssl or verify_env
    key = f"{proxy_cfg.strip() if proxy_cfg else 'direct'}_{final_verify}"
    if key not in _repeater_clients or _repeater_clients[key].is_closed:
        kwargs = {
            "verify": final_verify,
            "follow_redirects": True,
            "timeout": 30.0,
            "limits": httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=60.0)
        }
        if proxy_cfg and proxy_cfg.strip():
            kwargs["proxy"] = proxy_cfg.strip()
        _repeater_clients[key] = httpx.AsyncClient(**kwargs)
    return _repeater_clients[key]

# ==============================================================================
# Repeater Replay Endpoint
# ==============================================================================

@app.post("/api/repeater/send")
async def repeater_send_request(req: RepeaterSendRequest, db: Session = Depends(get_db)):
    """Executes a request manually via Repeater, saves to DB, triages, and returns full response."""
    import urllib.parse

    # 1. Scope check
    is_allowed, block_reason = check_scope(req.project, req.url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=block_reason)

    # 2. Upstream proxy & TLS verification lookup
    proj = db.query(Project).filter(Project.name == req.project.lower()).first()
    proxy_cfg = proj.upstream_proxy if proj and proj.upstream_proxy else os.getenv("SPECTRA_UPSTREAM_PROXY")
    verify_ssl = bool(proj.verify_ssl) if proj else False

    parsed = urllib.parse.urlparse(req.url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    start_time = time.time()
    status_code = 502
    res_headers = {}
    res_body = ""

    # Ensure valid headers dict
    req_headers = {str(k): str(v) for k, v in (req.headers or {}).items()}
    if "User-Agent" not in req_headers and "user-agent" not in req_headers:
        req_headers["User-Agent"] = "SpectraRepeater/1.3"

    try:
        client = await _get_repeater_client(proxy_cfg or "", verify_ssl=verify_ssl)
        content_bytes = req.body.encode("utf-8") if req.body else None
        response = await client.request(
            method=req.method.upper(),
            url=req.url,
            headers=req_headers,
            content=content_bytes
        )
        status_code = response.status_code
        res_headers = dict(response.headers)
        try:
            res_body = response.text[:5242880]
        except Exception:
            res_body = f"<Binary data: {len(response.content)} bytes>"
    except Exception as ex:
        status_code = 502
        res_body = f"Transport Error: {str(ex)}"

    duration_ms = int((time.time() - start_time) * 1000)

    log_payload = {
        "project": req.project,
        "agent_id": "operator_repeater",
        "source": "REPEATER",
        "method": req.method.upper(),
        "url": req.url,
        "host": host,
        "path": path,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "request_headers": req_headers,
        "request_body": req.body or "",
        "response_headers": res_headers,
        "response_body": res_body,
        "reasoning": "Manual operator Repeater replay"
    }

    log_entry = await record_and_broadcast_log(log_payload, db)
    return log_entry.to_dict(include_body=True)


# ==============================================================================
# Reporting & OpenAPI / HAR 1.2 Export Endpoints
# ==============================================================================

@app.get("/api/projects/{name}/export/har")
def export_har(name: str, db: Session = Depends(get_db)):
    """Exports project traffic into standard HTTP Archive (HAR 1.2) for Burp/ZAP."""
    har_data = generate_har_export(name, db)
    safe_filename = sanitize_attachment_filename(f"spectra_{name}_traffic", "har")
    return JSONResponse(
        content=har_data,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


@app.get("/api/projects/{name}/export/report")
def export_markdown_report(name: str, db: Session = Depends(get_db)):
    """Exports vulnerability findings into an executive Markdown report."""
    md_content = generate_markdown_report(name, db)
    safe_filename = sanitize_attachment_filename(f"spectra_{name}_report", "md")
    return PlainTextResponse(
        content=md_content,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


@app.get("/api/projects/{name}/export/openapi")
def export_openapi(name: str, db: Session = Depends(get_db)):
    """Generates and exports an OpenAPI 3.0.3 specification from observed project traffic."""
    spec_data = generate_openapi_spec(name, db)
    safe_filename = sanitize_attachment_filename(f"spectra_{name}_openapi", "json")
    return JSONResponse(
        content=spec_data,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


# ==============================================================================
# Parameter Fuzzer / Mini-Intruder Endpoints
# ==============================================================================

@app.get("/api/fuzzer/payloads")
def list_fuzzer_payloads():
    """Returns built-in attack dictionaries."""
    return {"categories": BUILTIN_PAYLOADS}


@app.post("/api/fuzzer/run")
async def run_fuzzer_attack_endpoint(req: RunFuzzRequest, db: Session = Depends(get_db)):
    """Executes multi-threaded parameter fuzzing with automated baseline differential analysis."""
    import re
    clean_url = re.sub(r"§[^§]*§", "", req.url)
    is_allowed, block_reason = check_scope(req.project, clean_url, db)
    if not is_allowed:
        raise HTTPException(status_code=403, detail=f"Target URL is out of authorized scope: {block_reason}")

    payloads = req.custom_payloads
    if not payloads or len(payloads) == 0:
        cat = (req.category or "sqli").lower()
        payloads = BUILTIN_PAYLOADS.get(cat, BUILTIN_PAYLOADS["sqli"])

    proj = db.query(Project).filter(Project.name == req.project.lower()).first()
    proxy = proj.upstream_proxy if proj and proj.upstream_proxy else os.getenv("SPECTRA_UPSTREAM_PROXY")

    req_concurrency = min(max(req.concurrency, 1), 10)
    if req.custom_payloads and len(req.custom_payloads) > 1000:
        raise HTTPException(status_code=400, detail="Custom payloads list exceeds security threshold of 1,000 entries.")

    results = await run_fuzz_attack(
        base_url=req.url,
        method=req.method,
        headers=req.headers,
        body=req.body,
        payloads=payloads,
        concurrency=req_concurrency,
        upstream_proxy=proxy
    )

    await ws_manager.broadcast({
        "type": "FUZZER_COMPLETED",
        "project": req.project,
        "total": results.get("total_payloads", 0),
        "anomalies": results.get("anomalies_detected", 0)
    })
    return results


# ==============================================================================
# Session Keep-Alive / Heartbeat Endpoints
# ==============================================================================

@app.get("/api/auth/keepalive/status")
def keepalive_status_endpoint():
    """Returns operational status of the background session keeper service."""
    return get_session_keeper_status()


@app.post("/api/auth/keepalive/toggle")
async def keepalive_toggle_endpoint(enabled: bool = Query(...)):
    """Starts or stops the background session heartbeat service."""
    if enabled:
        start_session_keeper(interval=120)
    else:
        stop_session_keeper()
    return get_session_keeper_status()



# ==============================================================================
# Core Traffic & Stats Endpoints
# ==============================================================================

@app.get("/api/stats")
def get_stats(project: Optional[str] = None, db: Session = Depends(get_db)):
    cache_key = (project or "ALL").upper()
    now = time.time()
    if cache_key in _STATS_CACHE:
        cache_time, cached_data = _STATS_CACHE[cache_key]
        if now - cache_time < 1.0:  # 1-second TTL to avoid 5 SQL count queries on rapid polling
            return cached_data

    log_query = db.query(HttpLog)
    finding_query = db.query(Finding).join(HttpLog)

    if project and project.upper() != "ALL":
        log_query = log_query.filter(HttpLog.project == project.lower())
        finding_query = finding_query.filter(HttpLog.project == project.lower())

    total_requests = log_query.with_entities(func.count(HttpLog.id)).scalar() or 0
    confirmed_findings = finding_query.filter(Finding.severity.in_(["HIGH", "CRITICAL"])).with_entities(func.count(Finding.id)).scalar() or 0
    potential_findings = finding_query.filter(Finding.severity.in_(["LOW", "MEDIUM", "INFO"])).with_entities(func.count(Finding.id)).scalar() or 0
    clean_logs = log_query.filter(HttpLog.flag_status == "CLEAN").with_entities(func.count(HttpLog.id)).scalar() or 0
    
    sess_query = db.query(ActiveSession)
    cmd_query = db.query(AgentCommandLog)
    payload_query = db.query(CapturedPayload)
    if project and project.upper() != "ALL":
        sess_query = sess_query.filter(ActiveSession.project == project.lower())
        cmd_query = cmd_query.filter(AgentCommandLog.project == project.lower())
        payload_query = payload_query.filter(CapturedPayload.project == project.lower())
    active_sessions = sess_query.with_entities(func.count(ActiveSession.id)).scalar() or 0
    total_commands = cmd_query.with_entities(func.count(AgentCommandLog.id)).scalar() or 0
    total_payloads = payload_query.with_entities(func.count(CapturedPayload.id)).scalar() or 0

    res = {
        "project": project or "ALL",
        "total_requests": total_requests,
        "confirmed_findings": confirmed_findings,
        "potential_findings": potential_findings,
        "clean_logs": clean_logs,
        "active_sessions": active_sessions,
        "total_commands": total_commands,
        "total_payloads": total_payloads,
        "intercept_enabled": is_intercept_enabled(),
        "interactive_login_active": get_active_login_status()
    }
    _STATS_CACHE[cache_key] = (now, res)
    return res


@app.get("/api/logs")
def list_logs(
    project: Optional[str] = None,
    agent: Optional[str] = None,
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = None,
    flag: Optional[str] = None,
    method: Optional[str] = None,
    db: Session = Depends(get_db)
):
    # Defer heavy body text columns so paginated listings don't load multi-megabytes into memory
    query = db.query(HttpLog).options(defer(HttpLog.request_body), defer(HttpLog.response_body))

    if project and project.upper() != "ALL":
        query = query.filter(HttpLog.project == project.lower())
    if agent and agent.upper() != "ALL":
        query = query.filter(HttpLog.agent_id == agent)
    if flag and flag.upper() != "ALL":
        query = query.filter(HttpLog.flag_status == flag.upper())
    if method and method.upper() != "ALL":
        query = query.filter(HttpLog.method == method.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (HttpLog.url.ilike(search_pattern)) |
            (HttpLog.host.ilike(search_pattern)) |
            (HttpLog.path.ilike(search_pattern))
        )

    total = query.count()
    logs = query.order_by(desc(HttpLog.id)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "project": project or "ALL",
        "agent": agent or "ALL",
        "limit": limit,
        "offset": offset,
        "logs": [log.to_dict(include_body=False) for log in logs]
    }


@app.get("/api/agents")
def list_agents(project: Optional[str] = None, db: Session = Depends(get_db)):
    """Returns list of unique agent IDs active in logged operations."""
    query = db.query(HttpLog.agent_id).distinct()
    if project and project.upper() != "ALL":
        query = query.filter(HttpLog.project == project.lower())
    agents = [r[0] for r in query.all() if r[0]]
    if "primary_agent" not in agents:
        agents.insert(0, "primary_agent")
    return {"agents": agents}



@app.get("/api/logs/{log_id}")
def get_log_detail(log_id: int, db: Session = Depends(get_db)):
    log_entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
    if not log_entry:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return log_entry.to_dict(include_body=True)


@app.get("/api/findings")
def list_findings(project: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Finding).join(HttpLog)
    if project and project.upper() != "ALL":
        query = query.filter(HttpLog.project == project.lower())

    findings = query.order_by(desc(Finding.id)).all()
    results = []
    for f in findings:
        item = f.to_dict()
        if f.log:
            item["project"] = f.log.project
            item["log"] = {
                "method": f.log.method,
                "url": f.log.url,
                "status_code": f.log.status_code,
                "timestamp": f.log.timestamp.isoformat() if f.log.timestamp else ""
            }
        results.append(item)
    return {"findings": results}


@app.post("/api/logs")
async def record_log_api(data: LogRecordRequest, db: Session = Depends(get_db)):
    log_entry = await record_and_broadcast_log(data.model_dump(), db)
    return {"status": "recorded", "id": log_entry.id, "project": log_entry.project, "flag_status": log_entry.flag_status}


@app.post("/api/logs/clear")
async def clear_logs(
    project: Optional[str] = None,
    req: Optional[ClearRequest] = None,
    db: Session = Depends(get_db)
):
    target_raw = project or (req.project if req else None)
    if target_raw and target_raw.upper() != "ALL":
        target_proj = target_raw.lower()
        log_ids = [l.id for l in db.query(HttpLog.id).filter(HttpLog.project == target_proj).all()]
        if log_ids:
            db.query(Finding).filter(Finding.log_id.in_(log_ids)).delete(synchronize_session=False)
            db.query(HttpLog).filter(HttpLog.project == target_proj).delete(synchronize_session=False)
        db.query(CapturedPayload).filter(CapturedPayload.project == target_proj).delete(synchronize_session=False)
        db.query(AgentCommandLog).filter(AgentCommandLog.project == target_proj).delete(synchronize_session=False)
        db.commit()
        _invalidate_stats_cache()
        await ws_manager.broadcast({"type": "LOGS_CLEARED", "project": target_proj})
        await ws_manager.broadcast({"type": "COMMANDS_CLEARED", "project": target_proj})
        await ws_manager.broadcast({"type": "PAYLOADS_CLEARED", "project": target_proj})
        return {"status": "cleared", "project": target_proj}
    else:
        db.query(Finding).delete()
        db.query(CapturedPayload).delete()
        db.query(AgentCommandLog).delete()
        db.query(HttpLog).delete()
        db.commit()
        _invalidate_stats_cache()
        await ws_manager.broadcast({"type": "LOGS_CLEARED", "project": "ALL"})
        await ws_manager.broadcast({"type": "COMMANDS_CLEARED", "project": "ALL"})
        await ws_manager.broadcast({"type": "PAYLOADS_CLEARED", "project": "ALL"})
        return {"status": "cleared", "project": "ALL"}


# ==============================================================================
# AI Command & Terminal Audit Trail Endpoints
# ==============================================================================

@app.get("/api/commands")
def list_commands(
    project: Optional[str] = None,
    agent: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(250, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(AgentCommandLog).options(defer(AgentCommandLog.stdout), defer(AgentCommandLog.stderr))
    if project and project.upper() != "ALL":
        query = query.filter(AgentCommandLog.project == project.lower())
    if agent and agent.upper() != "ALL":
        query = query.filter(AgentCommandLog.agent_id == agent)
    if status and status.upper() != "ALL":
        query = query.filter(AgentCommandLog.status == status.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (AgentCommandLog.command.ilike(search_pattern)) |
            (AgentCommandLog.reasoning.ilike(search_pattern))
        )
    total = query.count()
    commands = query.order_by(desc(AgentCommandLog.id)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "commands": [c.to_dict(include_output=False) for c in commands]
    }


@app.get("/api/commands/{cmd_id}")
def get_command_detail(cmd_id: int, db: Session = Depends(get_db)):
    """Fetch complete stdout and stderr for a selected command execution."""
    entry = db.query(AgentCommandLog).filter(AgentCommandLog.id == cmd_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Command log entry not found")
    return entry.to_dict(include_output=True)


@app.post("/api/commands")
async def record_command_api(data: RecordCommandRequest, db: Session = Depends(get_db)):
    proj = (data.project or "default").strip().lower()
    entry = AgentCommandLog(
        project=proj,
        agent_id=data.agent_id or "primary_agent",
        command=data.command,
        tool_name=data.tool_name or "terminal",
        reasoning=data.reasoning or "",
        exit_code=data.exit_code,
        stdout=(data.stdout or "")[:5242880],
        stderr=(data.stderr or "")[:5242880],
        duration_ms=data.duration_ms or 0,
        status=data.status or "SUCCESS",
        linked_log_id=data.linked_log_id
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    cmd_dict = entry.to_dict()
    await ws_manager.broadcast({
        "type": "NEW_COMMAND",
        "project": proj,
        "command": cmd_dict
    })
    return cmd_dict


@app.post("/api/commands/clear")
async def clear_commands(
    project: Optional[str] = None,
    req: Optional[ClearRequest] = None,
    db: Session = Depends(get_db)
):
    target_raw = project or (req.project if req else None)
    if target_raw and target_raw.upper() != "ALL":
        target = target_raw.lower()
        db.query(AgentCommandLog).filter(AgentCommandLog.project == target).delete(synchronize_session=False)
    else:
        target = "ALL"
        db.query(AgentCommandLog).delete(synchronize_session=False)
    db.commit()
    _invalidate_stats_cache()
    await ws_manager.broadcast({"type": "COMMANDS_CLEARED", "project": target})
    return {"status": "cleared", "project": target}


# ==============================================================================
# Captured Security Payload Vault Endpoints
# ==============================================================================

@app.get("/api/payloads")
def list_payloads(
    project: Optional[str] = None,
    agent: Optional[str] = None,
    vuln_type: Optional[str] = None,
    outcome: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(250, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(CapturedPayload)
    if project and project.upper() != "ALL":
        query = query.filter(CapturedPayload.project == project.lower())
    if agent and agent.upper() != "ALL":
        query = query.filter(CapturedPayload.agent_id == agent)
    if vuln_type and vuln_type.upper() != "ALL":
        query = query.filter(CapturedPayload.vuln_type == vuln_type.upper())
    if outcome and outcome.upper() != "ALL":
        query = query.filter(CapturedPayload.outcome == outcome.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (CapturedPayload.raw_payload.ilike(search_pattern)) |
            (CapturedPayload.target_param.ilike(search_pattern)) |
            (CapturedPayload.target_url.ilike(search_pattern)) |
            (CapturedPayload.notes.ilike(search_pattern))
        )
    total = query.count()
    payloads = query.order_by(desc(CapturedPayload.id)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "payloads": [p.to_dict() for p in payloads]
    }


@app.post("/api/payloads")
async def record_payload_api(data: RecordPayloadRequest, db: Session = Depends(get_db)):
    proj = (data.project or "default").strip().lower()
    entry = CapturedPayload(
        project=proj,
        agent_id=data.agent_id or "primary_agent",
        vuln_type=(data.vuln_type or "CUSTOM").upper(),
        target_param=data.target_param or "",
        raw_payload=data.raw_payload,
        mutation_type=data.mutation_type or "DIRECT",
        target_url=data.target_url or "",
        http_method=(data.http_method or "GET").upper(),
        http_log_id=data.http_log_id,
        outcome=data.outcome or "TESTED",
        http_status=data.http_status,
        response_signature=data.response_signature or "",
        notes=data.notes or ""
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    p_dict = entry.to_dict()
    await ws_manager.broadcast({
        "type": "NEW_PAYLOAD",
        "project": proj,
        "payload": p_dict
    })
    return p_dict


@app.post("/api/payloads/clear")
async def clear_payloads(
    project: Optional[str] = None,
    req: Optional[ClearRequest] = None,
    db: Session = Depends(get_db)
):
    target_raw = project or (req.project if req else None)
    if target_raw and target_raw.upper() != "ALL":
        target = target_raw.lower()
        db.query(CapturedPayload).filter(CapturedPayload.project == target).delete(synchronize_session=False)
    else:
        target = "ALL"
        db.query(CapturedPayload).delete(synchronize_session=False)
    db.commit()
    _invalidate_stats_cache()
    await ws_manager.broadcast({"type": "PAYLOADS_CLEARED", "project": target})
    return {"status": "cleared", "project": target}


# ==============================================================================
# Authentication & HITL Endpoints
# ==============================================================================

@app.post("/api/auth/spawn")
async def trigger_spawn_login(req: SpawnAuthRequest, background_tasks: BackgroundTasks):
    async def cookie_callback(domain: str, count: int):
        await ws_manager.broadcast({
            "type": "AUTH_COOKIES_UPDATED",
            "project": req.project,
            "domain": domain,
            "cookie_count": count
        })

    async def run_worker():
        try:
            await ws_manager.broadcast({
                "type": "AUTH_SPAWNED",
                "project": req.project,
                "login_url": req.login_url,
                "domain": req.target_domain
            })
            result = await spawn_interactive_login(
                login_url=req.login_url,
                target_domain=req.target_domain,
                project=req.project,
                browser_choice=req.browser_choice or "chrome",
                on_cookie_update=cookie_callback
            )
            await ws_manager.broadcast({
                "type": "AUTH_COMPLETED",
                "project": req.project,
                "result": result
            })
        except Exception as ex:
            await ws_manager.broadcast({
                "type": "AUTH_ERROR",
                "project": req.project,
                "error": str(ex)
            })

    background_tasks.add_task(run_worker)
    return {
        "status": "spawning",
        "project": req.project,
        "message": "Headed Chromium browser launched. Complete login on screen."
    }


@app.post("/api/auth/cookies/import")
async def import_cookies_endpoint(req: ImportCookiesRequest):
    """
    Directly imports session cookies from:
    - document.cookie string (from DevTools or JS Bookmarklet)
    - Full cURL request (-H 'Cookie: ...')
    - HTTP Request Header block (Cookie: ...)
    - JSON cookies array (from Cookie-Editor extension or Playwright)
    """
    target_input = (req.raw_cookie or req.raw_input or "").strip()
    if not target_input:
        raise HTTPException(status_code=400, detail="Empty cookie input provided.")

    target_domain = (req.domain or "").strip()
    if not target_domain:
        # Fallback domain inference if possible
        target_domain = "target.local"

    proj = (req.project or "default").strip().lower()
    res = import_session_cookies(
        project=proj,
        domain=target_domain,
        raw_input=target_input
    )

    await ws_manager.broadcast({
        "type": "AUTH_COMPLETED",
        "project": proj,
        "result": res
    })

    return res


@app.post("/api/auth/confirm")
async def confirm_auth_session(req: ConfirmAuthRequest):
    signaled = signal_login_confirmation(req.domain)
    return {
        "status": "signaled" if signaled else "no_active_login",
        "message": "Session capture triggered." if signaled else "No pending login session found."
    }


@app.get("/api/auth/session")
def inspect_session(project: Optional[str] = None, show_tokens: bool = False, db: Session = Depends(get_db)):
    query = db.query(ActiveSession)
    if project and project.upper() != "ALL":
        query = query.filter(ActiveSession.project == project.lower())
    sessions = query.order_by(desc(ActiveSession.updated_at)).all()
    return {"sessions": [s.to_dict(include_secrets=show_tokens) for s in sessions]}


@app.delete("/api/auth/session/id/{session_id}")
def remove_session_by_id(session_id: int, db: Session = Depends(get_db)):
    """Revokes and deletes an active session by its unique database ID."""
    deleted = db.query(ActiveSession).filter(ActiveSession.id == session_id).delete(synchronize_session=False)
    db.commit()
    if deleted == 0:
        raise HTTPException(status_code=404, detail=f"Session with ID {session_id} not found.")
    return {"status": "deleted", "id": session_id, "count": deleted}


@app.delete("/api/auth/session/{session_id:int}/cookie/{cookie_name}")
def remove_single_cookie(session_id: int, cookie_name: str, db: Session = Depends(get_db)):
    """Revokes a specific cookie key from an active session."""
    session_obj = db.query(ActiveSession).filter(ActiveSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail=f"Session ID {session_id} not found.")
    
    state = session_obj.get_decrypted_state()
    cookies = state.get("cookies", [])
    initial_len = len(cookies)
    cookies = [c for c in cookies if c.get("name") != cookie_name]
    state["cookies"] = cookies
    session_obj.set_encrypted_state(state)
    session_obj.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "updated", "id": session_id, "removed_cookie": cookie_name, "remaining_cookies": len(cookies)}


@app.delete("/api/auth/session/{domain:path}")
def remove_session_by_domain(domain: str, db: Session = Depends(get_db)):
    """Revokes and deletes active sessions matching a target domain."""
    raw_domain = urllib.parse.unquote(domain).strip().lower()
    clean_domain = raw_domain.lstrip(".")
    deleted = db.query(ActiveSession).filter(
        or_(
            ActiveSession.domain == raw_domain,
            ActiveSession.domain == clean_domain,
            ActiveSession.domain == f".{clean_domain}",
            ActiveSession.domain.ilike(f"%{clean_domain}%")
        )
    ).delete(synchronize_session=False)
    db.commit()
    return {"status": "deleted", "domain": raw_domain, "count": deleted}


@app.post("/api/auth/session/clear")
def clear_all_sessions(project: Optional[str] = None, db: Session = Depends(get_db)):
    """Clears all stored active sessions."""
    query = db.query(ActiveSession)
    if project and project.upper() != "ALL":
        query = query.filter(ActiveSession.project == project.lower())
    count = query.delete(synchronize_session=False)
    db.commit()
    return {"status": "cleared", "count": count, "project": project or "ALL"}


# ==============================================================================
# Static Dashboard Hosting
# ==============================================================================

@app.get("/")
def serve_index():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file, media_type="text/html")
    return JSONResponse({"status": "Frontend not yet generated. Please create frontend/index.html"}, status_code=404)
