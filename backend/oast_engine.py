"""
Spectra / AetherGate - OAST (Out-of-Band Application Security Testing) Engine
Handles generation of unique correlation tokens, listener endpoints,
and real-time callback capture for Blind SSRF, Blind SQLi, Out-of-Band RCE, and DNS queries.
"""

import os
import json
import uuid
import time
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.database import SessionLocal, OastEvent, Project

# In-memory listeners for active polling: token -> asyncio.Event
_active_waiters: Dict[str, asyncio.Event] = {}
# Registry mapping token -> metadata (project, vuln_type, description)
_token_registry: Dict[str, Dict[str, Any]] = {}
_runtime_callback_url: Optional[str] = None

def set_base_callback_url(url: str):
    """Dynamically sets the public/custom URL for OAST callback delivery (e.g. ngrok or VPS)."""
    global _runtime_callback_url
    _runtime_callback_url = url.strip().rstrip("/") if url else None

def get_base_callback_url() -> str:
    """Returns the external or local URL for receiving out-of-band callbacks."""
    if _runtime_callback_url:
        return _runtime_callback_url
    custom_url = os.getenv("SPECTRA_OAST_CALLBACK_URL", "").strip().rstrip("/")
    if custom_url:
        return custom_url
    backend_url = os.getenv("SPECTRA_BACKEND_URL", "http://127.0.0.1:8000").strip().rstrip("/")
    return backend_url


def generate_oast_token(
    project: str = "default",
    description: str = "",
    vuln_type: str = "BLIND_CALLBACK"
) -> Dict[str, Any]:
    """
    Generates a unique OAST interaction token and correlation metadata.
    AI agents use this token to craft out-of-band payloads (SSRF, Blind SQLi, JNDI, XXE, RCE).
    """
    token = uuid.uuid4().hex[:12]
    base_url = get_base_callback_url()
    callback_url = f"{base_url}/oast/{token}"
    dns_hostname = f"{token}.oast.spectra.local"
    target_project = (project or "default").strip().lower()

    # Pre-register waiter event in memory
    _active_waiters[token] = asyncio.Event()
    _token_registry[token] = {
        "project": target_project,
        "description": description or f"OAST correlation token for {vuln_type}",
        "vuln_type": vuln_type.upper()
    }

    return {
        "token": token,
        "callback_url": callback_url,
        "http_url": callback_url,
        "dns_hostname": dns_hostname,
        "curl_test": f"curl -s {callback_url}",
        "vuln_type": vuln_type.upper(),
        "project": target_project,
        "description": description or f"OAST correlation token for {vuln_type}",
        "created_at": datetime.now().isoformat()
    }


def record_oast_hit(
    token: str,
    client_ip: str = "127.0.0.1",
    method: str = "GET",
    path: str = "",
    headers: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, Any]] = None,
    body: str = "",
    protocol: str = "HTTP",
    project: str = "default",
    description: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Persists an incoming out-of-band interaction into SQLite and triggers any active polling agents.
    """
    db = SessionLocal()
    try:
        clean_token = token.strip()
        reg = _token_registry.get(clean_token, {})
        effective_project = reg.get("project") or (project or "default").strip().lower()
        effective_vuln = reg.get("vuln_type") or "BLIND_INTERACTION"
        effective_desc = description or reg.get("description") or f"Incoming {protocol} callback from {client_ip}"

        headers_json = json.dumps(headers or {})
        params_json = json.dumps(query_params or {})

        event = OastEvent(
            project=effective_project,
            token=clean_token,
            vuln_type=effective_vuln,
            protocol=protocol.upper(),
            client_ip=client_ip,
            method=method.upper(),
            path=path or f"/oast/{clean_token}",
            request_headers=headers_json,
            query_params=params_json,
            request_body=(body or "")[:65536],  # Store up to 64 KB of exfiltrated data
            description=effective_desc
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        event_dict = event.to_dict()

        # Signal in-memory waiter if an agent is waiting on this token
        if clean_token in _active_waiters:
            _active_waiters[clean_token].set()

        return event_dict
    except Exception as ex:
        db.rollback()
        return None
    finally:
        db.close()


async def poll_oast_events(
    token: str,
    project: str = "default",
    timeout_seconds: float = 5.0
) -> List[Dict[str, Any]]:
    """
    Polls for callbacks matching token. If none exist immediately, waits asynchronously
    up to timeout_seconds for an incoming callback before returning.
    """
    clean_token = token.strip()
    target_project = (project or "default").strip().lower()

    # 1. Quick check database
    db = SessionLocal()
    try:
        events = db.query(OastEvent).filter(
            OastEvent.token == clean_token
        ).order_by(OastEvent.id.desc()).all()
        if events:
            return [e.to_dict() for e in events]
    finally:
        db.close()

    # 2. If no event yet, register or retrieve asyncio.Event waiter
    if clean_token not in _active_waiters:
        _active_waiters[clean_token] = asyncio.Event()

    waiter = _active_waiters[clean_token]
    try:
        await asyncio.wait_for(waiter.wait(), timeout=max(0.5, float(timeout_seconds)))
    except asyncio.TimeoutError:
        pass

    # 3. Re-query database after waiting
    db = SessionLocal()
    try:
        events = db.query(OastEvent).filter(
            OastEvent.token == clean_token
        ).order_by(OastEvent.id.desc()).all()
        return [e.to_dict() for e in events]
    finally:
        db.close()


def list_recent_oast_events(project: str = "default", limit: int = 50) -> List[Dict[str, Any]]:
    """Returns recent OAST callbacks for the dashboard or agent."""
    db = SessionLocal()
    try:
        query = db.query(OastEvent)
        if project and project.upper() != "ALL":
            query = query.filter(OastEvent.project == project.lower())
        events = query.order_by(OastEvent.id.desc()).limit(min(limit, 200)).all()
        return [e.to_dict() for e in events]
    finally:
        db.close()
