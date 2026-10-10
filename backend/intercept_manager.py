"""
Spectra MCP - Intercept & Scope Guardrail Manager
Manages real-time request traps (breakpoints) and out-of-scope domain boundaries.
"""

import re
import json
import uuid
import asyncio
import fnmatch
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from sqlalchemy.orm import Session
from backend.database import Project

# ==============================================================================
# Intercept Trap State
# ==============================================================================

_intercept_enabled: bool = False
_pending_intercepts: Dict[str, Dict[str, Any]] = {}


def is_intercept_enabled() -> bool:
    return _intercept_enabled


def set_intercept_mode(enabled: bool) -> bool:
    global _intercept_enabled
    _intercept_enabled = enabled
    return _intercept_enabled


def get_intercept_status() -> Dict[str, Any]:
    pending_list = []
    for i_id, item in list(_pending_intercepts.items()):
        req = item["request_data"]
        pending_list.append({
            "id": i_id,
            "project": req.get("project", "default"),
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "headers": req.get("headers", {}),
            "body": req.get("body", ""),
            "reasoning": req.get("reasoning", ""),
            "timestamp": item.get("created_at", "")
        })
    return {
        "enabled": _intercept_enabled,
        "pending_count": len(pending_list),
        "pending": pending_list
    }


def create_intercept_trap(request_data: Dict[str, Any]) -> Tuple[str, asyncio.Event]:
    """Registers an intercepted request and provides an asyncio.Event to wait on."""
    intercept_id = str(uuid.uuid4())[:8]
    event = asyncio.Event()
    _pending_intercepts[intercept_id] = {
        "event": event,
        "request_data": request_data,
        "decision": "pending",  # "forward", "drop"
        "modified_data": None,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    return intercept_id, event


def resolve_intercept_trap(
    intercept_id: str,
    action: str,
    modified_data: Optional[Dict[str, Any]] = None
) -> bool:
    """Releases a waiting intercept trap with operator decision."""
    if intercept_id not in _pending_intercepts:
        return False

    item = _pending_intercepts[intercept_id]
    item["decision"] = action.lower()
    item["modified_data"] = modified_data
    item["event"].set()
    return True


def pop_intercept_result(intercept_id: str) -> Optional[Dict[str, Any]]:
    return _pending_intercepts.pop(intercept_id, None)


# ==============================================================================
# Scope & Guardrail Engine
# ==============================================================================

def check_scope(project_name: str, url: str, db: Session) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a URL is within the authorized scope of a project.
    Returns: (is_allowed: bool, reason_if_blocked: str | None)
    """
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.netloc or "").split(":")[0].lower()
        full_path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    except Exception as ex:
        return False, f"Malformed target URL: {str(ex)}"

    project = db.query(Project).filter(Project.name == project_name.lower()).first()
    if not project or not project.scope_enabled:
        return True, None

    # 1. Check Blocked Regex Patterns (Anti-destructive / Out-of-bounds keywords)
    try:
        blocked_list = json.loads(project.blocked_patterns) if project.blocked_patterns else []
    except Exception:
        blocked_list = []

    for pattern in blocked_list:
        if not pattern:
            continue
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            if regex.search(full_path) or regex.search(url):
                return False, f"Blocked by guardrail: URL or path matches restricted pattern '{pattern}'"
        except Exception:
            if pattern.lower() in url.lower():
                return False, f"Blocked by guardrail: URL contains restricted keyword '{pattern}'"

    # 2. Check Allowed Hosts (Domain Boundaries)
    try:
        allowed_list = json.loads(project.allowed_hosts) if project.allowed_hosts else ["*"]
    except Exception:
        allowed_list = ["*"]

    if "*" in allowed_list or "all" in allowed_list:
        return True, None

    host_allowed = False
    for allowed_pattern in allowed_list:
        allowed_pattern = allowed_pattern.strip().lower()
        if fnmatch.fnmatch(host, allowed_pattern):
            host_allowed = True
            break

    if not host_allowed:
        return False, f"Out of Scope: Host '{host}' is not in allowed target domains {allowed_list} for project '{project_name}'"

    return True, None
