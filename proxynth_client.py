"""
Proxynth Client SDK - Micro-helper for AI Agents & Custom Pentest Scripts
Enables custom scripts to route traffic through Proxynth Proxy with automatic session injection,
and provides programmatic reporting back to the Proxynth Dashboard.
"""

import os
import requests
from typing import Optional, Dict, Any

PROXSYNTH_PROXY_PORT = os.getenv("PROXSYNTH_PROXY_PORT", "8088")
PROXSYNTH_PROXY_URL = os.getenv("HTTP_PROXY", f"http://127.0.0.1:{PROXSYNTH_PROXY_PORT}")
PROXSYNTH_PROJECT = os.getenv("PROXSYNTH_PROJECT", "default")
PROXSYNTH_BACKEND_URL = os.getenv("PROXSYNTH_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")


class ProxynthSession(requests.Session):
    """
    Drop-in replacement for requests.Session that automatically routes through Proxynth Forward Proxy,
    injects Proxynth project/agent metadata headers, and disables SSL warning noise during testing.
    """
    def __init__(self, project: Optional[str] = None, agent_id: str = "primary_agent"):
        super().__init__()
        self.project = (project or PROXSYNTH_PROJECT).strip().lower()
        self.agent_id = agent_id
        self.proxies = {
            "http": PROXSYNTH_PROXY_URL,
            "https": PROXSYNTH_PROXY_URL
        }
        self.verify = False
        self.headers.update({
            "X-Proxynth-Project": self.project,
            "X-Proxynth-Agent": self.agent_id
        })

    def report_finding(
        self,
        title: str,
        severity: str = "HIGH",
        category: str = "Custom Script Finding",
        evidence: str = "",
        remediation: str = "",
        description: str = ""
    ) -> bool:
        """Programmatically records a confirmed vulnerability directly into Proxynth Findings Ledger."""
        try:
            resp = requests.post(
                f"{PROXSYNTH_BACKEND_URL}/api/findings",
                json={
                    "title": title,
                    "severity": severity.upper(),
                    "category": category,
                    "evidence": str(evidence),
                    "remediation": remediation,
                    "description": description or "Reported by custom agent script via Proxynth SDK",
                    "project": self.project
                },
                timeout=3.0
            )
            return resp.status_code == 200
        except Exception:
            return False
