"""
Spectra Client SDK - Micro-helper for OpenCode & Hermes Custom Pentest Scripts
Enables custom scripts to route traffic through Spectra Proxy with automatic session injection,
and provides programmatic reporting back to the Spectra Dashboard.
"""

import os
import requests
from typing import Optional, Dict, Any

SPECTRA_PROXY_PORT = os.getenv("SPECTRA_PROXY_PORT", "8088")
SPECTRA_PROXY_URL = os.getenv("HTTP_PROXY", f"http://127.0.0.1:{SPECTRA_PROXY_PORT}")
SPECTRA_PROJECT = os.getenv("SPECTRA_PROJECT", "default")
SPECTRA_BACKEND_URL = os.getenv("SPECTRA_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")


class SpectraSession(requests.Session):
    """
    Drop-in replacement for requests.Session that automatically routes through Spectra Forward Proxy,
    injects Spectra project/agent metadata headers, and disables SSL warning noise during testing.
    """
    def __init__(self, project: Optional[str] = None, agent_id: str = "primary_agent"):
        super().__init__()
        self.project = (project or SPECTRA_PROJECT).strip().lower()
        self.agent_id = agent_id
        self.proxies = {
            "http": SPECTRA_PROXY_URL,
            "https": SPECTRA_PROXY_URL
        }
        self.verify = False
        self.headers.update({
            "X-Spectra-Project": self.project,
            "X-Spectra-Agent": self.agent_id
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
        """Programmatically records a confirmed vulnerability directly into Spectra Findings Ledger."""
        try:
            resp = requests.post(
                f"{SPECTRA_BACKEND_URL}/api/findings",
                json={
                    "title": title,
                    "severity": severity.upper(),
                    "category": category,
                    "evidence": str(evidence),
                    "remediation": remediation,
                    "description": description or f"Reported by custom agent script via Spectra SDK",
                    "project": self.project
                },
                timeout=3.0
            )
            return resp.status_code == 200
        except Exception:
            return False


# Functional convenience shortcuts
def get(url: str, **kwargs) -> requests.Response:
    with SpectraSession() as s:
        return s.get(url, **kwargs)

def post(url: str, **kwargs) -> requests.Response:
    with SpectraSession() as s:
        return s.post(url, **kwargs)

def put(url: str, **kwargs) -> requests.Response:
    with SpectraSession() as s:
        return s.put(url, **kwargs)

def delete(url: str, **kwargs) -> requests.Response:
    with SpectraSession() as s:
        return s.delete(url, **kwargs)
