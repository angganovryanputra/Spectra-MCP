"""
Proxynth - Exploit Path Chaining Graph Engine
Synthesizes verified findings, assets, credentials, and open attack surfaces
into causal, multi-stage attack paths (Kill Chains) leading to Crown Jewel compromise.
"""

from typing import Dict, Any, List, Optional
from backend.database import (
    SessionLocal,
    TargetAsset,
    TargetService,
    TargetEndpoint,
    Finding,
    HttpLog,
    ActiveSession
)


SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10
}


def build_attack_path_graph(project: str = "default") -> Dict[str, Any]:
    """
    Constructs an interconnected attack path graph linking:
    [Attacker / External Entry] -> [Exposed Asset/Service] -> [Target Route] -> [Vulnerability Finding] -> [Crown Jewels / Impact]
    """
    target_project = (project or "default").strip().lower()

    db = SessionLocal()
    try:
        assets = db.query(TargetAsset).filter(TargetAsset.project == target_project).all()
        findings = db.query(Finding).join(HttpLog).filter(HttpLog.project == target_project).all()
        sessions = db.query(ActiveSession).filter(ActiveSession.project == target_project).all()

        nodes = []
        edges = []
        chains = []

        # 1. Entry Point Node
        entry_node_id = "node_entry"
        nodes.append({
            "id": entry_node_id,
            "label": "External Attacker / AI Agent",
            "type": "ENTRY_POINT",
            "severity": "INFO"
        })

        asset_map = {}
        for a in assets:
            a_node_id = f"asset_{a.id}"
            asset_map[a.host] = a_node_id
            nodes.append({
                "id": a_node_id,
                "label": f"Host: {a.host} ({a.ip or 'Public'})",
                "type": "ASSET",
                "details": f"OS: {a.os_info or 'Unknown'}",
                "severity": "INFO"
            })
            # Connect Entry -> Asset
            edges.append({
                "from": entry_node_id,
                "to": a_node_id,
                "relationship": "INTERNET_FACING"
            })

            # Connect Services & Endpoints
            for svc in (a.services or []):
                svc_node_id = f"svc_{svc.id}"
                nodes.append({
                    "id": svc_node_id,
                    "label": f"Port {svc.port}/{svc.protocol} ({svc.service_name})",
                    "type": "SERVICE",
                    "severity": "INFO"
                })
                edges.append({
                    "from": a_node_id,
                    "to": svc_node_id,
                    "relationship": "EXPOSES_PORT"
                })

            for ep in (a.endpoints or []):
                if ep.tested_status in ["VULNERABLE", "TESTED", "IN_PROGRESS"]:
                    ep_node_id = f"ep_{ep.id}"
                    nodes.append({
                        "id": ep_node_id,
                        "label": f"{ep.method} {ep.path}",
                        "type": "ENDPOINT",
                        "severity": "HIGH" if ep.tested_status == "VULNERABLE" else "LOW"
                    })
                    edges.append({
                        "from": a_node_id,
                        "to": ep_node_id,
                        "relationship": "ROUTES_TO"
                    })

        # 2. Findings & Exploitation Nodes
        finding_nodes = []
        for f in findings:
            f_node_id = f"vuln_{f.id}"
            f_sev = (f.severity or "MEDIUM").upper()
            nodes.append({
                "id": f_node_id,
                "label": f"[{f_sev}] {f.title}",
                "type": "VULNERABILITY",
                "severity": f_sev,
                "category": f.category
            })
            finding_nodes.append((f, f_node_id))

            # Connect Finding to originating Host / Endpoint
            if f.log and f.log.host:
                host_node_id = asset_map.get(f.log.host.lower())
                if host_node_id:
                    edges.append({
                        "from": host_node_id,
                        "to": f_node_id,
                        "relationship": "EXPLOITS"
                    })

            # Connect Findings to Crown Jewel / Impact Nodes
            cat_upper = (f.category or "").upper()
            title_upper = (f.title or "").upper()

            impact_label = None
            if "RCE" in title_upper or "COMMAND" in cat_upper:
                impact_label = "Crown Jewel: Host Takeover / Remote Code Execution"
            elif "SQL" in title_upper or "INJECTION" in cat_upper:
                impact_label = "Crown Jewel: Database Exfiltration & Data Tampering"
            elif "SSRF" in title_upper:
                impact_label = "Crown Jewel: Internal Network Pivot / Cloud Metadata Leak"
            elif "BOLA" in title_upper or "IDOR" in cat_upper:
                impact_label = "Crown Jewel: Horizontal Account Takeover / PII Breach"
            elif "AUTH" in cat_upper or "BYPASS" in title_upper:
                impact_label = "Crown Jewel: Administrative Privilege Escalation"

            if impact_label:
                impact_node_id = f"impact_{f.id}"
                nodes.append({
                    "id": impact_node_id,
                    "label": impact_label,
                    "type": "CROWN_JEWEL",
                    "severity": "CRITICAL"
                })
                edges.append({
                    "from": f_node_id,
                    "to": impact_node_id,
                    "relationship": "ACHIEVES_IMPACT"
                })

                # Register complete attack chain
                chains.append({
                    "target_impact": impact_label,
                    "severity": f_sev,
                    "exploit_step": f.title,
                    "target_host": f.log.host if f.log else "Unknown",
                    "path_nodes": [entry_node_id, host_node_id or "target", f_node_id, impact_node_id]
                })

        # Generate Mermaid Diagram
        mermaid_lines = ["flowchart LR"]
        for n in nodes:
            safe_label = n["label"].replace('"', "'")
            shape_start, shape_end = ("[", "]")
            if n["type"] == "ENTRY_POINT":
                shape_start, shape_end = ("([", "])")
            elif n["type"] == "VULNERABILITY":
                shape_start, shape_end = ("{{", "}}")
            elif n["type"] == "CROWN_JEWEL":
                shape_start, shape_end = ("[[", "]]")

            mermaid_lines.append(f'    {n["id"]}{shape_start}"{safe_label}"{shape_end}')

        for e in edges:
            mermaid_lines.append(f'    {e["from"]} -->|"{e["relationship"]}"| {e["to"]}')

        mermaid_code = "\n".join(mermaid_lines)

        return {
            "project": target_project,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_chains": len(chains),
            "critical_chains": [c for c in chains if c["severity"] in ["CRITICAL", "HIGH"]],
            "mermaid": mermaid_code,
            "nodes": nodes,
            "edges": edges,
            "chains": chains
        }
    finally:
        db.close()
