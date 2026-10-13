"""
Spectra / AetherGate - Target Knowledge Graph & Attack Surface Manager
Maintains stateful inventory of targets, hosts, ports, services, endpoints,
and testing progression (Untested -> In Progress -> Tested -> Vulnerable).
"""

import os
import json
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from backend.database import SessionLocal, TargetAsset, TargetService, TargetEndpoint, Finding, HttpLog


def upsert_target_asset(
    project: str = "default",
    host: str = "",
    ip: str = "",
    os_info: str = "",
    tags: Optional[List[str]] = None,
    notes: str = ""
) -> Dict[str, Any]:
    """Creates or updates a target host in the attack surface graph."""
    clean_host = host.strip().lower()
    if not clean_host:
        raise ValueError("Host cannot be empty")
    
    # Strip scheme or port if accidentally supplied in host
    if "://" in clean_host:
        clean_host = urllib.parse.urlparse(clean_host).netloc
    clean_host = clean_host.split(":")[0].strip("/")

    target_project = (project or "default").strip().lower()
    tags_str = ",".join([t.strip() for t in tags]) if tags else ""

    db = SessionLocal()
    try:
        asset = db.query(TargetAsset).filter(
            TargetAsset.project == target_project,
            TargetAsset.host == clean_host
        ).first()

        if asset:
            if ip:
                asset.ip = ip.strip()
            if os_info:
                asset.os_info = os_info.strip()
            if tags_str:
                existing_tags = set(asset.tags.split(",")) if asset.tags else set()
                new_tags = existing_tags.union(set([t.strip() for t in tags if t.strip()]))
                asset.tags = ",".join(new_tags)
            if notes:
                asset.notes = notes.strip()
            asset.updated_at = datetime.now()
        else:
            asset = TargetAsset(
                project=target_project,
                host=clean_host,
                ip=ip.strip() if ip else None,
                os_info=os_info.strip(),
                tags=tags_str,
                notes=notes.strip()
            )
            db.add(asset)

        db.commit()
        db.refresh(asset)
        return asset.to_dict()
    finally:
        db.close()


def add_or_update_service(
    project: str = "default",
    host: str = "",
    port: int = 80,
    protocol: str = "tcp",
    service_name: str = "unknown",
    banner: str = "",
    state: str = "open"
) -> Dict[str, Any]:
    """Associates an open/filtered port and service to a target asset."""
    target_project = (project or "default").strip().lower()
    asset_dict = upsert_target_asset(project=target_project, host=host)

    db = SessionLocal()
    try:
        service = db.query(TargetService).filter(
            TargetService.asset_id == asset_dict["id"],
            TargetService.port == int(port)
        ).first()

        if service:
            service.protocol = (protocol or "tcp").lower()
            if service_name and service_name != "unknown":
                service.service_name = service_name.lower()
            if banner:
                service.banner = banner.strip()
            service.state = (state or "open").lower()
        else:
            service = TargetService(
                asset_id=asset_dict["id"],
                port=int(port),
                protocol=(protocol or "tcp").lower(),
                service_name=(service_name or "unknown").lower(),
                banner=banner.strip() if banner else "",
                state=(state or "open").lower()
            )
            db.add(service)

        db.commit()
        db.refresh(service)
        return service.to_dict()
    finally:
        db.close()


def add_or_update_endpoint(
    project: str = "default",
    host: str = "",
    url: str = "",
    method: str = "GET",
    parameters: Optional[List[str]] = None,
    auth_required: bool = False,
    tested_status: str = "UNTESTED",
    notes: str = ""
) -> Dict[str, Any]:
    """Records a discovered web endpoint under a target asset."""
    target_project = (project or "default").strip().lower()
    clean_method = (method or "GET").upper().strip()

    parsed = urllib.parse.urlparse(url)
    clean_host = host.strip().lower() or (parsed.netloc or "").split(":")[0].strip().lower()
    if not clean_host:
        raise ValueError("Target host or valid URL must be provided")

    path = parsed.path or "/"

    # Auto-extract query param keys if parameters not explicitly provided
    if parameters is None and parsed.query:
        query_dict = urllib.parse.parse_qs(parsed.query)
        parameters = list(query_dict.keys())

    asset_dict = upsert_target_asset(project=target_project, host=clean_host)

    db = SessionLocal()
    try:
        endpoint = db.query(TargetEndpoint).filter(
            TargetEndpoint.asset_id == asset_dict["id"],
            TargetEndpoint.method == clean_method,
            TargetEndpoint.path == path
        ).first()

        params_json = json.dumps(parameters or [])

        if endpoint:
            endpoint.url = url
            endpoint.auth_required = bool(auth_required)
            if parameters:
                endpoint.parameters = params_json
            if tested_status:
                endpoint.tested_status = tested_status.upper()
            if notes:
                endpoint.notes = notes
        else:
            endpoint = TargetEndpoint(
                asset_id=asset_dict["id"],
                method=clean_method,
                path=path,
                url=url,
                auth_required=bool(auth_required),
                parameters=params_json,
                tested_status=(tested_status or "UNTESTED").upper(),
                notes=notes or ""
            )
            db.add(endpoint)

        db.commit()
        db.refresh(endpoint)
        return endpoint.to_dict()
    finally:
        db.close()


def get_attack_surface_graph(
    project: str = "default",
    host: Optional[str] = None
) -> Dict[str, Any]:
    """
    Returns high-level graph topology of the attack surface:
    Assets, Services, Endpoints, Tested Status, and Findings counts.
    """
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        query = db.query(TargetAsset)
        if target_project and target_project.upper() != "ALL":
            query = query.filter(TargetAsset.project == target_project)
        if host:
            clean_host = host.strip().lower()
            query = query.filter(TargetAsset.host.ilike(f"%{clean_host}%"))

        assets = query.all()
        assets_data = [a.to_dict() for a in assets]

        total_assets = len(assets_data)
        total_services = sum(a.get("services_count", 0) for a in assets_data)
        total_endpoints = sum(a.get("endpoints_count", 0) for a in assets_data)

        # Count testing status across all endpoints
        untested_count = 0
        tested_count = 0
        vulnerable_count = 0

        for a in assets_data:
            for ep in a.get("endpoints", []):
                st = ep.get("tested_status", "UNTESTED")
                if st == "UNTESTED":
                    untested_count += 1
                elif st in ["TESTED", "IN_PROGRESS"]:
                    tested_count += 1
                elif st == "VULNERABLE":
                    vulnerable_count += 1

        return {
            "project": target_project,
            "summary": {
                "total_assets": total_assets,
                "total_services": total_services,
                "total_endpoints": total_endpoints,
                "untested_endpoints": untested_count,
                "tested_endpoints": tested_count,
                "vulnerable_endpoints": vulnerable_count
            },
            "assets": assets_data
        }
    finally:
        db.close()


def auto_ingest_url_to_target_graph(project: str, url: str, method: str = "GET"):
    """Silently ingests an outbound or observed URL into the attack surface graph."""
    if not url or not url.startswith("http"):
        return
    try:
        parsed = urllib.parse.urlparse(url)
        backend_url_env = os.getenv("SPECTRA_BACKEND_URL", "")
        backend_port = None
        if backend_url_env:
            try:
                b_parsed = urllib.parse.urlparse(backend_url_env)
                if b_parsed.port:
                    backend_port = b_parsed.port
            except Exception:
                pass
        if not backend_port:
            try:
                backend_port = int(os.getenv("SPECTRA_PORT", "8000"))
            except Exception:
                backend_port = 8000
        proxy_port = int(os.getenv("SPECTRA_PROXY_PORT", "8088"))
        host = (parsed.hostname or "").lower()
        if not host:
            return

        # Do not ingest Spectra's own server infrastructure
        if host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] and port in [backend_port, proxy_port]:
            return

        service_name = "https" if parsed.scheme == "https" else "http"
        add_or_update_service(project=project, host=host, port=port, service_name=service_name)
        add_or_update_endpoint(project=project, host=host, url=url, method=method)
    except Exception:
        pass
