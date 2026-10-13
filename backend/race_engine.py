"""
Spectra - Turbo Race Condition & Single-Packet Synchronization Barrier Engine
Executes microsecond-synchronized concurrent bursts against web endpoints
to identify race conditions, double-spending, limit bypasses, and state-breakage flaws.
"""

import time
import asyncio
from typing import Dict, Any, List, Optional
import httpx

from backend.user_agents import apply_rotating_user_agent


async def run_race_attack(
    url: str,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = "",
    concurrency: int = 20,
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    Spawns `concurrency` parallel tasks that pre-warm their connection,
    align on a synchronization barrier, and release their payload simultaneously.
    """
    headers = headers or {}
    body = body or ""
    method = method.upper().strip()
    concurrency = max(2, min(concurrency, 50))  # Safe bounds: 2 to 50 concurrent requests

    proxy_kwargs = {}
    if upstream_proxy and upstream_proxy.strip():
        proxy_kwargs["proxy"] = upstream_proxy.strip()
    else:
        proxy_kwargs["proxy"] = None
        proxy_kwargs["trust_env"] = False

    sync_barrier = asyncio.Barrier(concurrency)
    results: List[Dict[str, Any]] = []
    results_lock = asyncio.Lock()

    limits = httpx.Limits(
        max_keepalive_connections=concurrency,
        max_connections=concurrency * 2,
        keepalive_expiry=30.0
    )

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20.0, limits=limits, **proxy_kwargs) as client:

        async def _race_worker(worker_id: int):
            worker_headers = dict(headers)
            apply_rotating_user_agent(worker_headers)
            content_bytes = body.encode("utf-8") if body else None

            # 1. Wait until all workers are completely initialized and aligned at the barrier
            try:
                await sync_barrier.wait()
            except Exception:
                pass

            # 2. Release request in microsecond sync
            t0 = time.time()
            res_status = None
            res_len = 0
            res_text = ""
            error = None

            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=worker_headers,
                    content=content_bytes
                )
                dur = int((time.time() - t0) * 1000)
                res_status = resp.status_code
                res_len = len(resp.content)
                res_text = resp.text[:400] if resp.text else ""
            except Exception as ex:
                dur = int((time.time() - t0) * 1000)
                error = str(ex)

            res_item = {
                "worker_id": worker_id + 1,
                "status_code": res_status,
                "duration_ms": dur,
                "length": res_len,
                "preview": res_text,
                "error": error
            }

            async with results_lock:
                results.append(res_item)

        # Launch all workers concurrently
        tasks = [_race_worker(i) for i in range(concurrency)]
        t_start_all = time.time()
        await asyncio.gather(*tasks, return_exceptions=True)
        total_time_ms = int((time.time() - t_start_all) * 1000)

    # 3. Analyze distribution & detect race conditions
    status_distribution: Dict[str, int] = {}
    success_responses = []

    for r in results:
        sc = r.get("status_code")
        if sc is not None:
            sc_key = str(sc)
            status_distribution[sc_key] = status_distribution.get(sc_key, 0) + 1
            if sc in [200, 201, 204]:
                success_responses.append(r)

    anomalies: List[Dict[str, Any]] = []

    # Check for Double-Spend / Concurrency Flaw:
    # If 2 or more requests succeeded simultaneously on sensitive state-changing endpoints
    path_lower = url.lower()
    is_sensitive_action = any(k in path_lower for k in [
        "pay", "transfer", "redeem", "coupon", "voucher", "checkout", "withdraw",
        "claim", "invite", "vote", "like", "order", "reset", "otp", "verify"
    ])

    if len(success_responses) > 1 and is_sensitive_action:
        anomalies.append({
            "type": "POTENTIAL_RACE_CONDITION_MULTIPLE_SUCCESS",
            "severity": "HIGH",
            "description": f"Target endpoint permitted {len(success_responses)} simultaneous successful state actions out of {concurrency} synchronized burst requests.",
            "success_count": len(success_responses)
        })

    # Check for status diversity / rate limit inconsistency
    if len(status_distribution) > 1:
        anomalies.append({
            "type": "STATUS_DIVERSIFICATION",
            "distribution": status_distribution,
            "description": f"Burst requests split across multiple status codes: {status_distribution}"
        })

    verdict = "POTENTIAL_RACE_CONDITION" if len(success_responses) > 1 else "CONSISTENT_BEHAVIOR"

    return {
        "status": "COMPLETED",
        "verdict": verdict,
        "url": url,
        "method": method,
        "concurrency": concurrency,
        "total_sent": len(results),
        "burst_duration_ms": total_time_ms,
        "total_duration_ms": total_time_ms,
        "status_distribution": status_distribution,
        "success_count": len(success_responses),
        "anomalies": anomalies,
        "results": sorted(results, key=lambda x: x["worker_id"])
    }
