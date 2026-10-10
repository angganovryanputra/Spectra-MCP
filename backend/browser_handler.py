"""
Spectra MCP - Browser & HITL (Human-in-the-Loop) Login Handler
Automated Playwright DOM rendering and interactive headed authentication handover.
"""

import asyncio
import json
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from backend.database import SessionLocal, ActiveSession

logger = logging.getLogger("spectra.browser")

# Active interactive login tracking: domain -> asyncio.Event
active_login_events: Dict[str, asyncio.Event] = {}
active_login_status: Dict[str, Dict[str, Any]] = {}


def signal_login_confirmation(domain: Optional[str] = None) -> bool:
    """Signals manual completion from the dashboard API for a given domain or all active domains."""
    signaled = False
    if domain and domain in active_login_events:
        active_login_events[domain].set()
        return True
    
    # If no specific domain or not found, signal all pending
    for d, evt in list(active_login_events.items()):
        evt.set()
        signaled = True
    return signaled


def get_active_login_status() -> Optional[Dict[str, Any]]:
    """Returns information about any currently running interactive login session."""
    for domain, info in active_login_status.items():
        if info.get("active"):
            return info
    return None


async def render_page(
    url: str,
    click_selector: Optional[str] = None,
    fill_inputs: Optional[Dict[str, str]] = None,
    wait_time_ms: int = 2000,
    upstream_proxy: Optional[str] = None
) -> Dict[str, Any]:
    """
    Renders a URL headlessly using Playwright, intercepts sub-requests, and returns DOM content.
    Supports routing traffic through upstream proxy (e.g. Burp Suite).
    """
    from playwright.async_api import async_playwright

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc

    intercepted_requests: List[Dict[str, Any]] = []

    async with async_playwright() as p:
        launch_kwargs = {"headless": True}
        if upstream_proxy and upstream_proxy.strip():
            launch_kwargs["proxy"] = {"server": upstream_proxy.strip()}

        browser = await p.chromium.launch(**launch_kwargs)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SpectraMCP/1.0",
            ignore_https_errors=True
        )

        # Inject existing active session cookies if available
        db = SessionLocal()
        try:
            sess_record = db.query(ActiveSession).filter(ActiveSession.domain == domain).first()
            if sess_record and sess_record.storage_state:
                try:
                    state_data = json.loads(sess_record.storage_state)
                    cookies = state_data.get("cookies", [])
                    if cookies:
                        await context.add_cookies(cookies)
                except Exception as ex:
                    logger.warning("Failed injecting cookies for %s: %s", domain, ex)
        finally:
            db.close()

        page = await context.new_page()

        # Network hooks to capture AJAX / sub-requests
        page.on("request", lambda req: intercepted_requests.append({
            "url": req.url,
            "method": req.method,
            "resource_type": req.resource_type,
            "headers": dict(req.headers)
        }))

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Optional fill inputs
            if fill_inputs:
                for selector, val in fill_inputs.items():
                    try:
                        await page.fill(selector, val, timeout=3000)
                    except Exception as ex:
                        logger.debug("Could not fill input %s: %s", selector, ex)

            # Optional click action
            if click_selector:
                try:
                    await page.click(click_selector, timeout=5000)
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    await asyncio.sleep(1.0)
            else:
                try:
                    await page.wait_for_load_state("networkidle", timeout=4000)
                except Exception:
                    await asyncio.sleep(0.5)

            title = await page.title()
            final_url = page.url
            try:
                body_text = await page.inner_text("body", timeout=5000)
            except Exception:
                body_text = await page.content()

            return {
                "title": title,
                "url": final_url,
                "domain": domain,
                "dom_text": body_text[:10000],  # Trim to prevent overwhelming context
                "intercepted_count": len(intercepted_requests),
                "intercepted_requests": intercepted_requests[:30]
            }
        finally:
            await browser.close()


def _save_session_cookies(project: str, domain: str, storage_state: dict):
    """Upserts captured session state into SQLite ActiveSession table."""
    db = SessionLocal()
    try:
        existing = db.query(ActiveSession).filter(ActiveSession.domain == domain).first()
        if existing:
            existing.project = project
            existing.storage_state = json.dumps(storage_state)
            existing.updated_at = datetime.now(timezone.utc)
        else:
            new_session = ActiveSession(
                project=project,
                domain=domain,
                storage_state=json.dumps(storage_state),
                updated_at=datetime.now(timezone.utc)
            )
            db.add(new_session)
        db.commit()
    except Exception as ex:
        logger.warning("Error saving active session: %s", ex)
    finally:
        db.close()


async def spawn_interactive_login(
    login_url: str,
    target_domain: Optional[str] = None,
    project: str = "default",
    timeout_seconds: int = 300,
    on_cookie_update: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Spawns headed Chromium window for Human-in-the-Loop (HITL) authentication.
    - Continuously extracts cookies in real-time as user interacts.
    - Saves state automatically to SQLite.
    - Detects successful post-login redirection OR manual confirmation trigger.
    """
    from playwright.async_api import async_playwright

    clean_url = (login_url or "").strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    domain = (target_domain or parsed.netloc.split(":")[0]).strip()

    completion_event = asyncio.Event()
    active_login_events[domain] = completion_event
    active_login_status[domain] = {
        "active": True,
        "login_url": clean_url,
        "domain": domain,
        "project": project,
        "started_at": datetime.now(timezone.utc).isoformat()
    }

    captured_data = {
        "cookies": [],
        "cookie_count": 0,
        "domain": domain,
        "project": project,
        "status": "pending"
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-infobars"
                ]
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 850},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                ignore_https_errors=True
            )
            page = await context.new_page()

            # Active continuous cookie synchronization loop
            async def sync_loop():
                while not completion_event.is_set():
                    try:
                        storage = await context.storage_state()
                        current_cookies = storage.get("cookies", [])
                        if current_cookies:
                            captured_data["cookies"] = current_cookies
                            captured_data["cookie_count"] = len(current_cookies)
                            _save_session_cookies(project, domain, storage)
                            if on_cookie_update:
                                try:
                                    await on_cookie_update(domain, len(current_cookies))
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    await asyncio.sleep(2.0)

            sync_task = asyncio.create_task(sync_loop())

            # Intelligent Navigation Check:
            # Only trigger completion if URL changes to an authenticated area AND cookies exist
            initial_path = (parsed.path.rstrip("/") or "/").lower()
            auth_keywords = ["dashboard", "home", "admin", "app", "main", "welcome", "portal", "user", "account", "feed"]

            async def on_frame_navigated(frame):
                if frame == page.main_frame:
                    curr_url = page.url or ""
                    if curr_url and curr_url != "about:blank":
                        curr_parsed = urllib.parse.urlparse(curr_url)
                        curr_path = (curr_parsed.path.rstrip("/") or "/").lower()

                        # Check if landed on authenticated page with cookies present
                        has_auth_path = any(kw in curr_path for kw in auth_keywords)
                        not_login_path = "login" not in curr_path and "signin" not in curr_path and "auth" not in curr_path
                        cookies_exist = captured_data.get("cookie_count", 0) > 0

                        if (has_auth_path or (not_login_path and curr_path != initial_path)) and cookies_exist:
                            # Settle session headers for 3.5 seconds before auto-closing
                            await asyncio.sleep(3.5)
                            completion_event.set()

            page.on("framenavigated", lambda frame: asyncio.create_task(on_frame_navigated(frame)))

            # If user closes browser window directly, finalize capture immediately
            context.on("close", lambda: completion_event.set())
            page.on("close", lambda: completion_event.set())

            try:
                await page.goto(clean_url, wait_until="domcontentloaded", timeout=45000)
            except Exception as nav_ex:
                logger.warning("Initial navigation error on %s: %s", clean_url, nav_ex)

            # Wait for either completion event or timeout
            try:
                await asyncio.wait_for(completion_event.wait(), timeout=float(timeout_seconds))
            except asyncio.TimeoutError:
                logger.warning("HITL interactive login timed out after %ds for %s", timeout_seconds, domain)

            sync_task.cancel()

            # Final capture and storage
            try:
                storage_state = await context.storage_state()
            except Exception:
                storage_state = {"cookies": captured_data.get("cookies", [])}

            cookies = storage_state.get("cookies", [])
            captured_data["cookies"] = cookies
            captured_data["cookie_count"] = len(cookies)
            captured_data["status"] = "success" if len(cookies) > 0 else "completed_no_cookies"

            if cookies:
                _save_session_cookies(project, domain, storage_state)

            try:
                await browser.close()
            except Exception:
                pass
    finally:
        active_login_events.pop(domain, None)
        active_login_status.pop(domain, None)

    return captured_data
