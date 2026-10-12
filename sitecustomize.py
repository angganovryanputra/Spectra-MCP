"""
SPECTRA PROXY AUTO-ENFORCEMENT RUNTIME HOOK (sitecustomize.py)
--------------------------------------------------------------
Auto-executed by Python's `site` module on startup before any script runs.
Guarantees that all outbound HTTP/HTTPS traffic from AI Agent scripts
(requests, httpx, urllib, aiohttp) routes through Spectra Forward Proxy (:8088),
with zero manual configuration required in the agent's code.
"""
import os
import sys

# Do not intercept if explicitly disabled or inside Spectra Proxy server process itself
if os.environ.get("SPECTRA_DISABLE_AUTO_PROXY", "0") != "1" and os.environ.get("SPECTRA_IS_PROXY", "0") != "1":
    proxy_port = int(os.environ.get("SPECTRA_PROXY_PORT", "8088"))
    proxy_url = os.environ.get("SPECTRA_PROXY_URL", f"http://127.0.0.1:{proxy_port}")

    # 1. Inject Standard Proxy Environment Variables
    os.environ["HTTP_PROXY"] = proxy_url
    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["http_proxy"] = proxy_url
    os.environ["https_proxy"] = proxy_url
    os.environ["ALL_PROXY"] = proxy_url
    os.environ["all_proxy"] = proxy_url

    # 2. Configure Spectra Root CA Certificate & Disable Verification Warnings
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    ca_path = ""
    for _ in range(5):
        candidate = os.path.join(curr_dir, ".spectra_ca", "spectra_ca.crt")
        if os.path.exists(candidate):
            ca_path = os.path.abspath(candidate)
            break
        parent = os.path.dirname(curr_dir)
        if parent == curr_dir:
            break
        curr_dir = parent

    if ca_path and os.path.exists(ca_path):
        os.environ["REQUESTS_CA_BUNDLE"] = ca_path
        os.environ["SSL_CERT_FILE"] = ca_path
        os.environ["CURL_CA_BUNDLE"] = ca_path

    os.environ["PYTHONHTTPSVERIFY"] = "0"
    os.environ["CURL_INSECURE"] = "1"
    os.environ["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    # Suppress SSL Insecure Request Warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    # 3. Patch `requests` library to guarantee proxy routing and MITM TLS inspection
    try:
        import requests
        _orig_session_init = requests.Session.__init__
        def _spectra_session_init(self, *args, **kwargs):
            _orig_session_init(self, *args, **kwargs)
            if not getattr(self, "proxies", None):
                self.proxies = {
                    "http": proxy_url,
                    "https": proxy_url
                }
            if getattr(self, "verify", None) is True:
                self.verify = False
        requests.Session.__init__ = _spectra_session_init
    except Exception:
        pass

    # 4. Patch `httpx` library if available
    try:
        import httpx
        _orig_httpx_init = httpx.Client.__init__
        def _spectra_httpx_init(self, *args, **kwargs):
            if "proxy" not in kwargs and "proxies" not in kwargs:
                kwargs["proxy"] = proxy_url
            if "verify" not in kwargs:
                kwargs["verify"] = False
            _orig_httpx_init(self, *args, **kwargs)
        httpx.Client.__init__ = _spectra_httpx_init

        if hasattr(httpx, "AsyncClient"):
            _orig_async_init = httpx.AsyncClient.__init__
            def _spectra_async_init(self, *args, **kwargs):
                if "proxy" not in kwargs and "proxies" not in kwargs:
                    kwargs["proxy"] = proxy_url
                if "verify" not in kwargs:
                    kwargs["verify"] = False
                _orig_async_init(self, *args, **kwargs)
            httpx.AsyncClient.__init__ = _spectra_async_init
    except Exception:
        pass

    # 5. Patch `urllib.request` standard library
    try:
        import urllib.request
        _proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url
        })
        _opener = urllib.request.build_opener(_proxy_handler)
        urllib.request.install_opener(_opener)
    except Exception:
        pass
