# SYSTEM INSTRUCTION & SPECIFICATION: GLASSBOX MCP PLATFORM

**Role:** Principal Full-Stack Engineer & Offensive Security Tooling Architect  
**Project:** Glassbox MCP — Security Testing Gateway & Observability Platform  
**Target Environment:** Local Security Lab / Authorized Testing Environment  

---

## 1. Executive Summary & Objective

Build an end-to-end, production-ready Model Context Protocol (MCP) server integrated with a real-time web observability dashboard, an automated vulnerability triage engine (*Confirmed* vs. *Potential*), and a Human-in-the-Loop (HITL) interactive authentication handler.

The system addresses critical challenges in agentic security testing:
1. **Traffic Isolation:** Only security testing traffic routed via MCP tools is intercepted and inspected; outbound LLM API requests and system telemetry remain unhindered.
2. **Transparent Observability:** Full visibility into all HTTP/HTTPS interactions triggered by autonomous agents via a split-view, real-time dashboard.
3. **Automated Triage:** Real-time dual-track classification separating deterministic findings from probabilistic anomalies.
4. **Interactive Authentication Handover:** Automated spawning of a headed Chromium browser when encountering login screens or CAPTCHAs, with seamless session extraction and injection.

---

## 2. Tech Stack & Dependencies

| Component | Technology | Version / Spec |
| :--- | :--- | :--- |
| **MCP Framework** | Python `mcp` SDK / `FastMCP` | `>=1.0.0` |
| **Backend Framework** | `FastAPI`, `Uvicorn`, `asyncio` | `>=0.110.0` |
| **Real-Time Transport** | WebSockets (`websockets`) | `>=12.0` |
| **Database & ORM** | `SQLAlchemy` (SQLite: `glassbox.db`) | `>=2.0.0` |
| **HTTP Client Engine** | `httpx` (Async HTTP/1.1 & HTTP/2) | `>=0.27.0` |
| **Browser Engine** | `Playwright` (Chromium headed & headless) | `>=1.42.0` |
| **Frontend Framework** | Single-File HTML5, TailwindCSS (CDN), Alpine.js | Dark Mode SOC Theme |
| **Typography** | Inter (UI), JetBrains Mono (Code/Headers) | Modern sans & monospace |

Create `requirements.txt`:
```text
mcp>=1.0.0
fastapi>=0.110.0
uvicorn[standard]>=0.28.0
sqlalchemy>=2.0.0
httpx>=0.27.0
playwright>=1.42.0
pydantic>=2.6.0
aiofiles>=23.2.0
websockets>=12.0
```

---

## 3. Directory Structure

```text
glassbox_mcp/
├── mcp_server.py           # MCP Server Entrypoint (Stdio & SSE Transport)
├── backend/
│   ├── __init__.py
│   ├── app.py              # FastAPI Web, REST API, & WebSocket Broadcaster
│   ├── database.py         # SQLAlchemy engine, session maker, & SQLite models
│   ├── analyzer.py         # Dual-track triage engine (Confirmed vs Potential)
│   └── browser_handler.py  # Playwright renderer & HITL Interactive Login worker
├── frontend/
│   └── index.html          # High-density SOC Dark Mode Dashboard
├── requirements.txt        # Python dependency manifest
├── run.sh                  # One-click startup runner
└── mcp_config.json         # Integration template for AI Agent clients
```

---

## 4. Backend Implementation Specifications

### A. Database Models (`backend/database.py`)
Implement the following SQLite schema using SQLAlchemy:

1. **`HttpLog` Model:**
   - `id`: Integer, Primary Key, Autoincrement
   - `timestamp`: DateTime (UTC now)
   - `source`: String (`"HTTP_CLIENT"` or `"BROWSER_RENDER"`)
   - `method`: String (`GET`, `POST`, `PUT`, `DELETE`, etc.)
   - `url`: Text
   - `host`: String
   - `path`: Text
   - `status_code`: Integer
   - `duration_ms`: Integer
   - `request_headers`: JSON Text (Dict)
   - `request_body`: Text (Truncated to 50KB if binary/large)
   - `response_headers`: JSON Text (Dict)
   - `response_body`: Text (Truncated to 50KB)
   - `flag_status`: String (`"CLEAN"`, `"POTENTIAL"`, `"CONFIRMED"`)

2. **`Finding` Model:**
   - `id`: Integer, Primary Key, Autoincrement
   - `log_id`: Integer, ForeignKey(`HttpLog.id`)
   - `title`: String
   - `severity`: String (`"INFO"`, `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`)
   - `category`: String (e.g., `"SQL Error Leak"`, `"Token Exposure"`, `"Input Reflection"`)
   - `evidence`: Text (Matched string snippet)
   - `description`: Text

3. **`ActiveSession` Model:**
   - `id`: Integer, Primary Key
   - `domain`: String, Unique Index
   - `storage_state`: JSON Text (Cookies, LocalStorage, SessionStorage)
   - `updated_at`: DateTime (UTC now)

### B. Dual-Track Triage Engine (`backend/analyzer.py`)
Implement `analyze_traffic(log_entry: HttpLog) -> tuple[str, list[dict]]`:

1. **Track 1: Confirmed Findings (Deterministic Signatures):**
   - **Database Error Signatures:**
     - MySQL: `(?:SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result)`
     - PostgreSQL: `(?:PostgreSQL.*ERROR|pg_query\(\):.*Query failed)`
     - Oracle: `(?:ORA-[0-9]{5}|Oracle error)`
     - SQLite: `(?:SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException)`
     - Microsoft SQL: `(?:Driver.*SQL Server|OLE DB.*SQL Server|Unclosed quotation mark)`
   - **Secret & Credential Leaks:**
     - AWS Access Key: `\bAKIA[0-9A-Z]{16}\b`
     - Private RSA/OpenSSH Keys: `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`
     - Environment Variables: `(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY)\s*=`
   - **Critical Server Exposure:**
     - Fatal stack traces (Django Debug Mode, Spring Boot WhiteLabel Error, PHP Fatal Error).
   - *Result:* Set `flag_status = "CONFIRMED"`. Severity: `HIGH` or `CRITICAL`.

2. **Track 2: Potential Findings (Heuristics & Anomalies):**
   - **Input Reflection:** Inspect GET query parameters or POST form fields; if reflected raw in HTML/JSON body without sanitization, flag as potential reflection.
   - **Status Code Anomalies:** Unexpected HTTP 500 responses on input mutation.
   - *Result:* Set `flag_status = "POTENTIAL"`. Severity: `LOW` or `MEDIUM`.

3. **Fallback:** If no matches, set `flag_status = "CLEAN"`.

### C. Browser & HITL Login Handler (`backend/browser_handler.py`)
1. **`render_page(url: str, click_selector: str = None, fill_inputs: dict = None) -> dict`:**
   - Launch Playwright in headless mode.
   - Attach network hooks (`page.on("request")` and `page.on("response")`) to capture background AJAX/XHR calls.
   - If selector provided, click element and wait for network idle (`wait_until="networkidle"`).
   - Return page title, final URL, extracted DOM text, and list of intercepted sub-requests.

2. **`spawn_interactive_login(login_url: str, target_domain: str) -> dict`:**
   - Launch Playwright Chromium with `headless=False` at viewport 1280x800.
   - Navigate to `login_url`.
   - Maintain the window open until user completes login/CAPTCHA.
   - Provide dual completion triggers:
     - URL navigation away from login (e.g., to `/dashboard`, `/home`, or query change).
     - Manual API confirmation signal from Dashboard UI.
   - Call `await context.storage_state()`, extract cookies and localStorage.
   - Upsert session records into `ActiveSession`.
   - Close browser and return summary of captured cookies.

### D. FastAPI Application & WebSocket Hub (`backend/app.py`)
- **WebSocket Manager:** Broadcast new logs and triage alerts to connected frontend clients instantaneously.
- **REST Endpoints:**
  - `GET /api/logs`: Paginated HTTP traffic history with search and flag filtering.
  - `GET /api/logs/{log_id}`: Full raw request/response details.
  - `GET /api/findings`: List all flagged vulnerabilities.
  - `POST /api/auth/spawn`: Manual trigger to spawn the headed login browser.
  - `GET /api/auth/session`: Inspect currently stored session tokens.
  - `POST /api/logs/clear`: Clear log database for fresh runs.
- **Static Hosting:** Serve `frontend/index.html` at root URL (`http://127.0.0.1:8000`).

### E. MCP Server Layer (`mcp_server.py`)
Expose the following tools via FastMCP:
1. `send_http_request(method: str, url: str, headers: dict = None, body: str = None) -> str`:
   - Automatically inject domain session cookies from `ActiveSession`.
   - Execute request via `httpx.AsyncClient(verify=False, follow_redirects=True)`.
   - Record log to SQLite, trigger `analyzer.py`, and push live update over WebSocket.
   - Return structured response: Status Code, Response Headers, and Body snippet.
2. `browser_navigate_and_render(url: str, click_selector: str = None, fill_inputs: dict = None) -> str`:
   - Execute Playwright render, capture background calls, return DOM text representation.
3. `request_manual_login(login_url: str, domain: str) -> str`:
   - Trigger `spawn_interactive_login`. Pause agent execution until authentication completes.
   - Return status: `"Authentication successful. Sockets/cookies updated and active for domain."`

---

## 5. UI/UX Design & Frontend Specifications (`frontend/index.html`)

The web dashboard must feature a modern **Cyber Operations / Dark Mode** design system inspired by tools like Caido, Raycast, and Burp Suite.

### A. Design System Tokens
- **Base Surfaces:**
  - Main Background: `#0B0F17` (`bg-slate-950`)
  - Panels & Cards: `#111827` (`bg-slate-900/90`)
  - Borders: `#1E293B` (`border-slate-800`)
  - Accent Ring: `#0EA5E9` (`sky-500`)
- **Semantic Colors:**
  - `CONFIRMED`: `#F43F5E` (`rose-500`) with subtle pulsing animation (`animate-ping`)
  - `POTENTIAL`: `#F59E0B` (`amber-500`)
  - `CLEAN`: `#64748B` (`slate-500`)
  - Method GET: `#38BDF8` (`sky-400`)
  - Method POST: `#34D399` (`emerald-400`)
  - Method PUT: `#FBBF24` (`amber-400`)
  - Method DELETE: `#FB7185` (`rose-400`)

### B. Dashboard Layout
1. **Top Command Bar (Header):**
   - **Left:** System branding (`GLASSBOX // MCP PROXY`), WebSocket connection status indicator (pulsing green dot), and active target domain pill.
   - **Center:** 4 Stat Metric Cards:
     - Total Requests counter
     - Confirmed Findings counter (glowing rose badge)
     - Potential Findings counter (amber badge)
     - Session Auth Status (Active badge with cookie count, or Inactive)
   - **Right:** Action buttons:
     - `"Spawn Login Browser"` (Indigo button with browser icon)
     - `"Clear Logs"`
     - `"Toggle Auto-Scroll"`

2. **Main Split-View Work Area (100vh - Header):**
   - **Left Pane (55% Width) — HTTP Traffic History Table:**
     - **Filter Bar:** Real-time search input for URL/path, Method dropdown filter, Status Code filter, and Flag tabs (`ALL`, `CONFIRMED`, `POTENTIAL`).
     - **Interactive Table:**
       - Columns: `ID`, `Flag`, `Method`, `Status`, `Host / Path`, `Latency`, `Time`.
       - Row hover state and active row selection highlighted with `bg-slate-800/80 ring-1 ring-sky-500`.
   - **Right Pane (45% Width) — Deep Inspector:**
     - **Tab 1: Request Inspector:** Raw headers table, formatted payload viewer (JSON/Text), and `"Copy cURL"` button.
     - **Tab 2: Response Inspector:** Status line, headers, syntax-highlighted response body, and `"Copy Response"` button.
     - **Tab 3: Triage & Vulnerability Analysis:** Only highlighted when findings exist:
       - Severity badge (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
       - Finding Title & CWE Category
       - Highlighted Evidence Code Box displaying matched response snippet
       - Actionable Remediation Guidance

3. **Modals & Toast Notifications:**
   - Toast popup on bottom-right whenever a `CONFIRMED` vulnerability is detected.
   - Modal dialog during `Spawn Login Browser` execution displaying: *"Browser active on your screen. Complete login/CAPTCHA. Session will automatically sync."*

---

## 6. Execution Runner & Client Configuration

### A. Startup Script (`run.sh`)
```bash
#!/usr/bin/env bash
set -e

echo "[*] Initializing Glassbox MCP Environment..."
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
playwright install chromium

echo "[*] Starting FastAPI Web Dashboard on http://127.0.0.1:8000..."
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload &
FASTAPI_PID=$!

echo "[*] Starting Glassbox MCP Server..."
python3 mcp_server.py

kill $FASTAPI_PID
```

### B. Client Configuration (`mcp_config.json`)
```json
{
  "mcpServers": {
    "glassbox": {
      "command": "python3",
      "args": ["/path/to/glassbox_mcp/mcp_server.py"],
      "env": {
        "GLASSBOX_BACKEND_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```

---

## 7. Acceptance Criteria
1. Full asynchronous non-blocking pipeline: MCP tool execution must not hang on database writes or WebSocket broadcasts.
2. Zero code placeholders: Every file must contain complete, functional logic.
3. Clean error handling: Resilient execution against network timeouts, SSL errors, and malformed bodies.
4. Seamless HITL handover: `request_manual_login` must reliably persist browser cookies to `ActiveSession` and propagate to subsequent HTTP requests.
