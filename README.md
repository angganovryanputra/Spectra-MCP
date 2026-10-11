# 🛡️ SPECTRA MCP
### Security Testing Gateway, Intercept Proxy & Observability Platform for AI Pentesting Agents

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-FastMCP%201.0%2B-purple.svg)](https://modelcontextprotocol.io)
[![FastAPI](https://img.shields.io/badge/FastAPI-High%20Performance-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)

**Spectra** adalah gateway keamanan dan platform observabilitas real-time yang dirancang khusus untuk menjembatani **Autonomous AI Pentest Agents** (seperti **OpenCode**, **Hermes Agent**, **Claude Code**, atau LLM apa pun yang mendukung **Model Context Protocol / MCP**) dengan target aplikasi keamanan.

Spectra menyelesaikan tantangan utama saat menggunakan AI Agent dalam pentesting:
1. **Zero-Prompt Credential Auto-Injection**: Agen AI tidak perlu berulang kali meminta cookie atau melakukan login ulang. Cookie yang telah disimpan di Spectra otomatis diinjeksi ke setiap request target domain secara seamless.
2. **AI Command Execution Audit Trail**: Setiap perintah shell/CLI (`nmap`, `sqlmap`, `ffuf`, `curl`) yang dipanggil oleh agen dicatat secara lengkap (stdout, stderr, exit code, durasi, reasoning AI) dengan **CLI Safe-Mode** guardrail untuk mencegah eksekusi instruksi destruktif.
3. **Captured Security Payload Vault**: Menyimpan setiap mutasi exploit payload (SQLi, XSS, SSTI, SSRF, LFI, dsb.) dengan parameter target, outcome (`EXECUTED`, `REFLECTED`, `WAF_BLOCKED`), dan integrasi **1-Click "Send to Repeater"**.
4. **Interactive Intercept Proxy & Guardrails**: Operator manusia (HITL) dapat menjeda, memodifikasi, meneruskan, atau men-drop request AI secara real-time seperti Burp Suite Intercept.
5. **Ekspor Standar Industri**: Ekspor seluruh riwayat lalu lintas ke **HAR 1.2** (siap diimpor ke Burp Suite / OWASP ZAP), **Executive Pentest Report (Markdown)**, dan **OpenAPI 3.0 Specification**.

---

## 🏗️ Arsitektur Sistem

```text
┌────────────────────────────────────────────────────────────────────────┐
│             AI AGENT WORKSPACE (OpenCode / Hermes / Claude)            │
│  Calls: send_http_request | run_pentest_command | record_test_payload  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (MCP Protocol over Stdio)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          SPECTRA MCP SERVER                            │
│  - Zero-Prompt Cookie Auto-Injection (from target domain store)        │
│  - CLI Safe-Mode Guardrail (Blocks rm -rf, DROP TABLE, disk wipes)     │
│  - Deterministic & Probabilistic Vulnerability Heuristic Engine        │
│  - Real-Time Async Subprocess & Playwright Headless Renderer           │
└──────────────────┬────────────────────────────────┬────────────────────┘
                   │                                │
                   ▼                                ▼
       ┌───────────────────────┐        ┌────────────────────────┐
       │   TARGET WEB APP /    │        │   FASTAPI DASHBOARD    │
       │   NETWORK SERVICES    │        │  (:8000 Web UI + WS)   │
       └───────────────────────┘        └───────────┬────────────┘
                                                    │
                                                    ▼
                                        ┌────────────────────────┐
                                        │  OPERATOR SOC CONSOLE  │
                                        │ - Traffic History      │
                                        │ - AI Command Audit     │
                                        │ - Payload Vault        │
                                        │ - Repeater & Fuzzer    │
                                        │ - Intercept Breakpoint │
                                        └────────────────────────┘
```

---

## 🚀 Quick Start (Menjalankan Spectra)

### 1. Prasyarat
- Python 3.10 atau lebih tinggi
- Windows, Linux, atau macOS

### 2. Instalasi & Menjalankan Dashboard

#### Di Windows:
Cukup jalankan script batch otomatis:
```cmd
run.bat
```
Atau manual melalui PowerShell/CMD:
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

#### Di Linux / macOS:
```bash
chmod +x run.sh
./run.sh
```

Buka browser dan akses Web Console di: **`http://127.0.0.1:8000`**

---

## 🤖 Integrasi dengan OpenCode

**OpenCode** mendukung konfigurasi MCP server melalui file konfigurasi JSON.

### Langkah Konfigurasi OpenCode:
1. Buat atau edit file konfigurasi MCP OpenCode (misalnya `.opencode/mcp.json` di root workspace atau konfigurasi global OpenCode).
2. Tambahkan server `spectra`:

```json
{
  "mcpServers": {
    "spectra": {
      "command": "d:/PROJECT/01/venv/Scripts/python.exe",
      "args": [
        "d:/PROJECT/01/mcp_server.py"
      ],
      "env": {
        "SPECTRA_BACKEND_URL": "http://127.0.0.1:8000",
        "SPECTRA_PROJECT": "default",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

> **Tips:** Sesuaikan path `d:/PROJECT/01` dengan direktori absolut instalasi Spectra Anda. Jika menggunakan Linux/macOS, gunakan `.../venv/bin/python`.

3. Mulai sesi OpenCode. Agen akan secara otomatis mendeteksi 5 tools Spectra (`send_http_request`, `run_pentest_command`, `record_test_payload`, `render_webpage`, `request_manual_login`).

---

## 🦅 Integrasi dengan Hermes Agent

**Hermes Agent** dapat diintegrasikan dengan Spectra MCP baik melalui CLI runner maupun file konfigurasi agent (`hermes_config.json` / `agent_config.json`).

### 1. Konfigurasi MCP Hermes
Tambahkan blok Spectra ke dalam konfigurasi Hermes:

```json
{
  "mcp": {
    "servers": {
      "spectra": {
        "command": "d:/PROJECT/01/venv/Scripts/python.exe",
        "args": ["d:/PROJECT/01/mcp_server.py"],
        "env": {
          "SPECTRA_BACKEND_URL": "http://127.0.0.1:8000",
          "SPECTRA_PROJECT": "default"
        }
      }
    }
  }
}
```

### 2. System Instructions untuk Hermes / OpenCode
Agar AI Agent memanfaatkan fitur Spectra secara maksimal, sertakan panduan berikut pada System Prompt atau instruksi agent Anda (sudah tersedia di [`AGENT_INSTRUCTIONS.md`](AGENT_INSTRUCTIONS.md)):

```markdown
# PANDUAN PENTESTING DENGAN SPECTRA MCP

1. PRIORITASKAN `send_http_request`:
   - Selalu gunakan `send_http_request` daripada curl langsung untuk request web.
   - Jangan meminta cookie kepada pengguna! Spectra otomatis menyuntikkan cookie sesi yang valid ke setiap request sesuai domain target.

2. EKSEKUSI PERINTAH TERMINAL DENGAN `run_pentest_command`:
   - Ketika perlu menjalankan tool CLI (seperti nmap, sqlmap, ffuf, gobuster, nikto), panggil tool `run_pentest_command`.
   - Perintah akan tercatat pada Command Audit Trail operator secara live.
   - Perintah destruktif (seperti `rm -rf`, penghapusan disk/database) akan diblokir otomatis oleh Safe-Mode Guardrail.

3. KATALOGKAN SETIAP PAYLOAD DENGAN `record_test_payload`:
   - Saat membuat atau menguji payload celah keamanan (SQLi, XSS, SSRF, SSTI, LFI, RCE, IDOR), panggil `record_test_payload`.
   - Cantumkan tipe kerentanan, parameter target, payload mentah, dan outcome (EXECUTED, REFLECTED, WAF_BLOCKED, dsb.).
   - Operator dapat langsung memverifikasi payload tersebut dengan 1 tombol Repeater di dashboard.

4. TARGET DINAMIS DENGAN `render_webpage`:
   - Untuk SPA (Single Page Applications) yang membutuhkan eksekusi JavaScript, gunakan `render_webpage`. Tool ini menangkap seluruh request latar belakang (XHR/Fetch) secara otomatis.
```

---

## 🛠️ Integrasi dengan Claude Desktop / Cursor / Generic MCP

### Claude Desktop (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "spectra": {
      "command": "d:/PROJECT/01/venv/Scripts/python.exe",
      "args": ["d:/PROJECT/01/mcp_server.py"],
      "env": {
        "SPECTRA_BACKEND_URL": "http://127.0.0.1:8000",
        "SPECTRA_PROJECT": "default"
      }
    }
  }
}
```

---

## 🧰 Referensi MCP Tools Spectra

| Nama Tool | Kegunaan | Parameter Utama |
| :--- | :--- | :--- |
| **`send_http_request`** | Mengirimkan HTTP request melalui proxy observabilitas Spectra dengan auto-cookie injection & vulnerability triage. | `method`, `url`, `headers`, `body`, `project`, `reasoning` |
| **`run_pentest_command`** | Menjalankan perintah terminal/CLI secara aman dengan streaming stdout/stderr dan CLI Safe-Mode. | `command`, `project`, `tool_name`, `reasoning`, `timeout` |
| **`record_test_payload`** | Mengkatalogkan security payload khusus ke dalam brankas (Payload Vault) untuk 1-click Repeater replay. | `target_url`, `vuln_type`, `raw_payload`, `target_param`, `outcome`, `http_method` |
| **`render_webpage`** | Rendering browser headless Playwright dengan ekstraksi DOM dan intersepsi sub-request AJAX/fetch. | `url`, `click_selector`, `fill_inputs`, `project`, `reasoning` |
| **`request_manual_login`** | Meluncurkan browser headed untuk otentikasi interaktif (2FA / CAPTCHA) jika login otomatis tidak memungkinkan. | `login_url`, `domain`, `project` |

---

## 🖥️ Fitur Web Console (`http://127.0.0.1:8000`)

1. **Proxy Traffic History & Deep Inspector**:
   - Paginasi pintar (50, 100, 250, ALL baris per halaman) tanpa lagging pada ribuan request.
   - Filter per-kolom (ID, Flag, Method, Status, Host, Path, Latency) dan sorting multi-kolom.
   - Header Inspector (tampilan tabel key-value dan raw format).
   - Smart Auto-Beautifier untuk JSON, HTML, XML, dan Form data.

2. **AI Activity Console**:
   - **Command Audit Trail**: Pemantauan seluruh command terminal yang dijalankan AI, lengkap dengan drawer inspector yang menampilkan stdout/stderr, exit code, dan durasi eksekusi.
   - **Payload Vault & Matrix**: Brankas seluruh mutasi payload keamanan dengan status outcome dan tombol **1-Click Repeater**.

3. **Repeater & Baseline Differential Analysis**:
   - Replay request manual dengan pelacakan delta byte response.
   - Beautifier header dan body request dengan 1 tombol.

4. **Parameter Fuzzer / Mini-Intruder**:
   - Fuzzing multi-threaded dengan kamus bawaan (SQLi, XSS, Path Traversal, SSTI, Command Injection).
   - Deteksi anomali status code dan panjang response secara otomatis.

5. **Interactive Intercept Proxy**:
   - Menjeda request agen AI secara real-time.
   - Memodifikasi header/body sebelum diteruskan ke server target, atau men-drop request berbahaya.

6. **Session & Cookie Manager**:
   - Menyimpan credential sesi target hanya dengan paste string cookie mentah, perintah cURL, atau JSON state.
   - Tombol Revoke individual per-cookie key atau per-domain.

7. **Export & Reporting**:
   - **HAR 1.2**: Ekspor seluruh riwayat request/response untuk diimpor ke Burp Suite, OWASP ZAP, atau Postman.
   - **Executive Report**: Laporan audit Markdown komprehensif berisi ringkasan celah, bukti, rekomendasi, daftar command AI, dan brankas payload.
   - **OpenAPI 3.0**: Menghasilkan spesifikasi Swagger/OpenAPI otomatis dari lalu lintas yang diobservasi.

---

## ⚙️ Konfigurasi Environment Variables

| Variabel | Default | Keterangan |
| :--- | :--- | :--- |
| `SPECTRA_BACKEND_URL` | `http://127.0.0.1:8000` | Alamat URL backend FastAPI Spectra untuk sinkronisasi WebSocket & telemetry |
| `SPECTRA_PROJECT` | `default` | Nama workspace/proyek default yang aktif |
| `SPECTRA_UPSTREAM_PROXY` | *(kosong)* | Proxy upstream untuk chaining ke Burp Suite / Caido / ZAP (contoh: `http://127.0.0.1:8080`) |
| `SPECTRA_DB_PATH` | `./spectra.db` | Lokasi file database SQLite WAL Spectra |

---

## 📄 Lisensi
Spectra didistribusikan di bawah lisensi MIT. Gunakan hanya pada sistem yang Anda miliki atau dengan izin tertulis dari pemilik sistem.
