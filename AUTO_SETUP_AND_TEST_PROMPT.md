# 🚀 PROXSYNTH MCP — AUTOMATED SETUP & VALIDATION PROMPT

Dokumen ini berisi instruksi master prompt yang dapat langsung diberikan kepada AI Coding/Pentesting Agent (**Claude Code**, **OpenCode**, **Cursor**, **Windsurf**, **Hermes**, dll.) sesaat setelah pengguna melakukan `git clone` repositori Proxynth.

---

## 📋 Master Prompt (Copy & Paste ke Claude Code / OpenCode / Agent)

Salin seluruh teks di bawah ini ke dalam sesi prompt agent Anda:

```markdown
Anda adalah Autonomous Security & DevOps Agent. Saya baru saja melakukan `git clone` repositori Proxynth ini. 
Tugas Anda adalah:
1. Menjalankan auto-instalasi environment Proxynth MCP di sistem ini.
2. Memastikan konfigurasi MCP Client terpasang dan terhubung dengan benar.
3. Menjalankan backend Proxynth Dashboard.
4. Melakukan validasi pengujian fungsional tools Proxynth secara end-to-end terhadap target:
   👉 https://juice-shop.herokuapp.com/#/

Lakukan seluruh tahapan berikut secara berurutan dan mandiri:

### TAHAP 1: DETEKSI SISTEM & AUTO-INSTALLATION
1. Periksa OS saat ini (Windows vs Linux/WSL2).
2. Jalankan script auto-installer resmi Proxynth:
   - Jika di Windows: Jalankan `install.bat` (atau `powershell.exe -ExecutionPolicy Bypass -File .\install.ps1`).
   - Jika di Linux/WSL2: Jalankan `chmod +x install.sh run.sh && ./install.sh`.
3. Pastikan virtual environment (`venv`) telah terbuat dan seluruh dependensi di `requirements.txt` (termasuk FastAPI, Uvicorn, Playwright Chromium, dan Cryptography) terpasang tanpa error.

### TAHAP 2: KONFIGURASI MCP CLIENT
1. Periksa file konfigurasi MCP client Anda (`mcp_config.json`, `claude_desktop_config.json`, atau `~/.config/opencode/opencode.json`).
2. Daftarkan server `proxynth` dengan format berikut:
   ```json
   {
     "mcpServers": {
       "proxynth": {
         "command": "<PATH_KE_PYTHON_VENV>",
         "args": [
           "<PATH_KE_MCP_SERVER_PY>"
         ],
         "env": {
           "PROXSYNTH_BACKEND_URL": "http://127.0.0.1:8000",
           "PROXSYNTH_PROJECT": "default",
           "PYTHONIOENCODING": "utf-8"
         }
       }
     }
   }
   ```
   *(Catatan untuk WSL2 Mirrored Network: Anda dapat mengarahkan command ke `/mnt/d/PROJECT/01/venv/Scripts/python.exe` atau `python3` di WSL2 dengan backend URL `http://127.0.0.1:8000`).*

### TAHAP 3: MENJALANKAN DASHBOARD
1. Jalankan server dashboard Proxynth di background pada port 8000:
   - Windows: `run.bat dashboard` atau `uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload`
   - Linux/WSL2: `./run.sh dashboard`
2. Lakukan pengecekan HTTP GET ke `http://127.0.0.1:8000/api/stats` untuk memastikan dashboard merespons HTTP 200.

### TAHAP 4: ATURAN OPERASIONAL PENTEST (STRICT PROTOCOL)
Mulai saat ini, seluruh aktivitas pengujian WAJIB melalui Proxynth MCP Gateway:
- DILARANG menggunakan raw `curl` langsung di shell host.
- Gunakan `send_http_request` untuk seluruh HTTP traffic (menghasilkan Log ID, status, headers, preview body).
- Gunakan `get_log_detail` jika ingin menginspeksi body lengkap atau dump response tanpa batas (full payload / reflected findings).
- Gunakan `get_traffic_history` untuk melihat riwayat log traffic yang tersimpan.
- Gunakan `run_pentest_command` untuk seluruh utilitas command-line terminal (terinspeksi SSRF guard & terekam di Audit Trail, mendukung `cwd`).
- Gunakan `record_test_payload` untuk setiap payload yang dirancang (menghasilkan Payload ID).
- Gunakan `browser_navigate_and_render` untuk aplikasi web SPA dinamis (mengembalikan daftar endpoint API/URL yang terintercept).

### TAHAP 5: VALIDASI TOOLS TERHADAP OWASP JUICE SHOP (https://juice-shop.herokuapp.com/#/)
Eksekusi 4 pengujian validasi berikut secara berurutan menggunakan tool Proxynth MCP:

1. [TOOL 1: browser_navigate_and_render]
   - Panggil tool `browser_navigate_and_render` dengan url: `https://juice-shop.herokuapp.com/#/`.
   - Reasoning: "Render OWASP Juice Shop dynamic Angular SPA and intercept background REST API sub-requests".
   - Verifikasi bahwa DOM text berhasil diekstrak dan sub-request AJAX tercapture.

2. [TOOL 2: send_http_request - API Reconnaissance]
   - Panggil tool `send_http_request`:
     - Method: `GET`
     - URL: `https://juice-shop.herokuapp.com/rest/products/search?q=apple`
     - Reasoning: "Querying Juice Shop search API for baseline response".
   - Verifikasi bahwa response status code adalah 200 OK dengan format JSON produk.

3. [TOOL 3: send_http_request & record_test_payload - SQLi Fuzzing]
   - Uji payload SQL Injection pada search endpoint:
     - Method: `GET`
     - URL: `https://juice-shop.herokuapp.com/rest/products/search?q=apple%27%29%29--`
     - Reasoning: "Testing SQL injection string termination in Juice Shop search query".
   - Catat payload tersebut ke Proxynth Payload Vault dengan memanggil `record_test_payload`:
     - target_url: `https://juice-shop.herokuapp.com/rest/products/search?q=apple`
     - vuln_type: `SQLI`
     - raw_payload: `apple'))--`
     - target_param: `q`
     - outcome: `TESTED`
     - reasoning: "Juice Shop products search parameter injection test".

4. [TOOL 4: run_pentest_command - Recon CLI Safe-Mode]
   - Panggil tool `run_pentest_command`:
     - Command: `python -c "import urllib.request; resp = urllib.request.urlopen('https://juice-shop.herokuapp.com/'); print('Juice Shop HTTP Status:', resp.status)"`
     - Tool_name: `python`
     - Reasoning: "Validating outbound target connectivity via CLI safe-mode".

5. [TOOL 5: report_vulnerability - Exploit Verification & Findings Flagging]
   - Panggil tool `report_vulnerability`:
     - log_id: (Gunakan Log ID dari request pertama send_http_request)
     - title: "SQL Injection — Parameter Probe Verified"
     - severity: "HIGH"
     - category: "SQL Injection"
     - evidence: "Target returned differential responses on SQL injection probe."

### TAHAP 6: LAPORAN STATUS AKHIR
Tampilkan ringkasan verifikasi yang mencakup:
- Status instalasi Proxynth environment.
- Status koneksi MCP Server & Dashboard (HTTP 200).
- Ringkasan hasil eksekusi 5 tools di atas (Latency, Status Code, DOM title, Payload ID, dan Finding ID).
- Konfirmasi bahwa traffic, payload, dan finding telah muncul di Proxynth Dashboard (http://127.0.0.1:8000).
```
