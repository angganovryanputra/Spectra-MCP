# SPECTRA MCP — AGENT INTEGRATION GUIDE (Opencode / Hermes)

Panduan konfigurasi dan integrasi untuk agen otonom seperti **Opencode**, **Hermes Agent**, **Claude Desktop**, atau **Cursor** agar seluruh lalu lintas pengujian penetrasi (pentest) diarahkan dan ditangkap melalui gateway Spectra MCP.

---

## 1. Konfigurasi MCP Client

Tambahkan konfigurasi server Spectra MCP ke konfigurasi agent Anda:

### Untuk Opencode / Hermes (`mcp_config.json` atau runtime config)
```json
{
  "mcpServers": {
    "spectra": {
      "command": "python",
      "args": ["d:/PROJECT/01/mcp_server.py"],
      "env": {
        "SPECTRA_BACKEND_URL": "http://127.0.0.1:8000",
        "SPECTRA_PROJECT": "client-alpha"
      }
    }
  }
}
```

---

## 2. System Prompt / Instruksi untuk Agen (Opencode / Hermes)

Tambahkan arahan berikut pada system prompt agen agar agen:
1. Selalu menggunakan MCP Tool `send_http_request`.
2. Menyertakan hipotesis/alasan pengujian pada parameter `reasoning`.
3. Mematuhi boundary pengujian yang ditentukan operator.

```text
[SECURITY TESTING DIRECTIVE]
Anda terhubung dengan Spectra Security Testing Gateway melalui MCP Tools:
1. Setiap kali berinteraksi dengan target pentest (HTTP/HTTPS), Anda WAJIB menggunakan tool `send_http_request`. JANGAN menggunakan bash `curl` langsung di terminal host.
2. Selalu sertakan parameter `reasoning` saat memanggil tool untuk menjelaskan hipotesis keamanan Anda (contoh: "Testing SQL injection pada query param id karena aplikasi merespon error SQL").
3. Jika target berada di luar scope atau memicu proteksi guardrail, hormati pesan blokir dan batasi pengujian pada endpoint yang diizinkan.
4. Jika target membutuhkan rendering halaman JavaScript dinamis, gunakan tool `browser_navigate_and_render`.
5. Jika menemui login wall, CAPTCHA, atau Two-Factor Authentication (2FA), gunakan tool `request_manual_login` agar operator manusia dapat melakukan login via browser interaktif.
6. Jika perlu menjalankan perintah terminal / CLI (seperti nmap, curl, sqlmap, custom scripts), gunakan tool `run_pentest_command` agar perintah, stdout, dan stderr terekam di Spectra Command Audit Trail. Anda dapat menentukan parameter `cwd` untuk direktori kerja eksekusi.
7. Jika membuat atau menguji payload eksploitasi khusus (SQLi, XSS, SSRF, SSTI, RCE, IDOR), gunakan tool `record_test_payload` untuk mencatat payload ke dalam Spectra Payload Vault (mengembalikan Payload ID).
8. Jika response body terpotong pada `send_http_request` atau Anda membutuhkan response body/headers utuh untuk analisis mendalam (misal: reflected XSS, token extraction, dump JSON besar), gunakan tool `get_log_detail(log_id=<ID>)` dengan `Log ID` yang didapat dari `send_http_request`.
9. Jika perlu meninjau riwayat request yang pernah dikirim sebelumnya untuk chaining atau replay, gunakan tool `get_traffic_history(project="default", limit=20)`.
10. **Pelaporan & Flagging Kerentanan (Sangat Penting):**
    - Saat mengirim request exploit yang Anda ketahui atau duga sebagai kerentanan, Anda dapat langsung menambahkan parameter di `send_http_request`: `finding_title="SQL Injection — Authentication Bypass"`, `finding_severity="CRITICAL"`, `flag_status="CONFIRMED"`, `finding_category="SQL Injection"`, `finding_evidence="Admin JWT token returned"`.
    - ATAU setelah menganalisis respons dengan `get_log_detail(log_id)`, panggil tool `report_vulnerability(log_id=<ID>, title="...", severity="CRITICAL"|"HIGH"|"MEDIUM", category="...", evidence="...")` untuk mencatat temuan terkonfirmasi ke dalam Spectra Dashboard Findings Ledger.

11. **Standardisasi Output JSON & Token-Saving (Hemat Konteks LLM):**
    - Gunakan `output_format="json"` pada `send_http_request` atau `run_pentest_command` untuk mendapatkan output terstruktur yang mudah diparsing.
    - Gunakan parameter `diff_baseline_id=<ID>` pada `send_http_request` saat mengirim payload variasi/mutasi untuk membandingkan respons dengan baseline awal. Spectra akan menghitung diff unified secara otomatis sehingga menghemat token LLM hingga 90%.
12. **Target Knowledge Graph (Stateful Recon & Surface Mapping):**
    - Gunakan `get_attack_surface(project="...")` untuk melihat topologi aset target, port/layanan terbuka, dan status endpoint yang sudah maupun belum diuji.
    - Catat host/IP baru dengan `record_target_asset(...)`.
    - Catat port terbuka hasil nmap/portscan dengan `record_target_service(...)`.
    - Catat rute/endpoint baru dan update status progresnya (`UNTESTED`, `IN_PROGRESS`, `TESTED_CLEAN`, `TESTED_VULNERABLE`) dengan `record_target_endpoint(...)`.
13. **OAST Engine (Deteksi Blind Vulnerabilities Out-of-Band):**
    - Untuk mendeteksi Blind SSRF, Blind SQLi, Blind RCE, XXE, atau Log4j/JNDI, gunakan `generate_oast_token(vuln_type="SSRF", description="...")`.
    - Masukkan `callback_url` yang diberikan ke dalam payload eksploitasi Anda.
14. **Custom Pentest Scripts & Transparent Proxy Interception (OpenCode / Hermes):**
    - Saat Anda membuat dan mengeksekusi script pentest mandiri (misal: Python `requests`/`httpx`/`urllib`, `curl`, `sqlmap`, `ffuf`, `nuclei`):
      - **Enforcement Otomatis**: Melalui runtime hook `sitecustomize.py` dan environment proxy (`HTTP_PROXY`, `HTTPS_PROXY`), bahkan jika Anda menjalankan script Python via terminal biasa (`python script.py`), lalu lintasnya **pasti otomatis melewati Spectra Forward Proxy (:8088)** dengan TLS MITM decryption tanpa perlu konfigurasi proxy manual di script Anda.
      - **Zero Guardrails by Default**: Secara default tidak ada guardrail yang memblokir target internal/lab (`127.0.0.1`, RFC1918) maupun external domain, sehingga seluruh pengujian berjalan lancar tanpa terhalang SSRF filter bawaan kecuali operator sengaja mengaktifkan Scope Guardrail di Dashboard.
      - Seluruh target hit dari script Anda akan **otomatis tertangkap di Spectra Forward Interception Proxy (:8088)**, disuntikkan session cookies aktif, dianalisis kerentanannya oleh Dual-Track Triage, dan otomatis di-ingest ke Target Knowledge Graph!
    - Untuk script Python tingkat lanjut, Anda juga dapat mengimpor micro-SDK bawaan: `from spectra_client import SpectraSession, report_finding`.
```

---

## 3. Fitur Utama yang Aktif

- **Transparent Auto-Enforcement (`sitecustomize.py` & `.env`):** Menjamin bahwa setiap script Python yang dieksekusi agen otomatis diarahkan ke Forward Interception Proxy Spectra (:8088), bahkan saat agen memanggil terminal host langsung.
- **Zero Default Guardrails:** Secara default guardrail berada dalam status nonaktif (`scope_enabled = False`, `allow_internal_networks = True`, `blocked_patterns = []`). Pengguna memiliki kontrol penuh dan hanya perlu mengatur guardrail manual jika pengujian membutuhkan pembatasan scope ketat.
- **TLS MITM Decryption Engine (Dynamic Cert Generator):** Mendekripsi lalu lintas HTTPS dari script agen secara transparan sehingga payload riil, status code, response body, dan findings langsung tercatat (bukan sekadar tunneling CONNECT blind).
- **Target Knowledge Graph:** State reconnaissance dan mapping target terpusat (Asset -> Service/Port -> Endpoint) dengan tracking status pengujian & auto-ingestion dari script traffic.
- **OAST Engine (Out-of-Band Callback Listener):** Deteksi blind vulnerabilities dengan korelasi token unik dan live WebSocket hit notification.
- **Token-Saving JSON & Differential Analysis:** Output JSON terstruktur dan diffing baseline terotomatisasi untuk efisiensi context window agen.
- **Traffic Isolation:** Request inferensi LLM (OpenCode/Hermes ke OpenAI/Anthropic/Ollama) tidak tercampur atau terganggu oleh lalu lintas pengujian.
- **Interactive Intercept (Proxy Trap):** Operator dapat menahan (pause), memodifikasi, atau membatalkan request agen sebelum dikirim ke target.
- **Scope & Guardrails:** Pembatasan scope fleksibel yang dapat dikonfigurasi sesuai kebutuhan proyek.
- **Repeater Console:** Operator dapat menguji ulang request agen dengan payload kustom secara berdampingan.
- **Export HAR 1.2 & Markdown:** Ekspor seluruh lalu lintas pengujian untuk dianalisis di Burp Suite atau dibuat laporan pentest eksekutif.
- **Automated Dual-Track Triage:** Klasifikasi otomatis kerentanan Confirmed vs Potential.
