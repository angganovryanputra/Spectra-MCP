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
```

---

## 3. Fitur Utama yang Aktif

- **Traffic Isolation:** Request inferensi LLM (OpenCode/Hermes ke OpenAI/Anthropic/Ollama) tidak tercampur atau terganggu oleh lalu lintas pengujian.
- **Interactive Intercept (Proxy Trap):** Operator dapat menahan (pause), memodifikasi, atau membatalkan request agen sebelum dikirim ke target.
- **Scope & Guardrails:** Memblokir tautan destruktif (`logout`, `delete`, `payment`) atau domain eksternal secara otomatis.
- **Repeater Console:** Operator dapat menguji ulang request agen dengan payload kustom secara berdampingan.
- **Export HAR 1.2 & Markdown:** Ekspor seluruh lalu lintas pengujian untuk dianalisis di Burp Suite atau dibuat laporan pentest eksekutif.
- **Automated Dual-Track Triage:** Klasifikasi otomatis kerentanan Confirmed vs Potential.
