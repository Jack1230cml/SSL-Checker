# 🔒 SSL Checker

Inspect the SSL/TLS details of any `host:port` — negotiated protocol, cipher
suite, and a full breakdown of the certificate chain.

Built with **FastAPI** (backend) + a lightweight vanilla-JS web UI. The server
makes the actual TLS connection, so it can check **any** host and port (unlike
a pure browser-based tool, which is limited by CORS and can only fetch HTTPS
URLs on 443).

## Features

- Check any `host:port` (default port `443`)
- Negotiated **TLS version** and **cipher suite**
- Certificate details: subject / issuer, serial number, signature algorithm,
  public key (algorithm + size), SHA-256 fingerprint
- **SANs** (Subject Alternative Names) — DNS + IP
- Validity window with **days remaining** and status
  (`valid` / `expiring_soon` / `expired` / `not_yet_valid`)
- Full **certificate chain** with per-cert expiry
- **Verification status** against the system trust store — self-signed /
  expired / misconfigured certs still show their details (with a warning)
- IPv6 literals (`[::1]:443`), pasted URLs, and `host:port` in a single box

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
uvicorn app.main:app --reload --port 8000
```

Then open <http://localhost:8000> and enter a host.

## Deploying to Plesk

Plesk runs Python apps through **Phusion Passenger**, which is WSGI-only. The
repo ships a `passenger_wsgi.py` entry point that bridges FastAPI (ASGI) to WSGI
via `a2wsgi`, so Passenger can serve it directly.

1. In Plesk, create the (sub)domain and set its document root to a folder where
   you'll place the app (e.g. `httpdocs/`).
2. Upload/copy the repo contents **into the document root** — so the doc root
   contains `app/`, `passenger_wsgi.py` and `requirements.txt`.
3. Over SSH (as the domain user or root), install dependencies into a
   **virtualenv inside the doc root** — Passenger's `passenger_wsgi.py` picks it
   up automatically:
   ```bash
   cd /var/www/vhosts/<domain>/httpdocs
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt
   ```
   (If `python3` isn't the system interpreter, use the Plesk-managed one, e.g.
   `/opt/plesk/python/3.11/bin/python3`.)
4. Make sure `passenger_wsgi.py` and `app/` are readable by the web-server user
   (`psaserv` / `psacln` group). Plesk usually handles this automatically.
5. In Plesk → **Websites & Domains → [domain] → Hosting Settings**, the app is
   served automatically once `passenger_wsgi.py` is in the doc root. If it shows
   a 503/"Web application could not be started", restart the domain's
   PHP/FastCGI/Passenger app from the Plesk UI and check the error log at
   `/var/www/vhosts/<domain>/logs/error_log`.

Verify from the server's own shell (must hit the same host the browser hits):

```bash
curl -s https://<domain>/api/health          # -> {"status":"ok"}
curl -s -X POST https://<domain>/api/check -H "Content-Type: application/json" \
  -d '{"host":"google.com","port":443}'      # -> JSON report
```

> **Alternative (full ASGI / WebSocket):** run `uvicorn` as a systemd service
> and reverse-proxy to it from Plesk's nginx (Domains → Apache & nginx Settings →
> Additional nginx directives). More moving parts, but no WSGI bridge needed.

## API

### `POST /api/check`

Request body:

```json
{ "host": "example.com", "port": 443 }
```

Response (abridged):

```json
{
  "host": "example.com",
  "port": 443,
  "connected": true,
  "tls_negotiated": true,
  "tls_version": "TLSv1.3",
  "cipher": { "name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256 },
  "ip_address": "93.184.216.34",
  "verified": true,
  "verify_error": null,
  "certificate": {
    "subject": { "CN": "www.example.org" },
    "issuer": { "CN": "DigiCert Global G2 TLS RSA SHA256 2020 CA1" },
    "serial_number": "0FBF...",
    "signature_algorithm": "sha256WithRSAEncryption",
    "not_before": "2025-01-30T00:00:00Z",
    "not_after": "2026-03-01T23:59:59Z",
    "days_remaining": 123,
    "validity_status": "valid",
    "san": { "dns": ["www.example.org", "example.org"], "ip": [] },
    "public_key": { "algorithm": "RSA", "bits": 2048 },
    "fingerprint_sha256": "ab12...",
    "version": "v3"
  },
  "certificates": [ "…leaf…", "…intermediate…", "…root…" ]
}
```

### `GET /api/health`

```json
{ "status": "ok" }
```

## Project layout

```
SSL-Checker/
├── app/
│   ├── __init__.py
│   ├── checker.py      # core TLS inspection logic (ssl + cryptography)
│   ├── main.py         # FastAPI app + /api/check endpoint
│   └── static/         # web UI (index.html, style.css, app.js)
├── requirements.txt
└── README.md
```

## Notes

- **Verification** uses the system trust store (`ssl.create_default_context()`).
  On Linux this is usually `/etc/ssl/certs`; on Windows the OS certificate store.
- The full chain is extracted on **Python 3.13+** (`get_verified_chain` /
  `get_unverified_chain`); on older interpreters only the leaf certificate is
  reported.
- Certificates expiring within **14 days** are flagged `expiring_soon`.
