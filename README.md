# 🔒 SSL Checker

Inspect the SSL/TLS details of any `host:port` — negotiated protocol, cipher
suite, and a full breakdown of the certificate chain.

Built with **Node.js** (Express backend + vanilla-JS web UI). The server makes
the actual TLS connection, so it can check **any** host and port (unlike a
pure browser-based tool, which is limited by CORS and can only fetch HTTPS URLs
on 443).

## Features

- Check any `host:port` (default port `443`)
- Negotiated **TLS version** and **cipher suite** (with key size)
- Certificate details: subject / issuer, serial number, signature algorithm,
  public key (algorithm + size/curve), SHA-256 fingerprint
- **SANs** (Subject Alternative Names) — DNS + IP
- Validity window with **days remaining** and status
  (`valid` / `expiring_soon` / `expired` / `not_yet_valid`)
- Full **certificate chain** with per-cert expiry
- **Verification status** against the system trust store — self-signed /
  expired / misconfigured certs still show their details (with a warning)
- IPv6 literals (`[::1]:443`), pasted URLs, and `host:port` in a single box

## Quick start

```bash
npm install
npm start          # or: node app.js
```

Then open <http://localhost:3000> and enter a host.

## Deploying to Plesk (Node.js hosting)

Plesk's **Node.js** hosting runs the app via Phusion Passenger, which executes
the *Application Startup File* — for this repo that's **`app.js`**.

1. In Plesk, create the (sub)domain with **Node.js** hosting type.
2. Upload/copy the repo contents into the **Application Root** — so it contains
   `app.js`, `lib/`, `public/` and `package.json`.
3. In Plesk → **Websites & Domains → [domain] → Node.js**, set:
   - **Document Root** → the app root (or a `public/` subdir)
   - **Application Mode** → `production`
   - **Application Startup File** → `app.js`
4. Run **npm install** (Plesk's "Run npm install" button, or over SSH:
   `cd /var/www/vhosts/<domain>/httpdocs && npm install`).
5. Restart the app from the Plesk UI.

The app reads the `PORT` env var Passenger provides and binds all interfaces
(no host argument), so Passenger's reverse proxy can reach it.

Verify from the server's own shell (must hit the same host the browser hits):

```bash
curl -s http://localhost:<port>/api/health           # -> {"status":"ok"}
curl -s -X POST http://localhost:<port>/api/check -H "Content-Type: application/json" \
  -d '{"host":"google.com","port":443}'              # -> JSON report
```

> **`app.js` is both the server entry point AND the startup file.** The browser
> UI JavaScript lives in `public/main.js` (not `app.js`) to avoid any clash with
> the Passenger startup-file name.

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
    "public_key": { "algorithm": "EC", "curve": "prime256v1", "bits": 256 },
    "fingerprint_sha256": "ab12..."
  },
  "certificates": [ "…leaf…", "…intermediate…", "…root…" ]
}
```

### `GET /api/health`

```json
{ "status": "ok" }
```

## Rate limiting & anti-abuse

To stop one IP from hammering the checker, `/api/check` is rate-limited. When
an IP makes more than `RATE_LIMIT` requests within `RATE_WINDOW_MS`, the API
returns **429** with a self-contained **math challenge**:

```json
{ "detail": "rate_limited", "challenge": { "id": "...", "question": "7 + 4 = ?" } }
```

The client solves it via `POST /api/verify` (`{ id, answer }`); on a correct
answer the server returns a **single-use token** that lets exactly one
`/api/check` through — every request beyond the limit needs its own solve. All
knobs are env-tunable (defaults shown):

| Env var | Default | Meaning |
|---|---|---|
| `RATE_LIMIT` | `5` | requests allowed per window |
| `RATE_WINDOW_MS` | `600000` | window in ms (10 min) |
| `RATE_CHALLENGE_TTL_MS` | `300000` | challenge lifetime (5 min) |
| `RATE_TOKEN_TTL_MS` | `60000` | single-use token lifetime (1 min) |

State is in-memory (per-process), so it resets on app restart — fine for a
single-instance Plesk deployment.

## Project layout

```
SSL-Checker/
├── app.js              # Express server entry point (Passenger startup file)
├── lib/
│   ├── checker.js      # core TLS inspection logic (tls + crypto + node-forge)
│   └── rate-limit.js   # per-IP rate limiter + math-CAPTCHA challenge
├── public/             # web UI (index.html, style.css, main.js)
└── package.json
```

## Notes

- **Verification** uses Node's default trust store (`rejectUnauthorized: true`).
- The full chain is walked from `getPeerCertificate(true)`; the loop guards
  against self-signed roots whose `issuerCertificate` points back to themselves.
- The signature algorithm is read straight off the certificate DER (via
  `node-forge`) because `getPeerCertificate()` does not expose it, and
  `forge.pki.certificateFromPem` throws on EC/EdDSA public keys.
- Certificates expiring within **14 days** are flagged `expiring_soon`.
