# 🔒 SSL Checker

Inspect the SSL/TLS details of any `host:port` — negotiated protocol and cipher
suite, a full certificate-chain breakdown, and an SSL-Labs-style security scan
(revocation, cipher enumeration, HSTS, CAA).

Built with **Node.js** (Express backend + vanilla-JS web UI). The server makes
the actual TLS connection, so it can check **any** host and port (unlike a
pure browser-based tool, which is limited by CORS and can only fetch HTTPS URLs
on 443).

## Features

**Core check**

- Check any `host:port` (default port `443`); IPv6 literals (`[::1]:443`),
  pasted URLs, and `host:port` all in a single box
- Negotiated **TLS version** and **cipher suite** (with key size)
- **Verification status** against the system trust store — self-signed,
  expired, or misconfigured certs still show their details with a warning
- Summary header (host, resolved IP, test duration)

**Certificate**

- Subject / issuer (organisation + country), serial number, signature
  algorithm, public key (algorithm + size/curve), SHA-256 fingerprint
- **SANs** (Subject Alternative Names) — DNS + IP
- **Name matches domain** (wildcard-aware) and **certificate type**
  (DV/OV/EV × wildcard/multi-domain/single)
- Validity window with **days remaining** and **total validity period**, plus
  status (`valid` / `expiring_soon` / `expired` / `not_yet_valid`)
- Full **certificate chain** (collapsible accordion) with per-cert expiry;
  every cert has **view/copy PEM** and **download `.pem`**
- **OCSP** and **CA Issuers** URLs

**Advanced security scan**

- **OCSP/CRL revocation status** (live query against the responder)
- **Supported TLS versions** (1.0–1.3)
- **DNS CAA** records
- **Cipher suite enumeration** — probed individually, classified
  secure / moderate / weak / insecure with a forward-secrecy flag
- **HSTS** (HTTP Strict-Transport-Security) header

**Anti-abuse**

- Per-IP daily rate limit with a self-contained math CAPTCHA (single-use token)

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
  "checked_at": "2026-09-22T12:00:00Z",
  "duration_ms": 412,
  "connected": true,
  "tls_negotiated": true,
  "tls_version": "TLSv1.3",
  "cipher": { "name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256 },
  "ip_address": "93.184.216.34",
  "verified": true,
  "verify_error": null,
  "name_matches": true,
  "revocation": { "status": "good", "detail": "" },
  "supported_tls_versions": ["TLSv1.2", "TLSv1.3"],
  "caa": { "found": true, "issue": ["letsencrypt.org"], "issuewild": [], "iodef": [] },
  "cipher_suites": [
    { "name": "ECDHE-RSA-AES256-GCM-SHA384", "strength": "secure", "pfs": true }
  ],
  "hsts": { "found": true, "value": "max-age=31536000; includeSubdomains" },
  "certificate": {
    "subject": { "CN": "www.example.org" },
    "issuer": { "CN": "DigiCert Global G2 TLS RSA SHA256 2020 CA1", "O": "DigiCert Inc", "C": "US" },
    "serial_number": "0FBF...",
    "signature_algorithm": "sha256WithRSAEncryption",
    "not_before": "2025-01-30T00:00:00Z",
    "not_after": "2026-03-01T23:59:59Z",
    "days_remaining": 123,
    "validity_days_total": 90,
    "validity_status": "valid",
    "cert_type": "Domain Validation (Multi-Domain)",
    "san": { "dns": ["www.example.org", "example.org"], "ip": [] },
    "ocsp_url": "http://ocsp.digicert.com",
    "ca_issuers_url": "http://cacerts.digicert.com/DigiCertGlobalG2.crt",
    "public_key": { "algorithm": "EC", "curve": "prime256v1", "bits": 256 },
    "fingerprint_sha256": "ab12...",
    "pem": "-----BEGIN CERTIFICATE-----\n..."
  },
  "certificates": [ "…leaf…", "…intermediate…", "…root…" ]
}
```

`revocation.status` is one of `good` / `revoked` / `unknown` / `error` (the
last two when the responder is unreachable or the cert has no OCSP URL).
`cipher_suites` entries carry `strength` (`secure`/`moderate`/`weak`/
`insecure`) and `pfs` (forward secrecy). Every certificate in `certificates`
also has a `pem` field for view/download.

### `GET /api/health`

```json
{ "status": "ok" }
```

## Rate limiting & anti-abuse

To stop one IP from hammering the checker, `/api/check` is capped at
`RATE_DAILY_LIMIT` requests per **calendar day** (server-local time). Past
that, the API returns **429** with a self-contained **math challenge** on
every request until the next day:

```json
{ "detail": "rate_limited", "challenge": { "id": "...", "question": "7 + 4 = ?" } }
```

The client solves it via `POST /api/verify` (`{ id, answer }`); on a correct
answer the server returns a **single-use token** that lets exactly one
`/api/check` through — every request past the daily limit needs its own solve.
The counter resets at midnight (server-local). All knobs are env-tunable
(defaults shown):

| Env var | Default | Meaning |
|---|---|---|
| `RATE_DAILY_LIMIT` | `20` | requests allowed per calendar day |
| `RATE_CHALLENGE_TTL_MS` | `300000` | challenge lifetime (5 min) |
| `RATE_TOKEN_TTL_MS` | `60000` | single-use token lifetime (1 min) |

State is in-memory (per-process), so it resets on app restart — fine for a
single-instance Plesk deployment. The day boundary uses the server's local
timezone (override with the `TZ` env var if needed).

## Project layout

```
SSL-Checker/
├── app.js              # Express server entry point (Passenger startup file)
├── lib/
│   ├── checker.js      # core TLS inspection (tls + crypto + node-forge + ocsp)
│   └── rate-limit.js   # per-IP rate limiter + math-CAPTCHA challenge
├── public/             # web UI (index.html, style.css, main.js)
└── package.json        # deps: express, node-forge, ocsp
```

## Notes

- **Verification** uses Node's default trust store (`rejectUnauthorized: true`).
- The full chain is walked from `getPeerCertificate(true)`; the loop guards
  against self-signed roots whose `issuerCertificate` points back to themselves.
- The signature algorithm is read straight off the certificate DER (via
  `node-forge`) because `getPeerCertificate()` does not expose it, and
  `forge.pki.certificateFromPem` throws on EC/EdDSA public keys.
- Certificates expiring within **14 days** are flagged `expiring_soon`.
- On a successful handshake the advanced probes run in parallel and each one
  degrades gracefully if its responder/resolver is unreachable:
  - **OCSP revocation** — the request is built with the `ocsp` package (which
    parses EC certs that node-forge can't) and the response's `certStatus` is
    parsed directly, skipping the EC signature verification that `ocsp.verify`
    fails on.
  - **Supported TLS versions** and **cipher suites** — probed with per-cipher
    `minVersion`/`maxVersion` pins; ciphers removed from modern OpenSSL
    (RC4/DES) throw synchronously, so `tls.connect` is guarded.
  - **DNS CAA** — resolved via `dns.resolve(…, 'CAA')`; a resolver that lacks
    CAA support returns "no records" rather than failing the whole report.
