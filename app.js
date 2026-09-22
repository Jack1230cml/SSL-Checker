'use strict';

/**
 * SSL-Checker web service (Node.js).
 *
 * Exposes `POST /api/check` for querying the SSL/TLS state of an arbitrary
 * `host:port`, plus the static web UI in `public/`. This is the entry point
 * Phusion Passenger / Plesk "Node.js" hosting runs (`node app.js`).
 */

const express = require('express');
const path = require('path');
const { checkSSL } = require('./lib/checker');
const {
  getClientIp,
  isRateLimited,
  recordHit,
  createChallenge,
  verifyChallenge,
  markVerified,
} = require('./lib/rate-limit');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/check', async (req, res) => {
  const ip = getClientIp(req);

  // Anti-abuse: an IP that checks too often must solve a challenge first.
  if (isRateLimited(ip)) {
    return res.status(429).json({ detail: 'rate_limited', challenge: createChallenge() });
  }

  const body = req.body || {};
  const host = cleanHost(body.host);
  const port = normalizePort(body.port);

  if (!host) return res.status(400).json({ detail: 'host is required' });
  if (!port) {
    return res.status(400).json({ detail: 'port must be an integer between 1 and 65535' });
  }

  recordHit(ip);

  try {
    const result = await checkSSL(host, port);
    res.json(result);
  } catch (err) {
    res.status(500).json({ detail: err.message || String(err) });
  }
});

app.post('/api/verify', (req, res) => {
  const ip = getClientIp(req);
  const { id, answer } = req.body || {};

  if (!id || answer == null || answer === '') {
    return res.status(400).json({ detail: 'challenge id and answer are required' });
  }

  if (verifyChallenge(id, answer)) {
    markVerified(ip);
    return res.json({ ok: true });
  }

  return res.status(400).json({ detail: 'wrong answer', challenge: createChallenge() });
});

function cleanHost(raw) {
  if (typeof raw !== 'string') return '';
  let h = raw.trim();
  if (!h) return '';
  h = h.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, ''); // strip scheme
  h = h.split('/')[0]; // strip path
  h = h.split('@').pop(); // strip userinfo
  // IPv6 literal: [::1] or [::1]:port
  const ipv6 = h.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (ipv6) return ipv6[1];
  // host:port -> host (single colon only, so IPv6 like ::1 is untouched)
  const hostPort = h.match(/^([^:]+):(\d+)$/);
  if (hostPort) return hostPort[1];
  return h.trim();
}

function normalizePort(raw) {
  const p = Number(raw);
  return Number.isInteger(p) && p >= 1 && p <= 65535 ? p : null;
}

// Passenger provides PORT and reverse-proxies to it. Bind all interfaces
// (no host argument) — never bind to a machine hostname.
//
// NOTE: do NOT guard this with `if (require.main === module)`. Plesk's
// Phusion Passenger loads the app via require(), so `require.main` is the
// Passenger loader, not app.js — the guard would silently skip app.listen()
// and every request would 500. Always listen unconditionally.
const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`SSL-Checker listening on port ${port}`);
});
