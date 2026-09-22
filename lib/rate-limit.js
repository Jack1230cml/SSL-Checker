'use strict';

/**
 * In-memory per-IP daily rate limiter + self-contained math-CAPTCHA challenge.
 *
 * - Tracks check requests per client IP for the current calendar day (server
 *   local time).
 * - Once an IP exceeds DAILY_LIMIT requests today, EVERY further request must
 *   solve a math challenge first. The counter resets at the next calendar day.
 * - Solving a challenge via /api/verify issues a single-use token; presenting
 *   that token on the next /api/check lets exactly ONE request through.
 *
 * State is in-memory only (resets on restart, per-process). Fine for a
 * single-instance Plesk deployment. All knobs are env-tunable.
 */

const crypto = require('crypto');

const DAILY_LIMIT = Number(process.env.RATE_DAILY_LIMIT || process.env.RATE_LIMIT || 20);
const CHALLENGE_TTL_MS = Number(process.env.RATE_CHALLENGE_TTL_MS || 5 * 60 * 1000); // 5 min
const TOKEN_TTL_MS = Number(process.env.RATE_TOKEN_TTL_MS || 60 * 1000); // 1 min (single-use)

const daily = new Map(); // ip -> { day: 'YYYY-M-D', count }
const challenges = new Map(); // id -> { answer, expires }
const tokens = new Map(); // token -> { ip, expires }

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/** Calendar day key in server-local time (resets at midnight). */
function dayKey(now = new Date()) {
  return `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
}

function _state(ip, now = new Date()) {
  const today = dayKey(now);
  let s = daily.get(ip);
  if (!s || s.day !== today) {
    s = { day: today, count: 0 }; // new day -> reset
    daily.set(ip, s);
  }
  return s;
}

function isRateLimited(ip, now) {
  return _state(ip, now).count >= DAILY_LIMIT;
}

function recordHit(ip, now) {
  _state(ip, now).count += 1;
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function createChallenge() {
  const useMult = Math.random() < 0.4;
  let a, b, op, answer;
  if (useMult) {
    a = randInt(2, 9);
    b = randInt(2, 9);
    op = '×';
    answer = a * b;
  } else {
    a = randInt(1, 20);
    b = randInt(1, 20);
    op = '+';
    answer = a + b;
  }
  const id = crypto.randomUUID();
  challenges.set(id, { answer, expires: Date.now() + CHALLENGE_TTL_MS });
  return { id, question: `${a} ${op} ${b} = ?` };
}

/**
 * Validate a challenge answer. On success issues a single-use token bound to
 * the IP and returns it; returns null on any failure (missing, expired, wrong).
 */
function verifyChallenge(id, answer, ip) {
  const c = challenges.get(id);
  if (!c) return null;
  challenges.delete(id); // single-use
  if (Date.now() > c.expires) return null;
  if (Number(answer) !== c.answer) return null;

  const token = crypto.randomUUID();
  tokens.set(token, { ip, expires: Date.now() + TOKEN_TTL_MS });
  return token;
}

/** Consume a single-use token for `ip`; returns true only if valid & unused. */
function consumeToken(token, ip) {
  const t = tokens.get(token);
  if (!t) return false;
  tokens.delete(token); // single-use
  if (t.ip !== ip) return false;
  return Date.now() <= t.expires;
}

// Periodic cleanup to prevent unbounded growth.
const cleanup = setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) if (now > c.expires) challenges.delete(id);
  for (const [t, e] of tokens) if (now > e.expires) tokens.delete(t);
  const today = dayKey();
  for (const [ip, s] of daily) if (s.day !== today) daily.delete(ip); // drop stale days
}, 5 * 60 * 1000);
if (cleanup.unref) cleanup.unref();

module.exports = {
  getClientIp,
  isRateLimited,
  recordHit,
  createChallenge,
  verifyChallenge,
  consumeToken,
  DAILY_LIMIT,
  dayKey,
};
