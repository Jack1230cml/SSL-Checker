'use strict';

/**
 * In-memory rate limiter + self-contained math-CAPTCHA challenge.
 *
 * - Tracks check requests per client IP (sliding window).
 * - When an IP exceeds LIMIT requests within WINDOW_MS, /api/check returns 429
 *   with a math challenge instead of processing.
 * - The client solves it via POST /api/verify; on success the IP is marked
 *   verified for VERIFIED_MS and can use the tool freely again.
 *
 * State is in-memory only (resets on restart, per-process). Fine for a
 * single-instance Plesk deployment. All knobs are env-tunable.
 */

const crypto = require('crypto');

const LIMIT = Number(process.env.RATE_LIMIT || 5);
const WINDOW_MS = Number(process.env.RATE_WINDOW_MS || 10 * 60 * 1000); // 10 min
const VERIFIED_MS = Number(process.env.RATE_VERIFIED_MS || 60 * 60 * 1000); // 1 h grace
const CHALLENGE_TTL_MS = Number(process.env.RATE_CHALLENGE_TTL_MS || 5 * 60 * 1000); // 5 min

const timestamps = new Map(); // ip -> number[] (recent request times)
const verifiedUntil = new Map(); // ip -> timestamp
const challenges = new Map(); // id -> { answer, expires }

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function _prune(ip) {
  const now = Date.now();
  let arr = timestamps.get(ip) || [];
  arr = arr.filter((t) => now - t < WINDOW_MS);
  if (arr.length) timestamps.set(ip, arr);
  else timestamps.delete(ip);
  return arr;
}

function isRateLimited(ip) {
  const until = verifiedUntil.get(ip) || 0;
  if (Date.now() < until) return false; // still within verified grace period
  return _prune(ip).length >= LIMIT;
}

function recordHit(ip) {
  const arr = _prune(ip);
  arr.push(Date.now());
  timestamps.set(ip, arr);
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

function verifyChallenge(id, answer) {
  const c = challenges.get(id);
  if (!c) return false;
  challenges.delete(id); // single-use
  if (Date.now() > c.expires) return false;
  return Number(answer) === c.answer;
}

function markVerified(ip) {
  verifiedUntil.set(ip, Date.now() + VERIFIED_MS);
}

// Periodic cleanup to prevent unbounded growth of the three maps.
const cleanup = setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) if (now > c.expires) challenges.delete(id);
  for (const [ip, until] of verifiedUntil) if (now > until) verifiedUntil.delete(ip);
}, 5 * 60 * 1000);
if (cleanup.unref) cleanup.unref();

module.exports = {
  getClientIp,
  isRateLimited,
  recordHit,
  createChallenge,
  verifyChallenge,
  markVerified,
  LIMIT,
  WINDOW_MS,
  VERIFIED_MS,
};
