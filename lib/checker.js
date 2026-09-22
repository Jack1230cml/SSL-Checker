'use strict';

/**
 * Core SSL/TLS inspection logic.
 *
 * Connects to a `host:port` over TLS and returns a structured breakdown of the
 * handshake: negotiated protocol, cipher suite, and a full parse of the
 * certificate chain (subject, issuer, SANs, validity, key, fingerprint,
 * verification status, ...).
 *
 * The connection is made twice:
 *   1. A *verified* attempt (rejectUnauthorized) — determines whether the
 *      chain actually validates.
 *   2. If that fails on a certificate error, an *unverified* attempt so we can
 *      still report the details for self-signed / expired / misconfigured
 *      servers instead of returning just an error.
 */

const tls = require('tls');
const { createPublicKey } = require('crypto');
const forge = require('node-forge');

const EXPIRY_WARNING_DAYS = 14;
const DAY_MS = 86400000;

// Signature algorithm OIDs not covered (or poorly covered) by node-forge's
// forge.pki.oids — notably the ECDSA-with-SHA2 family.
const SIGNATURE_ALGORITHMS = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'ed25519',
  '1.3.101.113': 'ed448',
};

// Node error codes that indicate a *certificate* (not network) failure.
const CERT_ERROR_CODES = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_UNTRUSTED',
  'CERT_REVOKED',
  'ERR_SSL_CERTIFICATE_VERIFY_FAILED',
  'HOSTNAME_MISMATCH',
]);

function isCertError(err) {
  return Boolean(err && err.code && CERT_ERROR_CODES.has(err.code));
}

function friendlyError(err, timeout) {
  if (!err) return 'Unknown error';
  switch (err.code) {
    case 'ECONNREFUSED':
      return 'Connection refused (nothing listening on that port?)';
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return `Could not resolve host: ${err.hostname || ''}`.trim();
    case 'ETIMEDOUT':
      return `Connection timed out after ${(timeout || 8000) / 1000}s`;
    case 'EPROTO':
    case 'ERR_SSL_WRONG_VERSION_NUMBER':
    case 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION':
      return 'Connected, but the server does not speak TLS on this port';
    default:
      return err.message || err.code || String(err);
  }
}

function certErrorText(err) {
  if (!err) return 'certificate verification failed';
  return err.reason || err.message || err.code || 'certificate verification failed';
}

/** Extract the cipher key size (AES-256 => 256, CHACHA20 => 256, ...). */
function cipherBits(name) {
  if (!name) return null;
  const m = /AES[-_]?(\d{3})/i.exec(name);
  if (m) return parseInt(m[1], 10);
  if (/CHACHA20/i.test(name)) return 256;
  return null;
}

/**
 * Map a certificate's signature OID to a friendly name.
 *
 * We parse only the signatureAlgorithm OID straight off the DER instead of
 * using forge.pki.certificateFromPem, because the latter tries to parse the
 * public key and throws "Cannot read public key. OID is not RSA." on EC/EdDSA
 * certificates.
 */
function signatureAlgorithm(rawDer) {
  if (!rawDer) return null;
  try {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    const asn1 = forge.asn1.fromDer(Buffer.from(rawDer).toString('binary'));
    const top = asn1.value;
    if (!Array.isArray(top) || top.length < 2) return null;
    const sigAlg = top[1]; // AlgorithmIdentifier (SEQUENCE)
    const oidAsn1 = sigAlg.value && sigAlg.value[0];
    if (!oidAsn1) return null;
    const oid = forge.asn1.derToOid(oidAsn1.value);
    return SIGNATURE_ALGORITHMS[oid] || forge.pki.oids[oid] || oid || null;
  } catch {
    return null;
  }
}

function parseSan(subjectaltname) {
  const dns = [];
  const ip = [];
  if (subjectaltname) {
    for (const part of String(subjectaltname).split(/,\s*/)) {
      const m = part.match(/^(DNS|IP(?: Address)?):(.+)$/i);
      if (!m) continue;
      const kind = m[1].toLowerCase();
      if (kind === 'dns') dns.push(m[2]);
      else ip.push(m[2]);
    }
  }
  return { dns, ip };
}

function keyInfo(c) {
  try {
    if (c.pubkey) {
      const k = createPublicKey(c.pubkey);
      const type = k.asymmetricKeyType;
      const details = k.asymmetricKeyDetails || {};
      if (type === 'rsa') return { algorithm: 'RSA', bits: details.modulusLength || c.bits || null };
      if (type === 'ec') return { algorithm: 'EC', curve: details.namedCurve || c.asn1Curve || null, bits: c.bits || null };
      if (type === 'ed25519') return { algorithm: 'Ed25519', bits: 256 };
      if (type === 'ed448') return { algorithm: 'Ed448', bits: 448 };
      return { algorithm: type, bits: c.bits || null };
    }
  } catch {
    /* fall through to heuristic */
  }
  if (c.asn1Curve) return { algorithm: 'EC', curve: c.asn1Curve, bits: c.bits || null };
  if (c.exponent || c.modulus) return { algorithm: 'RSA', bits: c.bits || null };
  return { algorithm: null, bits: c.bits || null };
}

function certToDict(c) {
  const now = Date.now();
  const validFrom = c.valid_from ? Date.parse(c.valid_from) : NaN;
  const validTo = c.valid_to ? Date.parse(c.valid_to) : NaN;
  const daysLeft = Number.isFinite(validTo) ? Math.floor((validTo - now) / DAY_MS) : null;

  let status = 'valid';
  if (Number.isFinite(validFrom) && Number.isFinite(validTo)) {
    if (now < validFrom) status = 'not_yet_valid';
    else if (now > validTo) status = 'expired';
    else if (daysLeft <= EXPIRY_WARNING_DAYS) status = 'expiring_soon';
  }

  return {
    subject: c.subject || {},
    issuer: c.issuer || {},
    serial_number: (c.serialNumber || '').replace(/:/g, '').toUpperCase(),
    signature_algorithm: signatureAlgorithm(c.raw),
    not_before: Number.isFinite(validFrom) ? new Date(validFrom).toISOString() : null,
    not_after: Number.isFinite(validTo) ? new Date(validTo).toISOString() : null,
    days_remaining: daysLeft,
    validity_status: status,
    san: parseSan(c.subjectaltname),
    public_key: keyInfo(c),
    fingerprint_sha256: (c.fingerprint256 || '').replace(/:/g, '').toLowerCase(),
  };
}

function collect(socket, host, port) {
  const cipher = socket.getCipher() || {};
  const full = socket.getPeerCertificate(true);

  const certs = [];
  const seen = new Set();
  let c = full;
  while (c && c.subject && Object.keys(c.subject).length && !seen.has(c)) {
    seen.add(c);
    certs.push(certToDict(c));
    c = c.issuerCertificate;
  }

  return {
    host,
    port,
    connected: true,
    tls_negotiated: true,
    tls_version: socket.getProtocol(),
    cipher: cipher.name
      ? { name: cipher.name, protocol: cipher.version || null, bits: cipherBits(cipher.name) }
      : null,
    ip_address: socket.remoteAddress || null,
    certificates: certs,
    certificate: certs[0] || null,
  };
}

function connect(host, port, timeout, verify) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: verify,
      timeout,
    });
    let settled = false;
    const finish = (fn, arg) => {
      if (!settled) {
        settled = true;
        fn(arg);
      }
    };

    socket.setTimeout(timeout);
    socket.once('secureConnect', () => {
      const data = collect(socket, host, port);
      socket.destroy();
      finish(resolve, data);
    });
    socket.once('timeout', () => {
      socket.destroy();
      const err = new Error(`Connection timed out after ${timeout / 1000}s`);
      err.code = 'ETIMEDOUT';
      finish(reject, err);
    });
    socket.once('error', (err) => {
      socket.destroy();
      finish(reject, err);
    });
  });
}

/**
 * Inspect the SSL/TLS state of `host:port` and return a full report.
 * @param {string} host
 * @param {number} port
 * @param {number} [timeout=8000] timeout in ms
 */
async function checkSSL(host, port, timeout = 8000) {
  const base = {
    host,
    port,
    checked_at: new Date().toISOString(),
    connected: false,
    tls_negotiated: false,
    verified: false,
    verify_error: null,
    error: null,
  };

  try {
    const data = await connect(host, port, timeout, true);
    return { ...base, ...data, verified: true };
  } catch (err) {
    if (isCertError(err)) {
      try {
        const data = await connect(host, port, timeout, false);
        return { ...base, ...data, verified: false, verify_error: certErrorText(err) };
      } catch (err2) {
        return { ...base, error: friendlyError(err2, timeout) };
      }
    }
    return { ...base, error: friendlyError(err, timeout) };
  }
}

module.exports = { checkSSL };
