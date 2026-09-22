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
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const { createPublicKey } = require('crypto');
const forge = require('node-forge');
const ocsp = require('ocsp');

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

function derToPem(raw) {
  if (!raw) return null;
  try {
    const b64 = Buffer.from(raw).toString('base64');
    const wrapped = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
  } catch {
    return null;
  }
}

/** Return the extnValue node (OCTET STRING) of a certificate extension by OID. */
function getExtensionValue(raw, targetOid) {
  if (!raw) return null;
  try {
    const asn1 = forge.asn1.fromDer(Buffer.from(raw).toString('binary'));
    const tbs = asn1.value && asn1.value[0];
    if (!tbs || !tbs.value) return null;
    let extSeq = null;
    for (const node of tbs.value) {
      if (node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 3) {
        extSeq = node.value && node.value[0]; // the Extensions SEQUENCE
        break;
      }
    }
    if (!extSeq || !extSeq.value) return null;
    for (const ext of extSeq.value) {
      if (!ext.value || !ext.value[0]) continue;
      const oid = forge.asn1.derToOid(ext.value[0].value);
      if (oid === targetOid) return ext.value[ext.value.length - 1];
    }
    return null;
  } catch {
    return null;
  }
}

function parseInfoAccess(infoAccess) {
  const out = { ocsp: null, ca_issuers: null };
  if (infoAccess && typeof infoAccess === 'object') {
    if (Array.isArray(infoAccess['OCSP - URI']) && infoAccess['OCSP - URI'].length) out.ocsp = infoAccess['OCSP - URI'][0];
    if (Array.isArray(infoAccess['CA Issuers - URI']) && infoAccess['CA Issuers - URI'].length) out.ca_issuers = infoAccess['CA Issuers - URI'][0];
  }
  return out;
}

function certPolicyOids(raw) {
  const ext = getExtensionValue(raw, '2.5.29.32');
  if (!ext || !ext.value) return [];
  try {
    const seq = forge.asn1.fromDer(ext.value);
    const oids = [];
    if (seq.value) {
      for (const pi of seq.value) {
        if (pi.value && pi.value[0]) oids.push(forge.asn1.derToOid(pi.value[0].value));
      }
    }
    return oids;
  } catch {
    return [];
  }
}

function certType(c, dns) {
  const oids = certPolicyOids(c.raw);
  let validation = 'Domain Validation';
  if (oids.includes('1.3.6.1.4.1.311.60.1.1')) validation = 'Extended Validation';
  else if (oids.includes('2.23.140.1.2.2')) validation = 'Organization Validation';
  else if (oids.includes('2.23.140.1.2.1')) validation = 'Domain Validation';

  const list = dns || [];
  const hasWildcard = list.some((d) => d.startsWith('*.'));
  const kind = hasWildcard ? 'Wildcard' : (list.length > 1 ? 'Multi-Domain' : 'Single Domain');
  return `${validation} (${kind})`;
}

function nameMatches(host, cert) {
  if (!host || !cert) return false;
  const h = String(host).toLowerCase();
  const names = [];
  const cn = cert.subject && cert.subject.CN;
  if (cn) names.push(String(cn).toLowerCase());
  for (const d of (cert.san && cert.san.dns) || []) names.push(String(d).toLowerCase());
  if (((cert.san && cert.san.ip) || []).some((ip) => String(ip).toLowerCase() === h)) return true;
  return names.some((name) => {
    if (name === h) return true;
    if (name.startsWith('*.')) {
      const suffix = name.slice(1);
      if (!h.endsWith(suffix)) return false;
      const prefix = h.slice(0, h.length - suffix.length);
      return prefix.length > 0 && !prefix.includes('.');
    }
    return false;
  });
}

function certToDict(c) {
  const now = Date.now();
  const validFrom = c.valid_from ? Date.parse(c.valid_from) : NaN;
  const validTo = c.valid_to ? Date.parse(c.valid_to) : NaN;
  const daysLeft = Number.isFinite(validTo) ? Math.floor((validTo - now) / DAY_MS) : null;
  const totalDays = Number.isFinite(validFrom) && Number.isFinite(validTo) ? Math.floor((validTo - validFrom) / DAY_MS) : null;
  const san = parseSan(c.subjectaltname);
  const ia = parseInfoAccess(c.infoAccess);

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
    validity_days_total: totalDays,
    validity_status: status,
    san,
    cert_type: certType(c, san.dns),
    ocsp_url: ia.ocsp,
    ca_issuers_url: ia.ca_issuers,
    public_key: keyInfo(c),
    fingerprint_sha256: (c.fingerprint256 || '').replace(/:/g, '').toLowerCase(),
    pem: derToPem(c.raw),
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
    name_matches: certs[0] ? nameMatches(host, certs[0]) : false,
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

function httpPost(url, body, contentType, timeout) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      host: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method: 'POST',
      headers: { 'Content-Type': contentType, 'Content-Length': body.length },
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(timeout, () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function parseOcspResponse(respBuf) {
  try {
    const resp = forge.asn1.fromDer(respBuf.toString('binary'));
    const status = resp.value[0].value.charCodeAt(0);
    if (status !== 0) return { status: 'error', detail: `responder status ${status}` };
    const respBytes = resp.value[1];
    if (!respBytes || !respBytes.value || !respBytes.value[0]) return { status: 'error', detail: 'empty response' };
    const inner = respBytes.value[0];
    const responseOctet = inner.value[1];
    const basic = forge.asn1.fromDer(responseOctet.value);
    const tbsData = basic.value[0];
    for (const node of tbsData.value) {
      if (node.tagClass === forge.asn1.Class.UNIVERSAL && node.type === forge.asn1.Type.SEQUENCE) {
        const single = node.value[0];
        if (!single || !single.value || !single.value[1]) break;
        const certStatus = single.value[1];
        if (certStatus.type === 0) return { status: 'good', detail: '' };
        if (certStatus.type === 1) {
          let reason = '';
          try { reason = certStatus.value && certStatus.value[0] ? certStatus.value[0].value.charCodeAt(0) : ''; } catch { /* ignore */ }
          return { status: 'revoked', detail: `reason ${reason}` };
        }
        if (certStatus.type === 2) return { status: 'unknown', detail: '' };
        break;
      }
    }
    return { status: 'unknown', detail: 'no status found' };
  } catch (e) {
    return { status: 'error', detail: e.message };
  }
}

/** Query the leaf cert's OCSP responder for its revocation status. */
function checkOcsp(leaf, issuer) {
  return new Promise((resolve) => {
    if (!leaf || !issuer || !leaf.ocsp_url || !leaf.pem || !issuer.pem) {
      return resolve({ status: 'unknown', detail: 'no OCSP URL or issuer certificate' });
    }
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    try {
      const req = ocsp.request.generate(leaf.pem, issuer.pem);
      httpPost(leaf.ocsp_url, req.data, 'application/ocsp-request', 4000)
        .then(({ status, body }) => {
          if (status !== 200) return finish({ status: 'error', detail: `HTTP ${status}` });
          finish(parseOcspResponse(body));
        })
        .catch((err) => finish({ status: 'error', detail: err.message }));
    } catch (err) {
      finish({ status: 'error', detail: err.message });
    }
    setTimeout(() => finish({ status: 'error', detail: 'timeout' }), 5000);
  });
}

const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

function testTlsVersion(host, port, version, timeout) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host, port, servername: host,
      minVersion: version, maxVersion: version,
      rejectUnauthorized: false, timeout,
    });
    let done = false;
    socket.once('secureConnect', () => { done = true; socket.destroy(); resolve(version); });
    socket.once('error', () => { if (!done) { done = true; socket.destroy(); resolve(null); } });
    socket.once('timeout', () => { if (!done) { done = true; socket.destroy(); resolve(null); } });
  });
}

async function checkTlsVersions(host, port) {
  const results = await Promise.all(TLS_VERSIONS.map((v) => testTlsVersion(host, port, v, 2500)));
  return results.filter(Boolean);
}

/** Query DNS CAA records for the host. */
async function checkCaa(host) {
  try {
    const records = await dns.resolve(host, 'CAA');
    const list = records.map((r) => (typeof r === 'string' ? r : r.value || JSON.stringify(r)));
    const issue = [];
    const issuewild = [];
    const iodef = [];
    for (const rec of records) {
      const val = typeof rec === 'string' ? rec : rec.value || '';
      const m = val.match(/^(?:\d+\s+)?(issue|issuewild|iodef)\s+(.+)$/i);
      if (m) {
        const bucket = m[1].toLowerCase() === 'issue' ? issue : m[1].toLowerCase() === 'issuewild' ? issuewild : iodef;
        bucket.push(m[2].trim());
      }
    }
    return { found: records.length > 0, records: list, issue, issuewild, iodef };
  } catch (err) {
    return { found: false, records: [], issue: [], issuewild: [], iodef: [], error: err.code || err.message };
  }
}

/**
 * Inspect the SSL/TLS state of `host:port` and return a full report.
 * @param {string} host
 * @param {number} port
 * @param {number} [timeout=8000] timeout in ms
 */
async function checkSSL(host, port, timeout = 8000) {
  const started = Date.now();
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

  let result;
  try {
    const data = await connect(host, port, timeout, true);
    result = { ...base, ...data, verified: true };
  } catch (err) {
    if (isCertError(err)) {
      try {
        const data = await connect(host, port, timeout, false);
        result = { ...base, ...data, verified: false, verify_error: certErrorText(err) };
      } catch (err2) {
        result = { ...base, error: friendlyError(err2, timeout) };
      }
    } else {
      result = { ...base, error: friendlyError(err, timeout) };
    }
  }

  // Additional network probes (revocation / TLS versions / CAA) — only when a
  // TLS handshake completed and we have a leaf certificate.
  if (result.connected && result.tls_negotiated && result.certificate) {
    const leaf = result.certificate;
    const issuer = result.certificates && result.certificates[1];
    const [ocspR, tlsR, caaR] = await Promise.allSettled([
      checkOcsp(leaf, issuer),
      checkTlsVersions(host, port),
      checkCaa(host),
    ]);
    result.revocation = ocspR.status === 'fulfilled' ? ocspR.value : { status: 'error', detail: 'ocsp probe failed' };
    result.supported_tls_versions = tlsR.status === 'fulfilled' ? tlsR.value : [];
    result.caa = caaR.status === 'fulfilled' ? caaR.value : { found: false };
  }

  result.duration_ms = Date.now() - started;
  return result;
}

module.exports = { checkSSL };
