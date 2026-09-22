"use strict";

const form = document.getElementById("checkForm");
const hostInput = document.getElementById("host");
const portInput = document.getElementById("port");
const btn = document.getElementById("checkBtn");
const resultsEl = document.getElementById("results");

const challengeModal = document.getElementById("challengeModal");
const challengeQuestionEl = document.getElementById("challengeQuestion");
const challengeAnswerEl = document.getElementById("challengeAnswer");
const challengeErrorEl = document.getElementById("challengeError");
const challengeSubmitBtn = document.getElementById("challengeSubmit");
const challengeCancelBtn = document.getElementById("challengeCancel");

let pendingChallenge = null;
let currentChain = [];

const ICONS = {
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>',
  err: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6"/><path d="M9 9l6 6"/></svg>',
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function splitHostPort(raw) {
  const s = raw.trim().replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "").split("/")[0];
  const ipv6 = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (ipv6) return { host: ipv6[1], port: ipv6[2] ? Number(ipv6[2]) : null };
  const parts = s.split(":");
  if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    return { host: parts[0], port: Number(parts[1]) };
  }
  return { host: s, port: null };
}

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function validityBadge(status) {
  const labels = { valid: "Valid", expiring_soon: "Expiring soon", expired: "Expired", not_yet_valid: "Not yet valid" };
  return `<span class="badge ${esc(status)}">${esc(labels[status] || status)}</span>`;
}

function daysText(d) {
  if (d == null) return "—";
  if (d < 0) return `${Math.abs(d)}d overdue`;
  return `${d}d left`;
}

function barState(status) {
  if (status === "valid") return "ok";
  if (status === "expiring_soon") return "warn";
  return "bad";
}

function renderVerdict(kind, title, facts, detail) {
  return `
    <div class="verdict verdict-${kind}">
      <div class="verdict-icon">${ICONS[kind]}</div>
      <div class="verdict-body">
        <div class="verdict-title">${esc(title)}</div>
        ${facts ? `<div class="verdict-facts">${facts}</div>` : ""}
        ${detail ? `<div class="verdict-detail">${esc(detail)}</div>` : ""}
      </div>
    </div>`;
}

function renderCertCard(c) {
  const cn = c.subject.CN || Object.values(c.subject)[0] || "(no CN)";
  const issuer = c.issuer.CN || Object.values(c.issuer)[0] || "—";
  const key = c.public_key.curve
    ? `${c.public_key.algorithm} ${c.public_key.curve} · ${c.public_key.bits} bits`
    : `${c.public_key.algorithm} · ${c.public_key.bits} bits`;
  const sans = [...(c.san.dns || []), ...(c.san.ip || [])];

  return `
    <section class="card">
      <div class="cert-subject">${esc(cn)}</div>
      <div class="cert-issuer">issued by <b>${esc(issuer)}</b></div>

      <div class="kv-grid">
        <div class="kv"><div class="k">Serial number</div><div class="v">${esc(c.serial_number)}</div></div>
        <div class="kv"><div class="k">Signature algorithm</div><div class="v">${esc(c.signature_algorithm || "—")}</div></div>
        <div class="kv"><div class="k">Public key</div><div class="v">${esc(key)}</div></div>
        <div class="kv"><div class="k">SHA-256 fingerprint</div><div class="v">${esc(c.fingerprint_sha256)}</div></div>
      </div>

      ${sans.length ? `
      <div class="san-block">
        <div class="san-label">Subject Alternative Names</div>
        <div class="san-tags">${sans.map((s) => `<span class="san-tag">${esc(s)}</span>`).join("")}</div>
      </div>` : ""}
    </section>`;
}

function renderValidity(c) {
  const nb = new Date(c.not_before);
  const na = new Date(c.not_after);
  const total = (na - nb) / 86400000;
  const pct = total > 0 ? Math.max(0, Math.min(100, (c.days_remaining / total) * 100)) : 0;
  const state = barState(c.validity_status);

  return `
    <section class="card">
      <div class="card-head">
        <span class="card-title">Validity</span>
        ${validityBadge(c.validity_status)}
      </div>
      <div class="bar"><div class="bar-fill ${state}" style="width:${pct}%"></div></div>
      <div class="validity-meta">
        <span class="validity-dates">${fmtDate(c.not_before)} → ${fmtDate(c.not_after)}</span>
        <span class="validity-days">${esc(daysText(c.days_remaining))}</span>
      </div>
    </section>`;
}

function fmtDateHuman(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" });
}

function chainRole(i, len) {
  if (len === 1) return "Certificate";
  if (i === 0) return "Server certificate";
  if (i === len - 1) return "Root CA";
  return "Intermediate CA";
}

function toggleChain(idx, btn) {
  const details = document.getElementById(`chain-details-${idx}`);
  if (!details) return;
  if (details.classList.contains("hidden")) {
    details.classList.remove("hidden");
    btn.setAttribute("aria-expanded", "true");
  } else {
    details.classList.add("hidden");
    btn.setAttribute("aria-expanded", "false");
  }
}

function renderChain(certs) {
  currentChain = certs;
  const items = certs.map((c, i) => {
    const cn = c.subject.CN || Object.values(c.subject)[0] || "(no CN)";
    const org = c.subject.O || "—";
    const issuer = c.issuer.CN || Object.values(c.issuer)[0] || "—";
    const valid = `${fmtDateHuman(c.not_before)} — ${fmtDateHuman(c.not_after)}`;
    const role = chainRole(i, certs.length);

    return `
      <li class="chain-node">
        <div class="chain-rail"><span class="chain-dot ${esc(c.validity_status)}"></span></div>
        <div class="chain-body chain-card">
          <div class="chain-head">
            <button type="button" class="chain-head-main" data-chain-toggle="${i}" aria-expanded="false">
              <span class="chain-chevron" aria-hidden="true">▸</span>
              <span class="chain-head-title">
                <span class="chain-role">${esc(role)}</span>
                <span class="chain-cn">${esc(cn)}</span>
              </span>
            </button>
            <button type="button" class="chain-download" data-download="${i}" title="Download as .pem">Download .pem</button>
          </div>
          <div class="chain-details hidden" id="chain-details-${i}">
            <div class="chain-kv">
              <div class="kv"><div class="k">Common Name</div><div class="v">${esc(cn)}</div></div>
              <div class="kv"><div class="k">Organization</div><div class="v">${esc(org)}</div></div>
              <div class="kv"><div class="k">Valid</div><div class="v">${esc(valid)}</div></div>
              <div class="kv"><div class="k">Issuer</div><div class="v">${esc(issuer)}</div></div>
            </div>
            <button type="button" class="chain-pem-toggle" data-pem-toggle="${i}">View / copy PEM</button>
            <div class="chain-pem hidden" id="pem-${i}">
              <textarea readonly spellcheck="false"></textarea>
              <div class="chain-pem-bar">
                <button type="button" class="chain-pem-copy" data-copy="${i}">Copy</button>
              </div>
            </div>
          </div>
        </div>
      </li>`;
  }).join("");

  return `
    <section class="card">
      <div class="card-head">
        <span class="card-title">Certificate chain</span>
        <span class="chain-count">${certs.length} cert${certs.length === 1 ? "" : "s"}</span>
      </div>
      <p class="chain-desc">Click a certificate to expand its details, then view/copy the PEM or download it.</p>
      <ul class="chain">${items}</ul>
    </section>`;
}

function downloadPem(cert) {
  if (!cert || !cert.pem) return;
  const cn = (cert.subject.CN || "certificate").replace(/[^\w.-]+/g, "_");
  const blob = new Blob([cert.pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${cn}.pem`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function togglePem(idx, btn) {
  const box = document.getElementById(`pem-${idx}`);
  if (!box) return;
  if (box.classList.contains("hidden")) {
    const ta = box.querySelector("textarea");
    if (ta && !ta.value && currentChain[idx]) ta.value = currentChain[idx].pem || "";
    box.classList.remove("hidden");
    btn.textContent = "Hide PEM";
  } else {
    box.classList.add("hidden");
    btn.textContent = "View / copy PEM";
  }
}

async function copyPem(pem, btn) {
  try {
    await navigator.clipboard.writeText(pem);
  } catch {
    const box = btn.closest(".chain-pem");
    const ta = box && box.querySelector("textarea");
    if (ta) { ta.focus(); ta.select(); return; }
  }
  const old = btn.textContent;
  btn.textContent = "Copied!";
  setTimeout(() => { btn.textContent = old; }, 1500);
}

function renderSummary(r) {
  const dur = r.duration_ms != null ? `${(r.duration_ms / 1000).toFixed(2)}s` : "";
  const parts = [
    `<span class="summary-host">${esc(r.host)}:${esc(r.port)}</span>`,
    r.ip_address ? `<span class="summary-item">IP ${esc(r.ip_address)}</span>` : "",
    dur ? `<span class="summary-item">${esc(dur)}</span>` : "",
  ].filter(Boolean);
  return `<div class="summary">${parts.join('<span class="summary-sep">·</span>')}</div>`;
}

function revocationText(rev) {
  if (!rev) return "—";
  switch (rev.status) {
    case "good": return "Good (not revoked)";
    case "revoked": return `Revoked${rev.detail ? ` (${rev.detail})` : ""}`;
    case "unknown": return "Unknown";
    default: return "Could not check";
  }
}

function tlsVersionsText(versions) {
  return versions && versions.length ? versions.join(", ") : "—";
}

function caaText(caa) {
  if (!caa) return "—";
  if (!caa.found) return caa.error ? `No records (${caa.error})` : "No CAA records";
  const parts = [];
  if (caa.issue && caa.issue.length) parts.push("issue: " + caa.issue.join(", "));
  if (caa.issuewild && caa.issuewild.length) parts.push("issuewild: " + caa.issuewild.join(", "));
  return parts.join(" · ") || "Yes";
}

function renderDetails(cert, r) {
  const issuerFull = cert.issuer
    ? [cert.issuer.O, cert.issuer.C].filter(Boolean).join(', ') || cert.issuer.CN || "—"
    : "—";
  const rows = [
    ["Name Matches Domain", r.name_matches ? "Yes" : "No"],
    ["Certificate Type", cert.cert_type || "—"],
    ["Validity Period", cert.validity_days_total != null ? `${cert.validity_days_total} days` : "—"],
    ["Issuer", issuerFull],
    ["OCSP/CRL Revocation", revocationText(r.revocation)],
    ["Supported TLS Versions", tlsVersionsText(r.supported_tls_versions)],
    ["DNS CAA", caaText(r.caa)],
    ["OCSP", cert.ocsp_url || "—"],
    ["CA Issuers", cert.ca_issuers_url || "—"],
  ];
  return `
    <section class="card">
      <div class="card-head"><span class="card-title">Certificate details</span></div>
      <div class="kv-grid">
        ${rows.map(([k, v]) => `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("")}
      </div>
    </section>`;
}

function render(r) {
  resultsEl.innerHTML = "";

  // Network / connection errors
  if (r.error) {
    resultsEl.innerHTML = renderVerdict("err", "Connection failed", null, r.error);
    return;
  }
  if (!r.tls_negotiated) {
    resultsEl.innerHTML = renderVerdict("warn", "No TLS handshake", null,
      "Connected, but the server did not complete a TLS handshake (is this port even TLS?).");
    return;
  }

  const cert = r.certificate;
  const cipherBits = r.cipher && r.cipher.bits ? ` · ${r.cipher.bits} bits` : "";
  const facts = [
    `<span>${esc(r.tls_version || "—")}</span>`,
    r.cipher ? `<span>${esc(r.cipher.name)}${cipherBits}</span>` : "",
    `<span>${esc(r.ip_address || "")}</span>`,
  ].filter(Boolean).join('<span class="sep">·</span>');

  let verdict;
  if (r.verified) {
    verdict = renderVerdict("ok", "Certificate is trusted", facts, null);
  } else {
    verdict = renderVerdict("warn", "Certificate is NOT trusted", facts, r.verify_error || "unknown reason");
  }

  const certCard = renderCertCard(cert);
  const detailsCard = renderDetails(cert, r);
  const validityCard = renderValidity(cert);
  const chainCard = r.certificates && r.certificates.length ? renderChain(r.certificates) : "";

  resultsEl.innerHTML = renderSummary(r) + verdict + certCard + detailsCard + validityCard + chainCard;
}

async function runCheck(token) {
  const { host, port } = splitHostPort(hostInput.value);
  if (!host) {
    resultsEl.innerHTML = renderVerdict("err", "Missing host", null, "Enter a host to check.");
    return;
  }

  btn.classList.add("loading");
  btn.disabled = true;

  try {
    const body = { host, port: port || 443 };
    if (token) body.token = token;
    const resp = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (resp.status === 429 && data.challenge) {
      showChallenge(data.challenge);
      return;
    }
    if (!resp.ok) throw new Error(data.detail || resp.statusText);
    render(data);
  } catch (e) {
    resultsEl.innerHTML = renderVerdict("err", "Request failed", null, e.message);
  } finally {
    btn.classList.remove("loading");
    btn.disabled = false;
  }
}

function showChallenge(challenge) {
  pendingChallenge = challenge;
  challengeQuestionEl.textContent = challenge.question;
  challengeAnswerEl.value = "";
  challengeErrorEl.classList.add("hidden");
  challengeModal.classList.remove("hidden");
  challengeAnswerEl.focus();
}

function hideChallenge() {
  challengeModal.classList.add("hidden");
  pendingChallenge = null;
}

async function submitChallenge() {
  if (!pendingChallenge) return;
  const answer = challengeAnswerEl.value.trim();
  if (!answer) {
    challengeErrorEl.textContent = "Please enter an answer.";
    challengeErrorEl.classList.remove("hidden");
    return;
  }

  challengeSubmitBtn.disabled = true;
  try {
    const resp = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: pendingChallenge.id, answer }),
    });
    const data = await resp.json();
    if (resp.ok && data.ok) {
      hideChallenge();
      runCheck(data.token); // retry the original check with the single-use token
    } else {
      challengeErrorEl.textContent = data.detail || "Wrong answer.";
      challengeErrorEl.classList.remove("hidden");
      if (data.challenge) {
        pendingChallenge = data.challenge;
        challengeQuestionEl.textContent = data.challenge.question;
        challengeAnswerEl.value = "";
      }
    }
  } catch (e) {
    challengeErrorEl.textContent = e.message;
    challengeErrorEl.classList.remove("hidden");
  } finally {
    challengeSubmitBtn.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runCheck();
});

document.querySelectorAll("[data-try]").forEach((a) => {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    const { host, port } = splitHostPort(a.dataset.try);
    hostInput.value = host;
    portInput.value = port || 443;
    runCheck();
  });
});

challengeSubmitBtn.addEventListener("click", submitChallenge);
challengeCancelBtn.addEventListener("click", hideChallenge);
challengeAnswerEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    submitChallenge();
  }
});
document.querySelector("[data-close]").addEventListener("click", hideChallenge);

resultsEl.addEventListener("click", (e) => {
  if (!(e.target instanceof Element)) return;
  const ct = e.target.closest("[data-chain-toggle]");
  if (ct) {
    toggleChain(Number(ct.dataset.chainToggle), ct);
    return;
  }
  const dl = e.target.closest("[data-download]");
  if (dl) {
    const cert = currentChain[Number(dl.dataset.download)];
    if (cert) downloadPem(cert);
    return;
  }
  const tg = e.target.closest("[data-pem-toggle]");
  if (tg) {
    togglePem(Number(tg.dataset.pemToggle), tg);
    return;
  }
  const cp = e.target.closest("[data-copy]");
  if (cp) {
    const cert = currentChain[Number(cp.dataset.copy)];
    if (cert && cert.pem) copyPem(cert.pem, cp);
    return;
  }
});
