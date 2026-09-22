"use strict";

const form = document.getElementById("checkForm");
const hostInput = document.getElementById("host");
const portInput = document.getElementById("port");
const btn = document.getElementById("checkBtn");
const resultsEl = document.getElementById("results");

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

function renderChain(certs) {
  const items = certs.map((c) => {
    const cn = c.subject.CN || Object.values(c.subject)[0] || "(no CN)";
    const issuer = c.issuer.CN || Object.values(c.issuer)[0] || "—";
    const issuerLine = cn === issuer ? "self-signed" : `issued by ${esc(issuer)}`;
    return `
      <li class="chain-node">
        <div class="chain-rail"><span class="chain-dot ${esc(c.validity_status)}"></span></div>
        <div class="chain-body">
          <div class="chain-cn">${esc(cn)}</div>
          <div class="chain-issuer">${issuerLine}</div>
        </div>
        <div class="chain-meta">
          ${validityBadge(c.validity_status)}
          <span class="chain-days">${esc(daysText(c.days_remaining))}</span>
        </div>
      </li>`;
  }).join("");

  return `
    <section class="card">
      <div class="card-head">
        <span class="card-title">Certificate chain</span>
        <span class="chain-days">${certs.length} cert${certs.length === 1 ? "" : "s"}</span>
      </div>
      <ul class="chain">${items}</ul>
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
  const validityCard = renderValidity(cert);
  const chainCard = r.certificates && r.certificates.length ? renderChain(r.certificates) : "";

  resultsEl.innerHTML = verdict + certCard + validityCard + chainCard;
}

async function runCheck() {
  const { host, port } = splitHostPort(hostInput.value);
  if (!host) {
    resultsEl.innerHTML = renderVerdict("err", "Missing host", null, "Enter a host to check.");
    return;
  }

  btn.classList.add("loading");
  btn.disabled = true;

  try {
    const resp = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, port: port || 443 }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || resp.statusText);
    render(data);
  } catch (e) {
    resultsEl.innerHTML = renderVerdict("err", "Request failed", null, e.message);
  } finally {
    btn.classList.remove("loading");
    btn.disabled = false;
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
