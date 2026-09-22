"use strict";

const form = document.getElementById("checkForm");
const hostInput = document.getElementById("host");
const portInput = document.getElementById("port");
const btn = document.getElementById("checkBtn");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function splitHostPort(raw) {
  const s = raw.trim().replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "").split("/")[0];
  // IPv6 literal in brackets
  const ipv6 = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (ipv6) return { host: ipv6[1], port: ipv6[2] ? Number(ipv6[2]) : null };
  const parts = s.split(":");
  if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    return { host: parts[0], port: Number(parts[1]) };
  }
  return { host: s, port: null };
}

function showStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = "status " + cls;
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function validityBadge(status) {
  const labels = {
    valid: "Valid",
    expiring_soon: "Expiring soon",
    expired: "Expired",
    not_yet_valid: "Not yet valid",
  };
  return `<span class="badge ${esc(status)}">${esc(labels[status] || status)}</span>`;
}

function renderTlsCard(r) {
  const rows = [
    ["TLS version", r.tls_version],
    ["Cipher suite", r.cipher ? r.cipher.name : null],
    ["Cipher bits", r.cipher ? r.cipher.bits : null],
    ["Server IP", r.ip_address],
  ];
  return `
    <div class="card">
      <h2>Connection</h2>
      <div class="grid">
        ${rows.map(([k, v]) => v == null ? "" : `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("")}
      </div>
    </div>`;
}

function renderCertCard(c) {
  const cn = c.subject.CN || Object.values(c.subject)[0] || "(no CN)";
  const sans = [...(c.san.dns || []), ...(c.san.ip || [])];
  const key = c.public_key.curve
    ? `${c.public_key.algorithm} ${c.public_key.curve} (${c.public_key.bits} bits)`
    : `${c.public_key.algorithm} (${c.public_key.bits} bits)`;
  const rows = [
    ["Subject", cn],
    ["Issuer", c.issuer.CN || Object.values(c.issuer)[0] || "—"],
    ["Serial number", c.serial_number],
    ["Signature algorithm", c.signature_algorithm],
    ["Public key", key],
    ["SHA-256 fingerprint", c.fingerprint_sha256],
  ];
  return `
    <div class="card">
      <h2>Certificate</h2>
      <div class="grid">
        ${rows.map(([k, v]) => `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("")}
      </div>
      <div style="margin-top:14px">
        <div class="k" style="color:var(--muted);font-size:.8rem">Subject Alternative Names (SANs)</div>
        <div class="tags" style="margin-top:6px">
          ${sans.length ? sans.map((s) => `<span class="tag">${esc(s)}</span>`).join("") : `<span class="tag" style="color:var(--muted)">none</span>`}
        </div>
      </div>
    </div>`;
}

function renderValidityCard(c) {
  const rows = [
    ["Not before", fmtDate(c.not_before)],
    ["Not after", fmtDate(c.not_after)],
    ["Days remaining", c.days_remaining],
    ["Status", validityBadge(c.validity_status)],
  ];
  return `
    <div class="card">
      <h2>Validity</h2>
      <div class="grid">
        ${rows.map(([k, v]) => `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`).join("")}
      </div>
    </div>`;
}

function renderChainCard(certs) {
  const items = certs.map((c, i) => {
    const cn = c.subject.CN || Object.values(c.subject)[0] || "(no CN)";
    return `
      <div class="chain-item">
        <div class="cn">${i + 1}. ${esc(cn)}</div>
        <div class="meta">${validityBadge(c.validity_status)} · ${c.days_remaining}d</div>
      </div>`;
  }).join("");
  return `
    <div class="card">
      <h2>Certificate chain (${certs.length})</h2>
      ${items}
    </div>`;
}

function render(r) {
  resultsEl.innerHTML = "";

  if (r.error) {
    showStatus("✗ " + r.error, "err");
    return;
  }

  if (!r.tls_negotiated) {
    showStatus("Connected, but no TLS handshake completed (is this port even TLS?).", "warn");
    return;
  }

  // Verification banner
  if (r.verified) {
    showStatus("✓ TLS handshake succeeded and the certificate chain is trusted.", "ok");
  } else {
    showStatus("⚠ Certificate chain could NOT be verified: " + (r.verify_error || "unknown"), "warn");
  }

  const frag = document.createDocumentFragment();
  const tls = document.createElement("div");
  tls.innerHTML = renderTlsCard(r);
  frag.appendChild(tls.firstElementChild);

  const cert = document.createElement("div");
  cert.innerHTML = renderCertCard(r.certificate);
  frag.appendChild(cert.firstElementChild);

  const val = document.createElement("div");
  val.innerHTML = renderValidityCard(r.certificate);
  frag.appendChild(val.firstElementChild);

  if (r.certificates && r.certificates.length) {
    const chain = document.createElement("div");
    chain.innerHTML = renderChainCard(r.certificates);
    frag.appendChild(chain.firstElementChild);
  }

  resultsEl.appendChild(frag);
}

async function runCheck() {
  const { host, port } = splitHostPort(hostInput.value);
  if (!host) { showStatus("✗ Please enter a host.", "err"); return; }

  btn.disabled = true;
  showStatus("Checking " + host + ":" + (port || 443) + " …", "");
  resultsEl.innerHTML = "";

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
    showStatus("✗ " + e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runCheck();
});

// Quick-try links
document.querySelectorAll("[data-try]").forEach((a) => {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    const { host, port } = splitHostPort(a.dataset.try);
    hostInput.value = host;
    portInput.value = port || 443;
    runCheck();
  });
});
