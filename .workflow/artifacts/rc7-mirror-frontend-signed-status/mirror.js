const state = {
  health: null,
  descriptor: null,
  channel: null,
  payloadIndex: null,
  install: null,
  compatibility: null,
  rollback: null,
  signatures: null,
  signed: null,
  revocations: null
};

const endpoints = {
  health: "/health.json",
  descriptor: "/.well-known/aios/mirror.json",
  channel: "/channel/index.json",
  payloadIndex: "/payloads/index.json",
  install: "/install/bootstrap.json",
  compatibility: "/install/compatibility.json",
  rollback: "/install/rollback-baseline.json",
  support: "/support/index.json"
};

function byId(id) {
  return document.getElementById(id);
}

function text(id, value) {
  const node = byId(id);
  if (node) node.textContent = value == null || value === "" ? "-" : String(value);
}

function setPill(id, value, kind) {
  const node = byId(id);
  if (!node) return;
  node.textContent = value;
  node.className = `status-pill ${kind || "neutral"}`;
}

async function getJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

function firstEntry() {
  const entries = state.payloadIndex?.entries || [];
  return entries[0] || {};
}

function shortHash(value) {
  if (!value) return "-";
  return String(value).slice(0, 12);
}

function boolWord(value) {
  return value ? "true" : "false";
}

async function loadData() {
  const base = await Promise.allSettled(Object.entries(endpoints).map(async ([key, path]) => [key, await getJson(path)]));
  base.forEach((item) => {
    if (item.status === "fulfilled") {
      state[item.value[0]] = item.value[1];
    }
  });

  const entry = firstEntry();
  const extra = {
    signatures: entry.signatures_path,
    signed: entry.signed_metadata_path,
    revocations: entry.revocations_path
  };

  const details = await Promise.allSettled(Object.entries(extra).filter(([, path]) => path).map(async ([key, path]) => [key, await getJson(path)]));
  details.forEach((item) => {
    if (item.status === "fulfilled") {
      state[item.value[0]] = item.value[1];
    }
  });
}

function renderSummary() {
  const entry = firstEntry();
  const install = state.install || {};
  const signed = state.signed || {};
  const signatures = state.signatures || {};
  const revocations = state.revocations || {};

  setPill("status-service", state.health ? "online" : "metadata unavailable", state.health ? "ok" : "bad");
  setPill("status-ga", state.channel?.production_ready_claim ? "GA claim" : "non-GA", state.channel?.production_ready_claim ? "bad" : "caution");
  setPill("status-install", install.install_allowed ? "install allowed" : "install blocked", install.install_allowed ? "bad" : "caution");

  text("metric-release", entry.release_id || install.default_release_id);
  text("metric-payload-status", entry.status || state.payloadIndex?.status);
  text("metric-signed", signed.public_signature_projection_available || signatures.public_signature_projection_available ? "projected" : "missing");
  text("metric-signed-detail", `crypto=${boolWord(signatures.cryptographic_signature_present)} signature=${boolWord(signatures.signature_available)}`);
  text("metric-revocation", revocations.revocation_status || "unknown");
  text("metric-revocation-detail", shortHash(signatures.revocation_snapshot_sha256 || entry.revocation_snapshot_sha256));
  text("metric-install", install.current_state || "verification-blocked");
  text("metric-blockers", `${(install.blockers || []).length} blockers`);
}

function addCheck(list, label, detail, kind) {
  const li = document.createElement("li");
  li.className = kind || "";
  li.innerHTML = `<div><strong>${label}</strong><span>${detail}</span></div>`;
  list.appendChild(li);
}

function renderChecks() {
  const list = byId("checks-list");
  if (!list) return;
  list.innerHTML = "";
  const entry = firstEntry();
  const install = state.install || {};
  const signatures = state.signatures || {};
  const compatibility = state.compatibility || {};
  const rollback = state.rollback || {};

  addCheck(list, "Signed metadata reference", entry.signed_metadata_sha256 ? shortHash(entry.signed_metadata_sha256) : "missing", entry.signed_metadata_sha256 ? "" : "block");
  addCheck(list, "Revocation snapshot", entry.revocation_snapshot_sha256 ? shortHash(entry.revocation_snapshot_sha256) : "missing", entry.revocation_snapshot_sha256 ? "" : "block");
  addCheck(list, "Compatibility metadata", compatibility.schema || "missing", compatibility.schema ? "" : "block");
  addCheck(list, "Rollback baseline", rollback.rollback_baseline_sha256 ? shortHash(rollback.rollback_baseline_sha256) : "missing", rollback.rollback_baseline_sha256 ? "" : "block");
  addCheck(list, "Cryptographic signature", signatures.cryptographic_signature_present ? "present" : "not present", signatures.cryptographic_signature_present ? "" : "block");
  addCheck(list, "Install authority", install.install_allowed ? "allowed" : "blocked", install.install_allowed ? "block" : "warn");
  addCheck(list, "TLS GA gate", install.tls_required_before_ga_claim ? "required before GA" : "not required", install.tls_required_before_ga_claim ? "warn" : "");
  text("checks-count", `${list.children.length} gates`);
}

function renderDirectory() {
  const body = byId("directory-body");
  if (!body) return;
  const entry = firstEntry();
  const rows = [
    ["/channel/index.json", "channel", state.channel?.status, "read-only"],
    ["/payloads/index.json", "payload index", state.payloadIndex?.status, "metadata-only"],
    [entry.signatures_path, "signatures", state.signatures?.status, "projection"],
    [entry.signed_metadata_path, "signed metadata", state.signed?.status, "projection"],
    [entry.revocations_path, "revocations", state.revocations?.status, "not-revoked"],
    ["/install/bootstrap.json", "install", state.install?.current_state, "preflight-only"],
    ["/install/compatibility.json", "compatibility", state.compatibility?.status, "published"],
    ["/install/rollback-baseline.json", "rollback", state.rollback?.status, "execution-blocked"],
    ["/support/index.json", "support", state.support?.status, "redacted"]
  ].filter((row) => row[0]);

  body.innerHTML = rows.map(([path, type, status, policy]) => `
    <tr>
      <td><a href="${path}">${path}</a></td>
      <td>${type || "-"}</td>
      <td>${status || "-"}</td>
      <td>${policy || "-"}</td>
    </tr>
  `).join("");
  text("directory-count", `${rows.length} entries`);
}

function renderHashes() {
  const entry = firstEntry();
  const install = state.install || {};
  const channel = state.channel || {};
  const pairs = [
    ["payload index", channel.payload_channel?.payload_index_sha256 || install.projection?.payload_index_sha256],
    ["payload signatures", entry.signatures_sha256 || install.projection?.payload_signatures_sha256],
    ["signed metadata", entry.signed_metadata_sha256 || install.projection?.signed_metadata_sha256],
    ["revocation", entry.revocation_snapshot_sha256 || install.projection?.revocation_snapshot_sha256],
    ["compatibility", entry.compatibility_sha256 || install.projection?.installer_compatibility_sha256],
    ["rollback baseline", entry.rollback_baseline_sha256 || install.projection?.rollback_baseline_sha256],
    ["channel", channel.payload_channel?.install_bootstrap_sha256]
  ].filter(([, value]) => value);

  const list = byId("hash-list");
  if (!list) return;
  list.innerHTML = pairs.map(([key, value]) => `<dt>${key}</dt><dd>${value}</dd>`).join("");
  text("hash-count", `${pairs.length} hashes`);
}

function drawSigil() {
  const canvas = byId("brand-sigil");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#f9fbf6";
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = "#2f6f78";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.moveTo(10, 30);
  ctx.lineTo(22, 9);
  ctx.lineTo(34, 30);
  ctx.closePath();
  ctx.stroke();
  ctx.fillStyle = "#20794f";
  ctx.fillRect(14, 29, 16, 4);
}

function drawTrustMap() {
  const canvas = byId("trust-map");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#fbfcf8";
  ctx.fillRect(0, 0, w, h);

  const nodes = [
    ["Mirror", "transport", 120, 128, "#2f6f78"],
    ["Signed metadata", "projected", 330, 92, "#315f9d"],
    ["Revocation", state.revocations?.revocation_status || "unknown", 550, 128, "#20794f"],
    ["Install gates", state.install?.current_state || "blocked", 760, 92, "#ad6a19"],
    ["Execution", "not authorized", 860, 235, "#a33a31"]
  ];

  ctx.lineWidth = 3;
  ctx.strokeStyle = "#c7d2ca";
  ctx.beginPath();
  ctx.moveTo(120, 128);
  ctx.bezierCurveTo(250, 60, 430, 60, 550, 128);
  ctx.bezierCurveTo(650, 188, 720, 120, 760, 92);
  ctx.bezierCurveTo(800, 150, 830, 195, 860, 235);
  ctx.stroke();

  nodes.forEach(([title, caption, x, y, color]) => {
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, 28, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = "#ffffff";
    ctx.font = "700 16px system-ui";
    ctx.textAlign = "center";
    ctx.fillText(title.slice(0, 2).toUpperCase(), x, y + 6);
    ctx.fillStyle = "#17211d";
    ctx.font = "700 15px system-ui";
    ctx.fillText(title, x, y + 52);
    ctx.fillStyle = "#61716a";
    ctx.font = "13px system-ui";
    ctx.fillText(caption, x, y + 72);
  });
}

function render() {
  renderSummary();
  renderChecks();
  renderDirectory();
  renderHashes();
  drawSigil();
  drawTrustMap();
}

loadData()
  .then(render)
  .catch((error) => {
    setPill("status-service", "metadata error", "bad");
    text("metric-release", error.message);
    drawSigil();
    drawTrustMap();
  });
