const state = {};
const endpoints = {
  status: "/.well-known/aios/rc8-mirror-status.json",
  channel: "/channel/index.json",
  payloadIndex: "/payloads/index.json",
  install: "/install/bootstrap.json",
  compatibility: "/install/compatibility.json",
  rollback: "/install/rollback-baseline.json"
};
const byId = (id) => document.getElementById(id);
const text = (id, value) => { const node = byId(id); if (node) node.textContent = value == null || value === "" ? "-" : String(value); };
const setPill = (id, value, kind) => { const node = byId(id); if (node) { node.textContent = value; node.className = `status-pill ${kind || "neutral"}`; } };
async function getJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}
function firstEntry() { return (state.payloadIndex?.entries || [])[0] || {}; }
function shortHash(value) { return value ? String(value).slice(0, 12) : "-"; }
function boolWord(value) { return value ? "true" : "false"; }
async function loadData() {
  const base = await Promise.allSettled(Object.entries(endpoints).map(async ([key, path]) => [key, await getJson(path)]));
  base.forEach((item) => { if (item.status === "fulfilled") state[item.value[0]] = item.value[1]; });
  const entry = firstEntry();
  const detailPaths = {
    descriptor: entry.object_descriptor_path,
    signature: entry.signature_receipt_path,
    signatureSummary: entry.signature_summary_path,
    preflight: entry.installer_preflight_result_path,
    failClosed: entry.installer_fail_closed_result_path
  };
  const details = await Promise.allSettled(Object.entries(detailPaths).filter(([, path]) => path).map(async ([key, path]) => [key, await getJson(path)]));
  details.forEach((item) => { if (item.status === "fulfilled") state[item.value[0]] = item.value[1]; });
}
function renderSummary() {
  const entry = firstEntry();
  const install = state.install || {};
  setPill("status-service", state.status ? "online" : "metadata unavailable", state.status ? "ok" : "bad");
  setPill("status-ga", state.channel?.production_ready_claim ? "GA claim" : "non-GA", state.channel?.production_ready_claim ? "bad" : "caution");
  setPill("status-install", install.install_allowed ? "install allowed" : "install blocked", install.install_allowed ? "bad" : "caution");
  text("metric-release", entry.release_id || install.default_release_id);
  text("metric-state", entry.status || state.status?.status);
  text("metric-object", shortHash(entry.object_sha256 || state.descriptor?.sha256));
  text("metric-size", `${entry.object_size_bytes || state.descriptor?.size_bytes || "-"} bytes`);
  text("metric-signature", entry.crypto_verified ? "verified" : "blocked");
  text("metric-signature-detail", `public=${boolWord(entry.public_signature_ingested)} crypto=${boolWord(entry.crypto_verified)}`);
  text("metric-install", install.current_state || "verification-blocked");
  text("metric-blockers", `${(install.blockers || state.status?.blockers || []).length} blockers`);
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
  addCheck(list, "Immutable object descriptor", entry.object_descriptor_sha256 ? shortHash(entry.object_descriptor_sha256) : "missing", entry.object_descriptor_sha256 ? "" : "block");
  addCheck(list, "Public signature receipt", entry.signature_receipt_sha256 ? shortHash(entry.signature_receipt_sha256) : "missing", entry.signature_receipt_sha256 ? "" : "block");
  addCheck(list, "Signature crypto", entry.crypto_verified ? "verified" : "not verified", entry.crypto_verified ? "" : "block");
  addCheck(list, "Installer VM smoke", state.status?.installer_vm_smoke_completed ? "completed" : "missing", state.status?.installer_vm_smoke_completed ? "" : "block");
  addCheck(list, "Fail-closed fixtures", `${state.status?.fail_closed_cases || 0} cases`, state.status?.fail_closed_failed_cases ? "block" : "");
  addCheck(list, "External object URI", install.external_https_object_uri_published ? "published" : "not published", install.external_https_object_uri_published ? "" : "warn");
  addCheck(list, "Install authority", install.install_allowed ? "allowed" : "blocked", install.install_allowed ? "block" : "warn");
  text("checks-count", `${list.children.length} gates`);
}
function renderDirectory() {
  const body = byId("directory-body");
  if (!body) return;
  const entry = firstEntry();
  const rows = [
    ["/channel/index.json", "channel", state.channel?.status, "metadata-only"],
    ["/payloads/index.json", "payload index", state.payloadIndex?.status, "metadata-only"],
    [entry.object_descriptor_path, "object descriptor", state.descriptor?.descriptor_state, "hash-bound"],
    [entry.signature_receipt_path, "signature receipt", state.signature?.verification_status, "public artifact"],
    [entry.signature_summary_path, "signature summary", state.signatureSummary?.status, "redacted"],
    [entry.installer_preflight_result_path, "installer preflight", state.preflight?.summary?.preflight_state, "preflight-only"],
    [entry.installer_fail_closed_result_path, "fail-closed result", state.failClosed?.status, "negative fixtures"],
    ["/install/bootstrap.json", "install", state.install?.current_state, "blocked"],
    ["/install/compatibility.json", "compatibility", state.compatibility?.status, "published"],
    ["/install/rollback-baseline.json", "rollback", state.rollback?.status, "execution-blocked"]
  ].filter((row) => row[0]);
  body.innerHTML = rows.map(([path, type, status, policy]) => `<tr><td><a href="${path}">${path}</a></td><td>${type || "-"}</td><td>${status || "-"}</td><td>${policy || "-"}</td></tr>`).join("");
  text("directory-count", `${rows.length} entries`);
}
function renderHashes() {
  const entry = firstEntry();
  const pairs = [
    ["payload index", state.channel?.payload_channel?.payload_index_sha256],
    ["install bootstrap", state.channel?.payload_channel?.install_bootstrap_sha256],
    ["object descriptor", entry.object_descriptor_sha256],
    ["signature receipt", entry.signature_receipt_sha256],
    ["installer preflight", entry.installer_preflight_result_sha256],
    ["fail-closed", entry.installer_fail_closed_result_sha256],
    ["revocation", entry.revocation_snapshot_sha256],
    ["compatibility", entry.compatibility_sha256],
    ["rollback", entry.rollback_baseline_sha256]
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
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#f9fbf6"; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "#2f6f78"; ctx.lineWidth = 3; ctx.beginPath(); ctx.moveTo(10, 30); ctx.lineTo(22, 9); ctx.lineTo(34, 30); ctx.closePath(); ctx.stroke();
  ctx.fillStyle = "#20794f"; ctx.fillRect(14, 29, 16, 4);
}
function drawTrustMap() {
  const canvas = byId("trust-map");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const nodes = [
    ["Mirror", "metadata-only", 120, 128, "#2f6f78"],
    ["Object", "hash-bound", 315, 92, "#315f9d"],
    ["Signature", "public verified", 520, 128, "#20794f"],
    ["Preflight", state.install?.current_state || "blocked", 725, 92, "#ad6a19"],
    ["Execution", "not authorized", 860, 235, "#a33a31"]
  ];
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#fbfcf8"; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.lineWidth = 3; ctx.strokeStyle = "#c7d2ca"; ctx.beginPath(); ctx.moveTo(120, 128); ctx.bezierCurveTo(250, 60, 430, 60, 520, 128); ctx.bezierCurveTo(640, 188, 690, 120, 725, 92); ctx.bezierCurveTo(780, 150, 830, 195, 860, 235); ctx.stroke();
  nodes.forEach(([title, caption, x, y, color]) => {
    ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, 28, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#fff"; ctx.font = "700 16px system-ui"; ctx.textAlign = "center"; ctx.fillText(title.slice(0, 2).toUpperCase(), x, y + 6);
    ctx.fillStyle = "#17211d"; ctx.font = "700 15px system-ui"; ctx.fillText(title, x, y + 52);
    ctx.fillStyle = "#61716a"; ctx.font = "13px system-ui"; ctx.fillText(caption, x, y + 72);
  });
}
function render() { renderSummary(); renderChecks(); renderDirectory(); renderHashes(); drawSigil(); drawTrustMap(); }
loadData().then(render).catch((error) => { setPill("status-service", "metadata error", "bad"); text("metric-release", error.message); drawSigil(); drawTrustMap(); });