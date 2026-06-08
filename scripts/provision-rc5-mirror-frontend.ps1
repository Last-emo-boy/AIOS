param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-mirror-frontend",
    [string]$OutputPath = "",
    [int]$SshConnectTimeoutSeconds = 10,
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $combined = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $script:repoRoot $Path }
    $full = [IO.Path]::GetFullPath($combined)
    $repoPrefix = $script:repoRoot.TrimEnd("\", "/") + [IO.Path]::DirectorySeparatorChar
    if ($full -ne $script:repoRoot -and -not $full.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes repository root: $Path"
    }
    return $full
}

function Get-StablePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith($script:repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($script:repoRoot.Length).TrimStart("\", "/") -replace "\\", "/"
    }
    return $full
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        $Command
    )
    $output = & ssh @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "Remote command failed ($exitCode): $text"
    }
    return $text
}

function Set-RemoteTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Mode = "0644"
    )
    $encoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($Text))
    $parent = [IO.Path]::GetDirectoryName($Path) -replace "\\", "/"
    $command = "set -eu; install -d -m 0755 '$parent'; printf '%s' '$encoded' | base64 -d > '$Path'; chmod '$Mode' '$Path'"
    Invoke-Remote $command | Out-Null
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$Method = "GET"
    )
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-X", $Method,
        "-w", "`n%{http_code}",
        $Url
    )
    $output = & curl.exe @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).TrimEnd()
    $parts = [regex]::Split($text, "\r?\n")
    $statusText = $parts[-1]
    $body = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join "`n") } else { "" }
    $statusCode = 0
    [void][int]::TryParse($statusText, [ref]$statusCode)
    return [ordered]@{
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        url = $Url
        method = $Method
    }
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) {
        $script:blockers += $entry
    }
}

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        "BEGIN PRIVATE KEY",
        "AIOS_SIGNER_API_TOKEN",
        "Authorization: Bearer",
        "Bearer ",
        "access_token",
        "refresh_token",
        ".local-release-authority/private",
        "signing-key.pem"
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.Contains($marker, [StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }
    return $true
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$generatedAt = (Get-Date).ToString("o")
$rc5EndpointVerifierPath = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-endpoint-verifier/result.json"
$rc5FailClosedPath = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json"

$indexHtml = @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>AIOS Mirror</title>
  <link rel="stylesheet" href="/assets/mirror.css">
</head>
<body>
  <div id="mirror-app" class="shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="AIOS Mirror home">
        <span class="brand-mark" aria-hidden="true"></span>
        <span>
          <strong>AIOS Mirror</strong>
          <small>aios.w33d.xyz</small>
        </span>
      </a>
      <nav class="nav" aria-label="Mirror navigation">
        <a href="/channel/index.json">Channel</a>
        <a href="/.well-known/aios/mirror.json">Descriptor</a>
        <a href="/health.json">Health</a>
        <a href="/releases/README.txt">Releases</a>
      </nav>
    </header>

    <main>
      <section class="status-band" aria-labelledby="status-title">
        <div>
          <p class="eyebrow">Production candidate mirror</p>
          <h1 id="status-title">AIOS distribution metadata</h1>
        </div>
        <div class="status-stack">
          <span id="service-status" class="status-pill neutral">Loading</span>
          <span id="storage-mode" class="status-pill neutral">metadata-only</span>
        </div>
      </section>

      <section class="summary-grid" aria-label="Mirror summary">
        <article class="metric">
          <span class="metric-label">Channel</span>
          <strong id="channel-name">-</strong>
          <span id="channel-state">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Freshness</span>
          <strong id="freshness-window">-</strong>
          <span id="generated-at">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Trust</span>
          <strong id="trust-state">verify locally</strong>
          <span id="authority-state">no activation authority</span>
        </article>
        <article class="metric">
          <span class="metric-label">Payloads</span>
          <strong id="payload-state">deferred</strong>
          <span>metadata only</span>
        </article>
      </section>

      <section class="workspace">
        <div class="panel topology-panel">
          <div class="panel-head">
            <h2>Mirror Path</h2>
            <span id="non-ga-badge" class="status-pill caution">non-GA</span>
          </div>
          <canvas id="signal-map" width="880" height="280" aria-label="Mirror trust path visualization"></canvas>
        </div>

        <div class="panel checks-panel">
          <div class="panel-head">
            <h2>Verification</h2>
            <span id="check-count">0 checks</span>
          </div>
          <ul id="checks-list" class="checks-list"></ul>
        </div>
      </section>

      <section class="panel directory-panel" aria-labelledby="directory-title">
        <div class="panel-head">
          <h2 id="directory-title">Directory</h2>
          <span id="entry-count">0 entries</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Type</th>
                <th>Status</th>
                <th>Authority</th>
              </tr>
            </thead>
            <tbody id="directory-rows"></tbody>
          </table>
        </div>
      </section>

      <section class="panel hash-panel" aria-labelledby="hash-title">
        <div class="panel-head">
          <h2 id="hash-title">Hash Bindings</h2>
          <span>RC4 source evidence</span>
        </div>
        <dl class="hash-list">
          <div>
            <dt>RC4 final audit</dt>
            <dd id="hash-rc4">-</dd>
          </div>
          <div>
            <dt>Hosted transport</dt>
            <dd id="hash-hosted">-</dd>
          </div>
          <div>
            <dt>Mirror publication</dt>
            <dd id="hash-mirror">-</dd>
          </div>
        </dl>
      </section>
    </main>
  </div>
  <script src="/assets/mirror.js" defer></script>
</body>
</html>
'@

$css = @'
:root {
  --paper: #f6f7f2;
  --surface: #ffffff;
  --ink: #17211d;
  --muted: #61706a;
  --line: #d8ded2;
  --green: #1e7b53;
  --teal: #2f6f7a;
  --amber: #ad6a19;
  --red: #a33a31;
  --blue: #315f9d;
  --shadow: 0 12px 30px rgba(23, 33, 29, 0.08);
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background:
    linear-gradient(180deg, rgba(255,255,255,0.82), rgba(246,247,242,0.98)),
    repeating-linear-gradient(90deg, rgba(49,95,157,0.05) 0, rgba(49,95,157,0.05) 1px, transparent 1px, transparent 80px);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  letter-spacing: 0;
}

a {
  color: inherit;
  text-decoration: none;
}

.shell {
  width: min(1180px, calc(100vw - 32px));
  margin: 0 auto;
  padding: 18px 0 40px;
}

.topbar {
  min-height: 60px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  border-bottom: 1px solid var(--line);
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand strong,
.brand small {
  display: block;
}

.brand small {
  color: var(--muted);
  margin-top: 2px;
}

.brand-mark {
  width: 38px;
  height: 38px;
  border-radius: 8px;
  background:
    linear-gradient(135deg, var(--green), var(--teal));
  position: relative;
  box-shadow: inset 0 0 0 1px rgba(255,255,255,0.4);
}

.brand-mark::before,
.brand-mark::after {
  content: "";
  position: absolute;
  background: #fff;
  opacity: 0.9;
}

.brand-mark::before {
  width: 20px;
  height: 3px;
  left: 9px;
  top: 13px;
}

.brand-mark::after {
  width: 3px;
  height: 20px;
  left: 18px;
  top: 9px;
}

.nav {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.nav a {
  min-height: 34px;
  padding: 8px 11px;
  border: 1px solid transparent;
  border-radius: 8px;
  color: var(--muted);
}

.nav a:hover,
.nav a:focus-visible {
  color: var(--ink);
  border-color: var(--line);
  background: rgba(255,255,255,0.78);
}

.status-band {
  min-height: 132px;
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 24px;
  padding: 26px 0 22px;
}

.eyebrow,
.metric-label {
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
}

h1,
h2 {
  margin: 0;
  letter-spacing: 0;
}

h1 {
  font-size: clamp(2rem, 6vw, 4.4rem);
  line-height: 0.96;
  max-width: 760px;
}

h2 {
  font-size: 1rem;
}

.status-stack {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--surface);
  color: var(--muted);
  font-size: 0.82rem;
  font-weight: 700;
  white-space: nowrap;
}

.status-pill.ok {
  color: var(--green);
  border-color: rgba(30,123,83,0.28);
  background: #edf7f1;
}

.status-pill.caution {
  color: var(--amber);
  border-color: rgba(173,106,25,0.3);
  background: #fff5e7;
}

.status-pill.bad {
  color: var(--red);
  border-color: rgba(163,58,49,0.3);
  background: #fff0ed;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 12px;
}

.metric,
.panel {
  background: rgba(255,255,255,0.86);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: var(--shadow);
}

.metric {
  min-height: 128px;
  padding: 16px;
}

.metric strong {
  display: block;
  min-height: 30px;
  font-size: 1.45rem;
  line-height: 1.15;
  overflow-wrap: anywhere;
}

.metric span:last-child {
  display: block;
  color: var(--muted);
  margin-top: 10px;
  overflow-wrap: anywhere;
}

.workspace {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(300px, 0.75fr);
  gap: 12px;
  margin-bottom: 12px;
}

.panel {
  padding: 16px;
}

.panel-head {
  min-height: 36px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.panel-head span {
  color: var(--muted);
  font-size: 0.86rem;
  font-weight: 700;
}

#signal-map {
  width: 100%;
  height: 260px;
  display: block;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fbfcf8;
}

.checks-list {
  display: grid;
  gap: 8px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.checks-list li {
  display: grid;
  grid-template-columns: 10px 1fr;
  gap: 10px;
  align-items: start;
  min-height: 28px;
  color: var(--muted);
}

.checks-list li::before {
  content: "";
  width: 10px;
  height: 10px;
  margin-top: 6px;
  border-radius: 999px;
  background: var(--green);
}

.checks-list li.warn::before {
  background: var(--amber);
}

.checks-list li.bad::before {
  background: var(--red);
}

.directory-panel,
.hash-panel {
  margin-bottom: 12px;
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}

th,
td {
  padding: 12px 10px;
  border-top: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}

th {
  color: var(--muted);
  font-size: 0.78rem;
  text-transform: uppercase;
}

td code,
.hash-list dd {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.82rem;
}

.hash-list {
  display: grid;
  gap: 10px;
  margin: 0;
}

.hash-list div {
  display: grid;
  grid-template-columns: 170px minmax(0, 1fr);
  gap: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--line);
}

.hash-list dt {
  color: var(--muted);
  font-weight: 700;
}

.hash-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}

@media (max-width: 860px) {
  .topbar,
  .status-band {
    align-items: stretch;
    flex-direction: column;
  }

  .nav,
  .status-stack {
    justify-content: flex-start;
  }

  .summary-grid,
  .workspace {
    grid-template-columns: 1fr;
  }

  .hash-list div {
    grid-template-columns: 1fr;
  }

  h1 {
    font-size: clamp(2rem, 13vw, 3.3rem);
  }
}
'@

$js = @'
const state = {
  health: null,
  descriptor: null,
  channel: null
};

const endpoints = [
  { path: "/health.json", type: "health", status: "public metadata", authority: "read-only" },
  { path: "/.well-known/aios/mirror.json", type: "descriptor", status: "public metadata", authority: "read-only" },
  { path: "/channel/index.json", type: "channel", status: "hash-bound", authority: "candidate only" },
  { path: "/releases/README.txt", type: "release placeholder", status: "metadata-only", authority: "no activation" }
];

function text(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? "-";
}

function pill(id, label, mode) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = label;
  el.className = `status-pill ${mode || "neutral"}`;
}

function shortHash(value) {
  if (!value || value.length < 16) return value || "-";
  return `${value.slice(0, 12)}...${value.slice(-10)}`;
}

async function loadJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

function renderChecks() {
  const checks = [
    {
      label: "Health endpoint returns RC5 schema",
      ok: state.health?.schema === "agentos.rc5-hosted-mirror-health.v1"
    },
    {
      label: "Channel index remains non-GA",
      ok: state.channel?.production_ready_claim === false
    },
    {
      label: "Mirror storage is metadata-only",
      ok: state.health?.storage_mode === "metadata-only" && state.channel?.storage_mode === "metadata-only"
    },
    {
      label: "Activation authority is absent",
      ok: state.health?.activation_authority === false && state.channel?.authority?.activation_authority === false
    },
    {
      label: "Signing authority is absent",
      ok: state.health?.signing_authority === false && state.channel?.authority?.signing_authority === false
    },
    {
      label: "TLS remains a GA gate",
      warn: true,
      ok: true
    }
  ];

  const list = document.getElementById("checks-list");
  list.innerHTML = "";
  checks.forEach((check) => {
    const li = document.createElement("li");
    li.className = check.ok ? (check.warn ? "warn" : "") : "bad";
    li.textContent = check.label;
    list.appendChild(li);
  });
  text("check-count", `${checks.length} checks`);
}

function renderDirectory() {
  const rows = document.getElementById("directory-rows");
  rows.innerHTML = "";
  const channelEntries = (state.channel?.entries || []).map((entry) => ({
    path: entry.path,
    type: "channel entry",
    status: entry.status || "candidate",
    authority: entry.activation_allowed ? "activation advertised" : "no activation"
  }));
  [...endpoints, ...channelEntries].forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${row.path}</code></td>
      <td>${row.type}</td>
      <td>${row.status}</td>
      <td>${row.authority}</td>
    `;
    rows.appendChild(tr);
  });
  text("entry-count", `${endpoints.length + channelEntries.length} entries`);
}

function drawSignalMap() {
  const canvas = document.getElementById("signal-map");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  ctx.fillStyle = "#fbfcf8";
  ctx.fillRect(0, 0, w, h);

  const nodes = [
    { x: 130, y: 135, title: "RC4 evidence", sub: "hash bound", color: "#315f9d" },
    { x: 440, y: 88, title: "AIOS mirror", sub: "metadata-only", color: "#1e7b53" },
    { x: 440, y: 190, title: "Fail closed", sub: "14 cases", color: "#ad6a19" },
    { x: 750, y: 135, title: "User verify", sub: "no activation", color: "#2f6f7a" }
  ];

  ctx.lineWidth = 3;
  ctx.strokeStyle = "#cdd6ca";
  [[0,1],[0,2],[1,3],[2,3]].forEach(([a,b]) => {
    ctx.beginPath();
    ctx.moveTo(nodes[a].x + 82, nodes[a].y);
    ctx.lineTo(nodes[b].x - 82, nodes[b].y);
    ctx.stroke();
  });

  nodes.forEach((node) => {
    ctx.fillStyle = "#ffffff";
    ctx.strokeStyle = "#d8ded2";
    ctx.lineWidth = 2;
    roundRect(ctx, node.x - 86, node.y - 43, 172, 86, 8);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = node.color;
    ctx.beginPath();
    ctx.arc(node.x - 58, node.y - 12, 7, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#17211d";
    ctx.font = "700 17px system-ui, sans-serif";
    ctx.fillText(node.title, node.x - 42, node.y - 6);
    ctx.fillStyle = "#61706a";
    ctx.font = "13px system-ui, sans-serif";
    ctx.fillText(node.sub, node.x - 42, node.y + 18);
  });
}

function roundRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
}

function render() {
  const health = state.health || {};
  const descriptor = state.descriptor || {};
  const channel = state.channel || {};

  pill("service-status", health.status || "unavailable", health.status ? "ok" : "bad");
  pill("storage-mode", health.storage_mode || "unknown", health.storage_mode === "metadata-only" ? "ok" : "bad");
  text("channel-name", channel.channel || "-");
  text("channel-state", channel.status || "-");
  text("freshness-window", channel.freshness_window || descriptor.freshness_window || "-");
  text("generated-at", channel.generated_at || health.generated_at || "-");
  text("trust-state", channel.production_ready_claim === false ? "verify locally" : "blocked");
  text("authority-state", channel.authority?.activation_authority === false ? "no activation authority" : "authority advertised");
  text("payload-state", health.large_artifact_storage_deferred ? "deferred" : "available");
  text("hash-rc4", shortHash(channel.source_rc4_final_audit_sha256));
  text("hash-hosted", shortHash(channel.hosted_transport_manifest_sha256));
  text("hash-mirror", shortHash(channel.mirror_publication_sha256));

  renderChecks();
  renderDirectory();
  drawSignalMap();
}

async function boot() {
  try {
    [state.health, state.descriptor, state.channel] = await Promise.all([
      loadJson("/health.json"),
      loadJson("/.well-known/aios/mirror.json"),
      loadJson("/channel/index.json")
    ]);
    render();
  } catch (err) {
    pill("service-status", "metadata unavailable", "bad");
    text("channel-state", err.message);
    drawSignalMap();
  }
}

window.addEventListener("resize", drawSignalMap);
boot();
'@

$nginxConfig = @'
server {
    listen 80;
    listen [::]:80;
    server_name aios.w33d.xyz;

    root /srv/aios-mirror;
    index index.html;
    autoindex off;
    server_tokens off;
    client_max_body_size 1m;
    access_log /var/log/nginx/aios.access.log;
    error_log /var/log/nginx/aios.error.log warn;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-AIOS-Mirror "rc5-metadata-only" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;

    location = / {
        default_type text/html;
        add_header Cache-Control "no-cache" always;
        try_files /index.html =404;
        limit_except GET HEAD { deny all; }
    }

    location = /index.html {
        default_type text/html;
        add_header Cache-Control "no-cache" always;
        try_files /index.html =404;
        limit_except GET HEAD { deny all; }
    }

    location /assets/ {
        autoindex off;
        try_files $uri =404;
        add_header Cache-Control "public, max-age=300" always;
        limit_except GET HEAD { deny all; }
    }

    location = /health.json {
        default_type application/json;
        add_header Cache-Control "no-store" always;
        try_files /health.json =404;
        limit_except GET HEAD { deny all; }
    }

    location = /.well-known/aios/mirror.json {
        default_type application/json;
        add_header Cache-Control "no-store" always;
        try_files /.well-known/aios/mirror.json =404;
        limit_except GET HEAD { deny all; }
    }

    location = /channel/index.json {
        default_type application/json;
        add_header Cache-Control "no-cache" always;
        try_files /channel/index.json =404;
        limit_except GET HEAD { deny all; }
    }

    location /releases/ {
        default_type text/plain;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /support/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location / {
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }
}
'@

Set-RemoteTextFile -Path "/srv/aios-mirror/index.html" -Text $indexHtml
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.css" -Text $css
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.js" -Text $js
Set-RemoteTextFile -Path "/etc/nginx/sites-available/aios.w33d.xyz" -Text $nginxConfig

$remoteCheck = Invoke-Remote "set -eu; nginx -t; systemctl reload nginx; systemctl is-active nginx; find /srv/aios-mirror -maxdepth 3 -type f -printf '%P %s\n' | sort; sha256sum /srv/aios-mirror/index.html /srv/aios-mirror/assets/mirror.css /srv/aios-mirror/assets/mirror.js"

$indexResponse = Invoke-Curl "http://$Domain/"
$htmlResponse = Invoke-Curl "http://$Domain/index.html"
$cssResponse = Invoke-Curl "http://$Domain/assets/mirror.css"
$jsResponse = Invoke-Curl "http://$Domain/assets/mirror.js"
$healthResponse = Invoke-Curl "http://$Domain/health.json"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$postRootResponse = Invoke-Curl "http://$Domain/" -Method "POST"

Add-Check "nginx.reload" ($remoteCheck -match "active") "Nginx must reload successfully after frontend provisioning." ($remoteCheck -split "`n")
Add-Check "root.http_200" ($indexResponse.status_code -eq 200) "Root path must serve the mirror frontend." $indexResponse.status_code
Add-Check "index.http_200" ($htmlResponse.status_code -eq 200) "index.html must be directly accessible." $htmlResponse.status_code
Add-Check "css.http_200" ($cssResponse.status_code -eq 200) "CSS asset must be accessible." $cssResponse.status_code
Add-Check "js.http_200" ($jsResponse.status_code -eq 200) "JS asset must be accessible." $jsResponse.status_code
Add-Check "metadata.still_available" ($healthResponse.status_code -eq 200 -and $channelResponse.status_code -eq 200) "Existing metadata endpoints must remain available." ([ordered]@{ health = $healthResponse.status_code; channel = $channelResponse.status_code })
Add-Check "frontend.app_root" ($indexResponse.body -match 'id="mirror-app"' -and $indexResponse.body -match 'AIOS Mirror') "Frontend must include the AIOS mirror app shell." $null
Add-Check "frontend.data_driven" ($jsResponse.body -match '/health.json' -and $jsResponse.body -match '/channel/index.json' -and $jsResponse.body -match 'drawSignalMap') "Frontend must read mirror metadata and render a visual trust path." $null
Add-Check "frontend.no_external_dependencies" ($indexResponse.body -notmatch 'https?://' -and $cssResponse.body -notmatch 'https?://' -and $jsResponse.body -notmatch 'https?://') "Frontend must not depend on external network assets." $null
Add-Check "frontend.secret_safe" (Test-NoSensitiveContent -Values @($indexResponse.body, $cssResponse.body, $jsResponse.body)) "Frontend assets must not contain private key or token markers." $null
Add-Check "post.root_blocked" (@(403, 405) -contains $postRootResponse.status_code) "POST to root frontend must be blocked." $postRootResponse.status_code

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc5-mirror-frontend-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC5-013"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        nginx_site = "/etc/nginx/sites-available/aios.w33d.xyz"
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source_artifacts = [ordered]@{
        rc5_hosted_endpoint_verifier = [ordered]@{ path = Get-StablePath $rc5EndpointVerifierPath; sha256 = Get-FileSha256 $rc5EndpointVerifierPath }
        rc5_hosted_metadata_fail_closed = [ordered]@{ path = Get-StablePath $rc5FailClosedPath; sha256 = Get-FileSha256 $rc5FailClosedPath }
    }
    frontend_outputs = [ordered]@{
        index_html_sha256 = Get-StringSha256 $indexResponse.body
        mirror_css_sha256 = Get-StringSha256 $cssResponse.body
        mirror_js_sha256 = Get-StringSha256 $jsResponse.body
    }
    invariants = [ordered]@{
        static_frontend_only = $true
        no_external_dependencies = $true
        metadata_endpoints_preserved = $true
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc5_013_complete = $passed
        frontend_url = "http://$Domain/"
        tls_required_before_ga_claim = $true
        production_ready_claim = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC5 mirror frontend $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
