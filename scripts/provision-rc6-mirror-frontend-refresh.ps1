param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-mirror-frontend-refresh",
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

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Text -Encoding UTF8
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

function ConvertFrom-JsonTextSafe {
    param([Parameter(Mandatory = $true)][string]$Text)
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
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
        sha256 = Get-StringSha256 $body
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

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        ("BEGIN " + "PRIVATE KEY"),
        ("PRIVATE KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ".local-release-authority",
        ("signing" + "-key.pem")
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

function Test-NoSensitiveFiles {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -Raw -LiteralPath $path
        if (-not (Test-NoSensitiveText -Values @($text))) {
            return $false
        }
    }
    return $true
}

function Has-FalseAuthority {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    $names = @(
        "signing_authority",
        "activation_authority",
        "rollback_execution_authority",
        "support_upload_authority",
        "production_ring_mutation_authority",
        "remote_dispatch_authority",
        "tui_authority"
    )
    foreach ($name in $names) {
        if ($null -ne $Value.$name -and $Value.$name -ne $false) {
            return $false
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
$taskId = "RC6-022"

$sourcePaths = [ordered]@{
    rc6_mirror_portal = ".workflow/artifacts/rc6-mirror-portal/result.json"
    rc6_hosted_payload_metadata = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json"
    rc6_bootstrap_installer_preflight = ".workflow/artifacts/rc6-bootstrap-installer-preflight/result.json"
    rc6_installer_fail_closed = ".workflow/artifacts/rc6-installer-fail-closed/result.json"
}
$sourceArtifacts = [ordered]@{}
foreach ($key in $sourcePaths.Keys) {
    $path = Resolve-RepoPath $sourcePaths[$key]
    $sourceArtifacts[$key] = [ordered]@{
        path = Get-StablePath $path
        sha256 = Get-FileSha256 $path
        present = Test-Path -LiteralPath $path -PathType Leaf
    }
}

$before = [ordered]@{
    health = Invoke-Curl "http://$Domain/health.json"
    descriptor = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"
    channel = Invoke-Curl "http://$Domain/channel/index.json"
    payload_index = Invoke-Curl "http://$Domain/payloads/index.json"
    install_bootstrap = Invoke-Curl "http://$Domain/install/bootstrap.json"
    support_index = Invoke-Curl "http://$Domain/support/index.json"
}

$beforeParsed = [ordered]@{
    health = ConvertFrom-JsonTextSafe $before.health.body
    descriptor = ConvertFrom-JsonTextSafe $before.descriptor.body
    channel = ConvertFrom-JsonTextSafe $before.channel.body
    payload_index = ConvertFrom-JsonTextSafe $before.payload_index.body
    install_bootstrap = ConvertFrom-JsonTextSafe $before.install_bootstrap.body
    support_index = ConvertFrom-JsonTextSafe $before.support_index.body
}

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
        <canvas id="brand-sigil" width="44" height="44" aria-hidden="true"></canvas>
        <span>
          <strong>AIOS Mirror</strong>
          <small>aios.w33d.xyz</small>
        </span>
      </a>
      <nav class="nav" aria-label="Mirror navigation">
        <a href="/channel/index.json">Channel</a>
        <a href="/payloads/index.json">Payloads</a>
        <a href="/install/bootstrap.json">Install</a>
        <a href="/support/index.json">Support</a>
      </nav>
    </header>

    <main>
      <section class="hero" aria-labelledby="hero-title">
        <div>
          <p class="eyebrow">Production candidate mirror</p>
          <h1 id="hero-title">AIOS public mirror</h1>
        </div>
        <div class="hero-status">
          <span id="status-service" class="status-pill neutral">Loading</span>
          <span id="status-ga" class="status-pill caution">non-GA</span>
          <span id="status-storage" class="status-pill neutral">metadata-only</span>
        </div>
      </section>

      <section class="summary-grid" aria-label="Mirror summary">
        <article class="metric">
          <span class="metric-label">Channel</span>
          <strong id="metric-channel">-</strong>
          <span id="metric-channel-status">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Current Payload</span>
          <strong id="metric-release">-</strong>
          <span id="metric-payload-status">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Install State</span>
          <strong id="metric-install">-</strong>
          <span id="metric-blockers">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Authority</span>
          <strong id="metric-authority">local verify</strong>
          <span id="metric-authority-detail">no mirror authority</span>
        </article>
      </section>

      <section class="mirror-grid">
        <section class="panel map-panel" aria-labelledby="map-title">
          <div class="panel-head">
            <h2 id="map-title">Trust Path</h2>
            <span id="map-caption">transport, not root of trust</span>
          </div>
          <canvas id="trust-map" width="960" height="340" aria-label="AIOS mirror trust path"></canvas>
        </section>

        <section class="panel checks-panel" aria-labelledby="checks-title">
          <div class="panel-head">
            <h2 id="checks-title">Verification Gates</h2>
            <span id="checks-count">0 checks</span>
          </div>
          <ul id="checks-list" class="checks-list"></ul>
        </section>
      </section>

      <section class="panel directory-panel" aria-labelledby="directory-title">
        <div class="panel-head">
          <h2 id="directory-title">Mirror Directory</h2>
          <span id="directory-count">0 entries</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Type</th>
                <th>Status</th>
                <th>Policy</th>
              </tr>
            </thead>
            <tbody id="directory-body"></tbody>
          </table>
        </div>
      </section>

      <section class="lower-grid">
        <section class="panel hash-panel" aria-labelledby="hash-title">
          <div class="panel-head">
            <h2 id="hash-title">Hash Bindings</h2>
            <span id="hash-count">0 hashes</span>
          </div>
          <dl id="hash-list" class="hash-list"></dl>
        </section>

        <section class="panel release-panel" aria-labelledby="release-title">
          <div class="panel-head">
            <h2 id="release-title">Payload Surface</h2>
            <span id="payload-count">0 payloads</span>
          </div>
          <div id="payload-list" class="payload-list"></div>
        </section>
      </section>
    </main>
  </div>
  <script src="/assets/mirror.js" defer></script>
</body>
</html>
'@

$css = @'
:root {
  --paper: #f5f7f2;
  --surface: #ffffff;
  --surface-soft: #eef5f0;
  --ink: #18211d;
  --muted: #617069;
  --line: #d6decf;
  --green: #20794f;
  --teal: #2f6f78;
  --blue: #315f9d;
  --amber: #ad6a19;
  --red: #a33a31;
  --shadow: 0 14px 34px rgba(24, 33, 29, 0.08);
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(245, 247, 242, 0.98)),
    linear-gradient(90deg, rgba(47, 111, 120, 0.08) 1px, transparent 1px),
    linear-gradient(0deg, rgba(49, 95, 157, 0.06) 1px, transparent 1px);
  background-size: auto, 72px 72px, 72px 72px;
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  letter-spacing: 0;
}

a {
  color: inherit;
  text-decoration: none;
}

.shell {
  width: min(1200px, calc(100vw - 32px));
  margin: 0 auto;
  padding: 18px 0 44px;
}

.topbar {
  min-height: 64px;
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

#brand-sigil {
  width: 44px;
  height: 44px;
  border-radius: 8px;
  border: 1px solid rgba(24, 33, 29, 0.12);
  background: #f9fbf6;
}

.brand strong,
.brand small {
  display: block;
}

.brand strong {
  font-size: 1.05rem;
}

.brand small {
  color: var(--muted);
  margin-top: 2px;
}

.nav {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 6px;
}

.nav a {
  min-height: 34px;
  padding: 8px 11px;
  border: 1px solid transparent;
  border-radius: 8px;
  color: var(--muted);
  font-weight: 700;
  font-size: 0.9rem;
}

.nav a:hover,
.nav a:focus-visible {
  color: var(--ink);
  border-color: var(--line);
  background: rgba(255, 255, 255, 0.86);
}

.hero {
  min-height: 142px;
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 24px;
  padding: 28px 0 22px;
}

.eyebrow,
.metric-label {
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 800;
  text-transform: uppercase;
}

h1,
h2 {
  margin: 0;
  letter-spacing: 0;
}

h1 {
  max-width: 780px;
  font-size: clamp(2.2rem, 7vw, 5.3rem);
  line-height: 0.94;
}

h2 {
  font-size: 1rem;
}

.hero-status,
.status-row {
  display: flex;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 8px;
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
  font-weight: 800;
  white-space: nowrap;
}

.status-pill.ok {
  color: var(--green);
  border-color: rgba(32, 121, 79, 0.28);
  background: #edf7f1;
}

.status-pill.caution {
  color: var(--amber);
  border-color: rgba(173, 106, 25, 0.3);
  background: #fff5e7;
}

.status-pill.bad {
  color: var(--red);
  border-color: rgba(163, 58, 49, 0.3);
  background: #fff0ed;
}

.summary-grid,
.mirror-grid,
.lower-grid {
  display: grid;
  gap: 12px;
}

.summary-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin-bottom: 12px;
}

.metric,
.panel {
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: var(--shadow);
}

.metric {
  min-height: 132px;
  padding: 16px;
}

.metric strong {
  display: block;
  min-height: 32px;
  font-size: 1.35rem;
  line-height: 1.15;
  overflow-wrap: anywhere;
}

.metric span:last-child {
  display: block;
  margin-top: 10px;
  color: var(--muted);
  overflow-wrap: anywhere;
}

.mirror-grid {
  grid-template-columns: minmax(0, 1.55fr) minmax(310px, 0.75fr);
  margin-bottom: 12px;
}

.lower-grid {
  grid-template-columns: minmax(0, 1fr) minmax(340px, 0.8fr);
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
  font-weight: 800;
}

#trust-map {
  width: 100%;
  height: 304px;
  display: block;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fbfcf8;
}

.checks-list {
  display: grid;
  gap: 9px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.checks-list li {
  display: grid;
  grid-template-columns: 10px minmax(0, 1fr);
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

.directory-panel {
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
  font-weight: 800;
}

.hash-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.payload-list {
  display: grid;
  gap: 10px;
}

.payload-item {
  display: grid;
  gap: 8px;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface-soft);
}

.payload-item strong,
.payload-item span {
  overflow-wrap: anywhere;
}

.payload-item span {
  color: var(--muted);
}

@media (max-width: 900px) {
  .topbar,
  .hero {
    align-items: stretch;
    flex-direction: column;
  }

  .nav,
  .hero-status {
    justify-content: flex-start;
  }

  .summary-grid,
  .mirror-grid,
  .lower-grid {
    grid-template-columns: 1fr;
  }

  .hash-list div {
    grid-template-columns: 1fr;
  }

  h1 {
    font-size: clamp(2.2rem, 14vw, 3.6rem);
  }
}
'@

$js = @'
const state = {
  health: null,
  descriptor: null,
  channel: null,
  payloadIndex: null,
  installBootstrap: null,
  supportIndex: null
};

const baseEndpoints = [
  { path: "/health.json", type: "health", status: "live", policy: "read-only" },
  { path: "/.well-known/aios/mirror.json", type: "descriptor", status: "live", policy: "read-only" },
  { path: "/channel/index.json", type: "channel", status: "hash-bound", policy: "candidate metadata" },
  { path: "/payloads/index.json", type: "payload index", status: "verification-gated", policy: "metadata-only" },
  { path: "/install/bootstrap.json", type: "installer bootstrap", status: "preflight-only", policy: "no activation" },
  { path: "/support/index.json", type: "support index", status: "available", policy: "no upload" }
];

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const el = byId(id);
  if (el) el.textContent = value ?? "-";
}

function setPill(id, label, mode) {
  const el = byId(id);
  if (!el) return;
  el.textContent = label;
  el.className = `status-pill ${mode || "neutral"}`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function shortHash(value) {
  if (!value) return "-";
  const text = String(value);
  return text.length > 24 ? `${text.slice(0, 12)}...${text.slice(-10)}` : text;
}

async function loadJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

function primaryPayload() {
  return state.payloadIndex?.entries?.[0] || {};
}

function installBlockerText() {
  const blockers = state.installBootstrap?.blockers || [];
  if (!blockers.length) return "no blockers listed";
  return `${blockers.length} blockers`;
}

function authorityClear() {
  const auth = state.channel?.authority || {};
  return [
    "signing_authority",
    "activation_authority",
    "rollback_execution_authority",
    "support_upload_authority",
    "production_ring_mutation_authority",
    "remote_dispatch_authority",
    "tui_authority"
  ].every((key) => auth[key] === false || auth[key] === undefined);
}

function renderSummary() {
  const payload = primaryPayload();
  const channel = state.channel || {};
  const health = state.health || {};
  const install = state.installBootstrap || {};

  setPill("status-service", health.status || "metadata unavailable", health.status ? "ok" : "bad");
  setPill("status-ga", channel.production_ready_claim === false ? "non-GA" : "GA claim blocked", channel.production_ready_claim === false ? "caution" : "bad");
  setPill("status-storage", health.storage_mode || channel.storage_mode || "unknown", health.storage_mode === "metadata-only" || channel.storage_mode === "metadata-only" ? "ok" : "bad");

  setText("metric-channel", channel.channel || "-");
  setText("metric-channel-status", channel.status || "-");
  setText("metric-release", payload.release_id || channel.payload_channel?.default_release_id || "-");
  setText("metric-payload-status", payload.status || "-");
  setText("metric-install", install.current_state || "-");
  setText("metric-blockers", installBlockerText());
  setText("metric-authority", authorityClear() ? "local verify" : "blocked");
  setText("metric-authority-detail", authorityClear() ? "no mirror authority" : "authority advertised");
}

function renderChecks() {
  const payload = primaryPayload();
  const checks = [
    {
      label: "Production ready claim is false",
      ok: state.channel?.production_ready_claim === false && state.payloadIndex?.production_ready_claim === false
    },
    {
      label: "Storage remains metadata-only",
      ok: state.channel?.storage_mode === "metadata-only" && state.payloadIndex?.storage_mode === "metadata-only"
    },
    {
      label: "Current payload is verification-blocked",
      ok: payload.status === "verification-blocked"
    },
    {
      label: "Payload signature is not yet available",
      ok: payload.signature_available === false || state.channel?.payload_channel?.signature_available === false,
      warn: true
    },
    {
      label: "Installer bootstrap does not allow install",
      ok: state.installBootstrap?.install_allowed === false && state.installBootstrap?.activation_allowed === false
    },
    {
      label: "Mirror has no signing or activation authority",
      ok: authorityClear()
    },
    {
      label: "TLS remains a GA gate",
      ok: state.installBootstrap?.tls_required_before_ga_claim === true || state.channel?.payload_channel?.metadata_only === true,
      warn: true
    }
  ];

  const list = byId("checks-list");
  list.innerHTML = "";
  checks.forEach((check) => {
    const li = document.createElement("li");
    li.className = check.ok ? (check.warn ? "warn" : "") : "bad";
    li.textContent = check.label;
    list.appendChild(li);
  });
  setText("checks-count", `${checks.length} checks`);
}

function renderDirectory() {
  const rows = byId("directory-body");
  rows.innerHTML = "";
  const channelEntries = (state.channel?.entries || []).map((entry) => ({
    path: entry.path,
    type: entry.kind || "channel entry",
    status: entry.status || "candidate",
    policy: entry.install_allowed || entry.activation_allowed ? "blocked" : "no activation"
  }));
  const entries = [...baseEndpoints, ...channelEntries];
  entries.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${escapeHtml(row.path)}</code></td>
      <td>${escapeHtml(row.type)}</td>
      <td>${escapeHtml(row.status)}</td>
      <td>${escapeHtml(row.policy)}</td>
    `;
    rows.appendChild(tr);
  });
  setText("directory-count", `${entries.length} entries`);
}

function renderHashes() {
  const channel = state.channel || {};
  const payload = primaryPayload();
  const hashes = [
    ["payload index", channel.payload_channel?.payload_index_sha256],
    ["install bootstrap", channel.payload_channel?.install_bootstrap_sha256],
    ["payload manifest", payload.manifest_sha256 || channel.payload_channel?.payload_manifest_sha256],
    ["payload checksums", payload.checksums_sha256 || channel.payload_channel?.payload_checksums_sha256],
    ["payload signatures", payload.signatures_sha256 || channel.payload_channel?.payload_signatures_sha256],
    ["support index", channel.support_recovery?.support_index_sha256]
  ].filter(([, value]) => value);

  const list = byId("hash-list");
  list.innerHTML = "";
  hashes.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.innerHTML = `<dt>${escapeHtml(label)}</dt><dd title="${escapeHtml(value)}">${escapeHtml(shortHash(value))}</dd>`;
    list.appendChild(row);
  });
  setText("hash-count", `${hashes.length} hashes`);
}

function renderPayloads() {
  const list = byId("payload-list");
  list.innerHTML = "";
  const entries = state.payloadIndex?.entries || [];
  entries.forEach((entry) => {
    const item = document.createElement("div");
    item.className = "payload-item";
    item.innerHTML = `
      <strong>${escapeHtml(entry.release_id || entry.id)}</strong>
      <span>${escapeHtml(entry.status || "candidate")} / ${entry.large_payload_deferred ? "large payload deferred" : "payload storage active"}</span>
      <span>${escapeHtml(entry.manifest_path || "-")}</span>
    `;
    list.appendChild(item);
  });
  setText("payload-count", `${entries.length} payloads`);
}

function drawBrand() {
  const canvas = byId("brand-sigil");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, 44, 44);
  ctx.fillStyle = "#f9fbf6";
  ctx.fillRect(0, 0, 44, 44);
  ctx.strokeStyle = "#20794f";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.moveTo(11, 28);
  ctx.lineTo(22, 10);
  ctx.lineTo(33, 28);
  ctx.stroke();
  ctx.strokeStyle = "#2f6f78";
  ctx.beginPath();
  ctx.moveTo(14, 26);
  ctx.lineTo(30, 26);
  ctx.stroke();
  ctx.fillStyle = "#315f9d";
  ctx.beginPath();
  ctx.arc(22, 33, 3.6, 0, Math.PI * 2);
  ctx.fill();
}

function drawTrustMap() {
  const canvas = byId("trust-map");
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#fbfcf8";
  ctx.fillRect(0, 0, w, h);

  const nodes = [
    { x: 132, y: 170, title: "Release evidence", sub: "RC5/RC6 hashes", color: "#315f9d" },
    { x: 374, y: 98, title: "Mirror transport", sub: "static nginx", color: "#20794f" },
    { x: 374, y: 244, title: "Fail closed", sub: "unsigned blocked", color: "#ad6a19" },
    { x: 630, y: 170, title: "Installer preflight", sub: "verification-blocked", color: "#2f6f78" },
    { x: 840, y: 170, title: "Canary gate", sub: "exact approval", color: "#a33a31" }
  ];

  ctx.lineWidth = 3;
  ctx.strokeStyle = "#cfd8cc";
  [[0,1],[0,2],[1,3],[2,3],[3,4]].forEach(([from, to]) => {
    const a = nodes[from];
    const b = nodes[to];
    ctx.beginPath();
    ctx.moveTo(a.x + 84, a.y);
    ctx.lineTo(b.x - 84, b.y);
    ctx.stroke();
  });

  nodes.forEach((node) => {
    ctx.fillStyle = "#ffffff";
    ctx.strokeStyle = "#d6decf";
    ctx.lineWidth = 2;
    roundedRect(ctx, node.x - 88, node.y - 44, 176, 88, 8);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = node.color;
    ctx.beginPath();
    ctx.arc(node.x - 58, node.y - 13, 7, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#18211d";
    ctx.font = "700 16px system-ui, sans-serif";
    ctx.fillText(node.title, node.x - 42, node.y - 8);
    ctx.fillStyle = "#617069";
    ctx.font = "13px system-ui, sans-serif";
    ctx.fillText(node.sub, node.x - 42, node.y + 18);
  });
}

function roundedRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
}

function render() {
  renderSummary();
  renderChecks();
  renderDirectory();
  renderHashes();
  renderPayloads();
  drawBrand();
  drawTrustMap();
}

async function boot() {
  drawBrand();
  drawTrustMap();
  try {
    [
      state.health,
      state.descriptor,
      state.channel,
      state.payloadIndex,
      state.installBootstrap,
      state.supportIndex
    ] = await Promise.all([
      loadJson("/health.json"),
      loadJson("/.well-known/aios/mirror.json"),
      loadJson("/channel/index.json"),
      loadJson("/payloads/index.json"),
      loadJson("/install/bootstrap.json"),
      loadJson("/support/index.json")
    ]);
    render();
  } catch (err) {
    setPill("status-service", "metadata unavailable", "bad");
    setText("metric-channel-status", err.message);
  }
}

window.addEventListener("resize", drawTrustMap);
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
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-AIOS-Mirror "rc6-metadata-only" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;

    location = / {
        default_type text/html;
        try_files /index.html =404;
        limit_except GET HEAD { deny all; }
    }

    location = /index.html {
        default_type text/html;
        try_files /index.html =404;
        limit_except GET HEAD { deny all; }
    }

    location /assets/ {
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location = /health.json {
        default_type application/json;
        try_files /health.json =404;
        limit_except GET HEAD { deny all; }
    }

    location = /.well-known/aios/mirror.json {
        default_type application/json;
        try_files /.well-known/aios/mirror.json =404;
        limit_except GET HEAD { deny all; }
    }

    location /channel/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /bootstrap/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /install/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /payloads/ {
        default_type application/json;
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

    location /releases/ {
        default_type text/plain;
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

$localFiles = [ordered]@{
    index_html = Join-Path $resolvedArtifactDir "index.html"
    mirror_css = Join-Path $resolvedArtifactDir "mirror.css"
    mirror_js = Join-Path $resolvedArtifactDir "mirror.js"
    nginx = Join-Path $resolvedArtifactDir "nginx-aios.w33d.xyz.conf"
}

Write-TextFile -Path $localFiles.index_html -Text $indexHtml
Write-TextFile -Path $localFiles.mirror_css -Text $css
Write-TextFile -Path $localFiles.mirror_js -Text $js
Write-TextFile -Path $localFiles.nginx -Text $nginxConfig

$localOutputPaths = @($localFiles.Values)
$localOutputsReady = @($localOutputPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -eq @($localOutputPaths).Count
$localOutputsSafe = Test-NoSensitiveFiles -Paths $localOutputPaths
$localOutputsSizeBounded = ((Get-Item -LiteralPath $localFiles.index_html).Length -le 65536) -and
    ((Get-Item -LiteralPath $localFiles.mirror_css).Length -le 65536) -and
    ((Get-Item -LiteralPath $localFiles.mirror_js).Length -le 65536) -and
    ((Get-Item -LiteralPath $localFiles.nginx).Length -le 32768)

Add-Check "source.artifacts.present" (@($sourceArtifacts.Values | Where-Object { -not $_.present }).Count -eq 0) "Frontend refresh must bind prior RC6 portal, payload, preflight, and fail-closed evidence." $sourceArtifacts
Add-Check "live.metadata.before.available" ($before.health.status_code -eq 200 -and $before.channel.status_code -eq 200 -and $before.payload_index.status_code -eq 200 -and $before.install_bootstrap.status_code -eq 200) "Live mirror metadata must be reachable before frontend refresh." ([ordered]@{
    health = $before.health.status_code
    channel = $before.channel.status_code
    payload_index = $before.payload_index.status_code
    install_bootstrap = $before.install_bootstrap.status_code
})
Add-Check "live.metadata.before.current_artifacts" ($beforeParsed.payload_index.entries[0].release_id -eq "production-distro-rc6-current-artifacts") "Frontend refresh must start from the current RC6 payload metadata, not the older preview payload." ([ordered]@{
    release_id = if ($null -ne $beforeParsed.payload_index) { $beforeParsed.payload_index.entries[0].release_id } else { $null }
})
Add-Check "local.outputs.ready" $localOutputsReady "Frontend refresh outputs must be generated locally before remote publication." ([ordered]@{ files = @($localFiles.Keys) })
Add-Check "local.outputs.secret_safe" $localOutputsSafe "Generated frontend and nginx config must not contain private key or token markers." $null
Add-Check "local.outputs.size_bounded" $localOutputsSizeBounded "Generated frontend assets must stay bounded for the small mirror host." ([ordered]@{
    index_html = (Get-Item -LiteralPath $localFiles.index_html).Length
    mirror_css = (Get-Item -LiteralPath $localFiles.mirror_css).Length
    mirror_js = (Get-Item -LiteralPath $localFiles.mirror_js).Length
    nginx = (Get-Item -LiteralPath $localFiles.nginx).Length
})

Set-RemoteTextFile -Path "/srv/aios-mirror/index.html" -Text $indexHtml
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.css" -Text $css
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.js" -Text $js
Set-RemoteTextFile -Path "/etc/nginx/sites-available/aios.w33d.xyz" -Text $nginxConfig

$remoteCheck = Invoke-Remote "set -eu; ln -sfn /etc/nginx/sites-available/aios.w33d.xyz /etc/nginx/sites-enabled/aios.w33d.xyz; nginx -t; systemctl reload nginx; systemctl is-active nginx; cd /srv/aios-mirror; find assets channel bootstrap install payloads support releases -maxdepth 5 -type f -printf '%P %s\n' | sort; sha256sum index.html assets/mirror.css assets/mirror.js channel/index.json payloads/index.json install/bootstrap.json"

$after = [ordered]@{
    root = Invoke-Curl "http://$Domain/"
    index = Invoke-Curl "http://$Domain/index.html"
    css = Invoke-Curl "http://$Domain/assets/mirror.css"
    js = Invoke-Curl "http://$Domain/assets/mirror.js"
    health = Invoke-Curl "http://$Domain/health.json"
    descriptor = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"
    channel = Invoke-Curl "http://$Domain/channel/index.json"
    payload_index = Invoke-Curl "http://$Domain/payloads/index.json"
    install_bootstrap = Invoke-Curl "http://$Domain/install/bootstrap.json"
    support_index = Invoke-Curl "http://$Domain/support/index.json"
    payload_dir = Invoke-Curl "http://$Domain/payloads/"
    assets_dir = Invoke-Curl "http://$Domain/assets/"
    post_root = Invoke-Curl "http://$Domain/" -Method "POST"
    post_payload = Invoke-Curl "http://$Domain/payloads/index.json" -Method "POST"
}

$afterParsed = [ordered]@{
    health = ConvertFrom-JsonTextSafe $after.health.body
    descriptor = ConvertFrom-JsonTextSafe $after.descriptor.body
    channel = ConvertFrom-JsonTextSafe $after.channel.body
    payload_index = ConvertFrom-JsonTextSafe $after.payload_index.body
    install_bootstrap = ConvertFrom-JsonTextSafe $after.install_bootstrap.body
    support_index = ConvertFrom-JsonTextSafe $after.support_index.body
}

$remoteHttpReady = $after.root.status_code -eq 200 -and
    $after.index.status_code -eq 200 -and
    $after.css.status_code -eq 200 -and
    $after.js.status_code -eq 200 -and
    $after.health.status_code -eq 200 -and
    $after.descriptor.status_code -eq 200 -and
    $after.channel.status_code -eq 200 -and
    $after.payload_index.status_code -eq 200 -and
    $after.install_bootstrap.status_code -eq 200 -and
    $after.support_index.status_code -eq 200

$metadataPreserved = $before.health.sha256 -eq $after.health.sha256 -and
    $before.descriptor.sha256 -eq $after.descriptor.sha256 -and
    $before.channel.sha256 -eq $after.channel.sha256 -and
    $before.payload_index.sha256 -eq $after.payload_index.sha256 -and
    $before.install_bootstrap.sha256 -eq $after.install_bootstrap.sha256 -and
    $before.support_index.sha256 -eq $after.support_index.sha256

$currentArtifactsPreserved = $null -ne $afterParsed.payload_index -and
    $afterParsed.payload_index.entries[0].release_id -eq "production-distro-rc6-current-artifacts" -and
    $afterParsed.payload_index.entries[0].status -eq "verification-blocked" -and
    $afterParsed.install_bootstrap.default_release_id -eq "production-distro-rc6-current-artifacts" -and
    $afterParsed.install_bootstrap.current_state -eq "verification-blocked"

$authorityPreserved = $null -ne $afterParsed.channel -and
    $afterParsed.channel.production_ready_claim -eq $false -and
    $afterParsed.channel.payload_channel.install_allowed -eq $false -and
    $afterParsed.channel.payload_channel.signature_available -eq $false -and
    (Has-FalseAuthority $afterParsed.channel.authority)

$frontendReady = $after.root.body -match 'AIOS public mirror' -and
    $after.root.body -match 'id="mirror-app"' -and
    $after.root.body -match 'id="trust-map"' -and
    $after.js.body -match '/payloads/index.json' -and
    $after.js.body -match '/install/bootstrap.json' -and
    $after.js.body -match 'drawTrustMap' -and
    $after.css.body -match 'grid-template-columns'

$noExternalDependencies = $after.root.body -notmatch 'https?://' -and
    $after.css.body -notmatch 'https?://' -and
    $after.js.body -notmatch 'https?://'

$remoteSecretSafe = Test-NoSensitiveText -Values @(
    $after.root.body,
    $after.css.body,
    $after.js.body,
    $after.health.body,
    $after.descriptor.body,
    $after.channel.body,
    $after.payload_index.body,
    $after.install_bootstrap.body,
    $after.support_index.body
)

Add-Check "nginx.reload" ($remoteCheck -match "active") "Nginx must validate and reload with the refreshed RC6 mirror frontend config." ($remoteCheck -split "`n")
Add-Check "remote.http.ready" $remoteHttpReady "Root frontend, assets, and existing mirror metadata endpoints must return HTTP 200 through resolve-pinned validation." ([ordered]@{
    root = $after.root.status_code
    css = $after.css.status_code
    js = $after.js.status_code
    health = $after.health.status_code
    channel = $after.channel.status_code
    payload_index = $after.payload_index.status_code
    install_bootstrap = $after.install_bootstrap.status_code
    support_index = $after.support_index.status_code
})
Add-Check "remote.metadata.preserved" $metadataPreserved "Frontend refresh must not rewrite existing health, descriptor, channel, payload, install, or support metadata." ([ordered]@{
    channel_before = $before.channel.sha256
    channel_after = $after.channel.sha256
    payload_before = $before.payload_index.sha256
    payload_after = $after.payload_index.sha256
    install_before = $before.install_bootstrap.sha256
    install_after = $after.install_bootstrap.sha256
})
Add-Check "remote.current_artifacts.preserved" $currentArtifactsPreserved "Live payload and install metadata must remain on production-distro-rc6-current-artifacts and verification-blocked." ([ordered]@{
    release_id = if ($null -ne $afterParsed.payload_index) { $afterParsed.payload_index.entries[0].release_id } else { $null }
    payload_status = if ($null -ne $afterParsed.payload_index) { $afterParsed.payload_index.entries[0].status } else { $null }
    install_state = if ($null -ne $afterParsed.install_bootstrap) { $afterParsed.install_bootstrap.current_state } else { $null }
})
Add-Check "remote.authority.preserved" $authorityPreserved "Live metadata must remain non-GA, unsigned, install-blocked, and non-authoritative." ([ordered]@{
    production_ready_claim = if ($null -ne $afterParsed.channel) { $afterParsed.channel.production_ready_claim } else { $null }
    signature_available = if ($null -ne $afterParsed.channel) { $afterParsed.channel.payload_channel.signature_available } else { $null }
    install_allowed = if ($null -ne $afterParsed.channel) { $afterParsed.channel.payload_channel.install_allowed } else { $null }
})
Add-Check "frontend.portal.ready" $frontendReady "Root frontend must render the refreshed AIOS mirror shell, directory, payload surface, and canvas trust path." $null
Add-Check "frontend.no_external_dependencies" $noExternalDependencies "Frontend must not depend on external scripts, styles, images, fonts, or APIs." $null
Add-Check "remote.secret_safe" $remoteSecretSafe "Remote frontend and metadata responses must not expose private key or token markers." $null
Add-Check "remote.directory_listing.blocked" ((@(403, 404) -contains $after.payload_dir.status_code) -and (@(403, 404) -contains $after.assets_dir.status_code)) "Directory listing must be blocked for payloads and assets." ([ordered]@{
    payloads = $after.payload_dir.status_code
    assets = $after.assets_dir.status_code
})
Add-Check "remote.write_methods.blocked" ((@(403, 405) -contains $after.post_root.status_code) -and (@(403, 405) -contains $after.post_payload.status_code)) "POST must remain blocked for root and payload metadata." ([ordered]@{
    root = $after.post_root.status_code
    payload_index = $after.post_payload.status_code
})

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-mirror-frontend-refresh-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = $taskId
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
    source_artifacts = $sourceArtifacts
    published_files = [ordered]@{
        index_html = "/srv/aios-mirror/index.html"
        mirror_css = "/srv/aios-mirror/assets/mirror.css"
        mirror_js = "/srv/aios-mirror/assets/mirror.js"
        nginx_site = "/etc/nginx/sites-available/aios.w33d.xyz"
    }
    local_outputs = [ordered]@{
        index_html = Get-StablePath $localFiles.index_html
        mirror_css = Get-StablePath $localFiles.mirror_css
        mirror_js = Get-StablePath $localFiles.mirror_js
        nginx = Get-StablePath $localFiles.nginx
    }
    frontend_hashes = [ordered]@{
        index_html_sha256 = $after.root.sha256
        mirror_css_sha256 = $after.css.sha256
        mirror_js_sha256 = $after.js.sha256
        nginx_config_sha256 = Get-FileSha256 $localFiles.nginx
    }
    preserved_metadata_hashes = [ordered]@{
        health_sha256 = $after.health.sha256
        descriptor_sha256 = $after.descriptor.sha256
        channel_sha256 = $after.channel.sha256
        payload_index_sha256 = $after.payload_index.sha256
        install_bootstrap_sha256 = $after.install_bootstrap.sha256
        support_index_sha256 = $after.support_index.sha256
    }
    payload_surface = [ordered]@{
        release_id = if ($null -ne $afterParsed.payload_index) { $afterParsed.payload_index.entries[0].release_id } else { $null }
        status = if ($null -ne $afterParsed.payload_index) { $afterParsed.payload_index.entries[0].status } else { $null }
        install_state = if ($null -ne $afterParsed.install_bootstrap) { $afterParsed.install_bootstrap.current_state } else { $null }
        signature_available = if ($null -ne $afterParsed.channel) { $afterParsed.channel.payload_channel.signature_available } else { $null }
        install_allowed = if ($null -ne $afterParsed.channel) { $afterParsed.channel.payload_channel.install_allowed } else { $null }
    }
    invariants = [ordered]@{
        static_frontend_only = $true
        no_external_dependencies = $true
        metadata_preserved = $metadataPreserved
        metadata_only = $true
        large_payload_storage_enabled = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        signature_available = $false
        install_allowed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
        tls_required_before_ga_claim = $true
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc6_022_complete = $passed
        frontend_url = "http://$Domain/"
        payload_index = "http://$Domain/payloads/index.json"
        install_bootstrap = "http://$Domain/install/bootstrap.json"
        production_ready_claim = $false
        next_task = "RC6-030"
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC6 mirror frontend refresh $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
