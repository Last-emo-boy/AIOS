param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-mirror-frontend-signed-status",
    [string]$ResultPath = "",
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
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
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

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function ConvertFrom-JsonTextSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
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
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = "GET"
    )
    $url = "http://$Domain$Path"
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-X", $Method,
        "-w", "`n%{http_code}",
        $url
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
        path = $Path
        url = $url
        method = $Method
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        sha256 = Get-StringSha256 $body
        json = if ($statusCode -eq 200) { ConvertFrom-JsonTextSafe $body } else { $null }
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
        ("BEGIN" + " " + "PRIVATE" + " " + "KEY"),
        ("PRIVATE" + " " + "KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ".local-release-authority",
        ("signing" + "-key.pem")
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
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
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath
$generatedAt = (Get-Date).ToString("o")

$sourcePaths = [ordered]@{
    rc7_signed_metadata_revocation = ".workflow/artifacts/rc7-signed-metadata-revocation/result.json"
    rc7_installer_signed_consumption = ".workflow/artifacts/rc7-installer-signed-consumption/result.json"
    rc7_signed_consumption_fail_closed = ".workflow/artifacts/rc7-signed-consumption-fail-closed/result.json"
    rc7_install_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
}
$sourceArtifacts = [ordered]@{}
$sourceJson = [ordered]@{}
foreach ($key in $sourcePaths.Keys) {
    $path = Resolve-RepoPath $sourcePaths[$key]
    $json = Read-JsonFile $path
    $sourceJson[$key] = $json
    $sourceArtifacts[$key] = [ordered]@{
        path = Get-StablePath $path
        sha256 = Get-FileSha256 $path
        present = Test-Path -LiteralPath $path -PathType Leaf
        schema = $json.schema
        status = $json.status
    }
}

$before = [ordered]@{
    health = Invoke-Curl "/health.json"
    descriptor = Invoke-Curl "/.well-known/aios/mirror.json"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    support_index = Invoke-Curl "/support/index.json"
}
$payloadEntry = if ($null -ne $before.payload_index.json -and $null -ne $before.payload_index.json.entries) { @($before.payload_index.json.entries)[0] } else { $null }
$payloadBasePath = if ($null -ne $payloadEntry -and $payloadEntry.manifest_path) { $payloadEntry.manifest_path -replace "/manifest\.json$", "" } else { "/payloads/aios/production-distro-rc6-current-artifacts" }
$before.signed_metadata = Invoke-Curl "$payloadBasePath/signed-metadata.json"
$before.revocations = Invoke-Curl "$payloadBasePath/revocations.json"
$before.signatures = Invoke-Curl "$payloadBasePath/signatures.json"

$metadataBefore = [ordered]@{}
foreach ($key in $before.Keys) {
    if ($key -notin @("health", "descriptor", "channel", "payload_index", "install_bootstrap", "compatibility", "rollback_baseline", "support_index", "signed_metadata", "revocations", "signatures")) {
        continue
    }
    $metadataBefore[$key] = $before[$key].sha256
}

Add-Check "source.artifacts.present" (@($sourceArtifacts.Values | Where-Object { -not $_.present -or $_.status -ne "passed" }).Count -eq 0) "Frontend refresh must bind RC7 signed metadata, consumption, fail-closed, and rollback baseline evidence." $sourceArtifacts
Add-Check "live.metadata.before.available" (@($before.Values | Where-Object { $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0) "Live RC7 metadata must be reachable before frontend refresh." (@($before.Keys))
Add-Check "live.metadata.before.rc7_surface" ($sourceJson.rc7_install_rollback_baseline.payload_surface.compatibility_published -eq $true -and $sourceJson.rc7_install_rollback_baseline.payload_surface.rollback_baseline_published -eq $true -and $sourceJson.rc7_install_rollback_baseline.payload_surface.install_allowed -eq $false) "Frontend refresh must start after RC7 compatibility and rollback baseline publication while install remains blocked." $sourceJson.rc7_install_rollback_baseline.payload_surface

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
  <div id="app" class="shell">
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
        <a href="/install/compatibility.json">Compatibility</a>
        <a href="/install/rollback-baseline.json">Rollback</a>
      </nav>
    </header>

    <main>
      <section class="hero" aria-labelledby="hero-title">
        <div>
          <p class="eyebrow">Production candidate mirror</p>
          <h1 id="hero-title">AIOS signed status mirror</h1>
        </div>
        <div class="hero-status">
          <span id="status-service" class="status-pill neutral">Loading</span>
          <span id="status-ga" class="status-pill caution">non-GA</span>
          <span id="status-install" class="status-pill caution">install blocked</span>
        </div>
      </section>

      <section class="summary-grid" aria-label="Mirror summary">
        <article class="metric">
          <span class="metric-label">Current Payload</span>
          <strong id="metric-release">-</strong>
          <span id="metric-payload-status">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Signed Metadata</span>
          <strong id="metric-signed">-</strong>
          <span id="metric-signed-detail">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Revocation</span>
          <strong id="metric-revocation">-</strong>
          <span id="metric-revocation-detail">-</span>
        </article>
        <article class="metric">
          <span class="metric-label">Install Gates</span>
          <strong id="metric-install">-</strong>
          <span id="metric-blockers">-</span>
        </article>
      </section>

      <section class="mirror-grid">
        <section class="panel map-panel" aria-labelledby="map-title">
          <div class="panel-head">
            <h2 id="map-title">Trust Path</h2>
            <span id="map-caption">transport, verify locally</span>
          </div>
          <canvas id="trust-map" width="980" height="360" aria-label="AIOS signed mirror trust path"></canvas>
        </section>

        <section class="panel checks-panel" aria-labelledby="checks-title">
          <div class="panel-head">
            <h2 id="checks-title">Verification Gates</h2>
            <span id="checks-count">0 gates</span>
          </div>
          <ul id="checks-list" class="checks-list"></ul>
        </section>
      </section>

      <section class="lower-grid">
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

        <section class="panel hash-panel" aria-labelledby="hash-title">
          <div class="panel-head">
            <h2 id="hash-title">Hash Bindings</h2>
            <span id="hash-count">0 hashes</span>
          </div>
          <dl id="hash-list" class="hash-list"></dl>
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
  --paper: #f6f8f3;
  --surface: #ffffff;
  --surface-soft: #eef4ef;
  --ink: #17211d;
  --muted: #61716a;
  --line: #d7dfd3;
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
    linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(246, 248, 243, 0.98)),
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
  width: min(1210px, calc(100vw - 32px));
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
  font-weight: 800;
  font-size: 0.88rem;
}

.nav a:hover,
.nav a:focus-visible {
  color: var(--ink);
  border-color: var(--line);
  background: rgba(255, 255, 255, 0.88);
}

.hero {
  min-height: 154px;
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 24px;
  padding: 30px 0 22px;
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
  max-width: 850px;
  font-size: clamp(2.1rem, 6.6vw, 5.1rem);
  line-height: 0.96;
}

h2 {
  font-size: 1rem;
}

.hero-status {
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
  background: rgba(255, 255, 255, 0.92);
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
  font-size: 1.28rem;
  line-height: 1.18;
  overflow-wrap: anywhere;
}

.metric span:last-child {
  display: block;
  margin-top: 10px;
  color: var(--muted);
  overflow-wrap: anywhere;
}

.mirror-grid {
  grid-template-columns: minmax(0, 1.5fr) minmax(318px, 0.78fr);
  margin-bottom: 12px;
}

.lower-grid {
  grid-template-columns: minmax(0, 1.08fr) minmax(340px, 0.82fr);
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
  height: 318px;
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

.checks-list li.block::before {
  background: var(--red);
}

.checks-list strong {
  display: block;
  color: var(--ink);
  font-size: 0.92rem;
  overflow-wrap: anywhere;
}

.checks-list span {
  display: block;
  margin-top: 2px;
  overflow-wrap: anywhere;
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th,
td {
  padding: 11px 10px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
  font-size: 0.9rem;
  overflow-wrap: anywhere;
}

th {
  color: var(--muted);
  font-size: 0.78rem;
  text-transform: uppercase;
}

.hash-list {
  display: grid;
  grid-template-columns: minmax(150px, 0.42fr) minmax(0, 1fr);
  gap: 9px 12px;
  margin: 0;
}

.hash-list dt {
  color: var(--muted);
  font-weight: 800;
}

.hash-list dd {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}

@media (max-width: 920px) {
  .topbar,
  .hero {
    align-items: flex-start;
    flex-direction: column;
  }

  .nav {
    justify-content: flex-start;
  }

  .summary-grid,
  .mirror-grid,
  .lower-grid {
    grid-template-columns: 1fr;
  }

  h1 {
    font-size: clamp(2.2rem, 13vw, 4.2rem);
  }
}

@media (max-width: 560px) {
  .shell {
    width: min(100% - 20px, 1210px);
    padding-top: 10px;
  }

  .hero {
    min-height: 0;
  }

  .metric,
  .panel {
    padding: 13px;
  }

  #trust-map {
    height: 260px;
  }

  .hash-list {
    grid-template-columns: 1fr;
  }
}
'@

$js = @'
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
'@

$indexPath = Join-Path $resolvedArtifactDir "index.html"
$cssPath = Join-Path $resolvedArtifactDir "mirror.css"
$jsPath = Join-Path $resolvedArtifactDir "mirror.js"
Write-TextFile $indexPath $indexHtml
Write-TextFile $cssPath $css
Write-TextFile $jsPath $js

Add-Check "local.outputs.ready" ((Test-Path -LiteralPath $indexPath -PathType Leaf) -and (Test-Path -LiteralPath $cssPath -PathType Leaf) -and (Test-Path -LiteralPath $jsPath -PathType Leaf)) "Frontend assets must be generated locally before remote publication." ([ordered]@{ index = Get-StablePath $indexPath; css = Get-StablePath $cssPath; js = Get-StablePath $jsPath })
Add-Check "local.outputs.secret_safe" (Test-NoSensitiveText -Values @($indexHtml, $css, $js)) "Generated frontend assets must not contain private key paths, PEM private blocks, or tokens." $null
Add-Check "local.outputs.size_bounded" ((Get-Item $indexPath).Length -lt 65536 -and (Get-Item $cssPath).Length -lt 131072 -and (Get-Item $jsPath).Length -lt 131072) "Generated frontend assets must stay bounded for the small mirror host." ([ordered]@{ index_html = (Get-Item $indexPath).Length; mirror_css = (Get-Item $cssPath).Length; mirror_js = (Get-Item $jsPath).Length })

Set-RemoteTextFile -Path "/srv/aios-mirror/index.html" -Text $indexHtml
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.css" -Text $css
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.js" -Text $js

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; cd /srv/aios-mirror; sha256sum index.html assets/mirror.css assets/mirror.js"
$after = [ordered]@{
    index = Invoke-Curl "/"
    css = Invoke-Curl "/assets/mirror.css"
    js = Invoke-Curl "/assets/mirror.js"
    health = Invoke-Curl "/health.json"
    descriptor = Invoke-Curl "/.well-known/aios/mirror.json"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    signed_metadata = Invoke-Curl "$payloadBasePath/signed-metadata.json"
    revocations = Invoke-Curl "$payloadBasePath/revocations.json"
    signatures = Invoke-Curl "$payloadBasePath/signatures.json"
    support_index = Invoke-Curl "/support/index.json"
}
$installDirResponse = Invoke-Curl "/install/"
$postResponse = Invoke-Curl "/assets/mirror.js" -Method "POST"

$metadataAfter = [ordered]@{}
foreach ($key in $metadataBefore.Keys) {
    $metadataAfter[$key] = $after[$key].sha256
}
$metadataPreserved = $true
foreach ($key in $metadataBefore.Keys) {
    if ($metadataBefore[$key] -ne $metadataAfter[$key]) {
        $metadataPreserved = $false
    }
}

$frontendReady = $after.index.status_code -eq 200 -and $after.css.status_code -eq 200 -and $after.js.status_code -eq 200 -and $after.index.body.Contains("AIOS signed status mirror") -and $after.js.body.Contains("Compatibility metadata") -and $after.js.body.Contains("Rollback baseline")
$metadataReady = @($metadataAfter.Keys | Where-Object { $after[$_].status_code -ne 200 -or $null -eq $after[$_].json }).Count -eq 0
$payloadLive = $after.payload_index.json
$installLive = $after.install_bootstrap.json
$compatLive = $after.compatibility.json
$rollbackLive = $after.rollback_baseline.json
$entryLive = if ($null -ne $payloadLive -and $null -ne $payloadLive.entries) { @($payloadLive.entries)[0] } else { $null }
$rc7StatusVisible = $entryLive.compatibility_sha256 -and $entryLive.rollback_baseline_sha256 -and $installLive.projection.installer_compatibility_sha256 -and $installLive.projection.rollback_baseline_sha256 -and $compatLive.schema -eq "agentos.rc7-installer-compatibility.v1" -and $rollbackLive.schema -eq "agentos.rc7-rollback-baseline.v1"
$blockedSemantics = $installLive.install_allowed -eq $false -and $entryLive.install_allowed -eq $false -and $entryLive.activation_allowed -eq $false -and $entryLive.rollback_execution_allowed -eq $false -and $payloadLive.production_ready_claim -eq $false
$remoteSecretSafe = Test-NoSensitiveText -Values @($after.index.body, $after.css.body, $after.js.body)

Add-Check "remote.nginx.active" ($remoteCheck -match "active") "Nginx must remain active after RC7 frontend refresh." ($remoteCheck -split "`n")
Add-Check "remote.frontend.ready" $frontendReady "Refreshed frontend assets must be reachable and contain RC7 signed status UI code." ([ordered]@{ index = $after.index.status_code; css = $after.css.status_code; js = $after.js.status_code })
Add-Check "remote.metadata.preserved" $metadataPreserved "Frontend refresh must not mutate existing RC7 metadata endpoint bytes." ([ordered]@{ before = $metadataBefore; after = $metadataAfter })
Add-Check "remote.metadata.ready" $metadataReady "RC7 metadata endpoints used by the frontend must remain reachable as JSON." (@($metadataAfter.Keys))
Add-Check "remote.rc7_status.visible" $rc7StatusVisible "Live metadata must expose signed, revocation, compatibility, and rollback baseline status for the frontend." ([ordered]@{ compatibility_schema = if ($null -ne $compatLive) { $compatLive.schema } else { $null }; rollback_schema = if ($null -ne $rollbackLive) { $rollbackLive.schema } else { $null } })
Add-Check "remote.install.blocked" $blockedSemantics "Refreshed frontend must represent a non-GA install-blocked mirror state." ([ordered]@{ install_allowed = if ($null -ne $installLive) { $installLive.install_allowed } else { $null }; production_ready_claim = if ($null -ne $payloadLive) { $payloadLive.production_ready_claim } else { $null } })
Add-Check "remote.frontend.secret_safe" $remoteSecretSafe "Remote frontend assets must not expose private key paths, PEM private blocks, or tokens." $null
Add-Check "remote.directory_listing.blocked" (@(403, 404) -contains $installDirResponse.status_code) "Install directory listing must remain blocked after frontend refresh." $installDirResponse.status_code
Add-Check "remote.write_methods.blocked" (@(403, 405) -contains $postResponse.status_code) "POST to frontend assets must remain blocked." $postResponse.status_code

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-mirror-frontend-signed-status-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-020"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source_artifacts = $sourceArtifacts
    published_files = [ordered]@{
        index_html = "/srv/aios-mirror/index.html"
        mirror_css = "/srv/aios-mirror/assets/mirror.css"
        mirror_js = "/srv/aios-mirror/assets/mirror.js"
    }
    local_outputs = [ordered]@{
        index_html = Get-StablePath $indexPath
        mirror_css = Get-StablePath $cssPath
        mirror_js = Get-StablePath $jsPath
    }
    frontend_hashes = [ordered]@{
        index_html_sha256 = Get-FileSha256 $indexPath
        mirror_css_sha256 = Get-FileSha256 $cssPath
        mirror_js_sha256 = Get-FileSha256 $jsPath
    }
    preserved_metadata_hashes = $metadataAfter
    payload_surface = [ordered]@{
        release_id = if ($null -ne $entryLive) { $entryLive.release_id } else { $null }
        status = if ($null -ne $entryLive) { $entryLive.status } else { $null }
        signed_metadata_published = [bool]$entryLive.signed_metadata_sha256
        revocation_snapshot_published = [bool]$entryLive.revocation_snapshot_sha256
        compatibility_published = [bool]$entryLive.compatibility_sha256
        rollback_baseline_published = [bool]$entryLive.rollback_baseline_sha256
        cryptographic_signature_present = if ($null -ne $after.signatures.json) { $after.signatures.json.cryptographic_signature_present } else { $null }
        signature_available = if ($null -ne $after.signatures.json) { $after.signatures.json.signature_available } else { $null }
        install_allowed = if ($null -ne $entryLive) { $entryLive.install_allowed } else { $null }
        activation_allowed = if ($null -ne $entryLive) { $entryLive.activation_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $entryLive) { $entryLive.rollback_execution_allowed } else { $null }
    }
    invariants = [ordered]@{
        static_frontend_only = $true
        no_external_dependencies = $true
        metadata_preserved = $metadataPreserved
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        install_performed = $false
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
        rc7_020_complete = $passed
        next_task = "RC7-021"
    }
}

Write-Json $result $resolvedResultPath
Write-Host "RC7 mirror frontend signed status refresh $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
