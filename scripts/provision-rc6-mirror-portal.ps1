param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-mirror-portal",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
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

function Read-JsonFileSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    try {
        return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
    } catch {
        return $null
    }
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
        "access_token",
        "refresh_token",
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
    return $Value.signing_authority -eq $false -and
        $Value.activation_authority -eq $false -and
        $Value.rollback_execution_authority -eq $false -and
        $Value.tui_authority -eq $false
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
$releaseId = "production-distro-rc6-metadata-preview"
$payloadBasePath = "/payloads/aios/$releaseId"

$rc5FinalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/FINAL-AUDIT-20260608-production-distro-rc5.json"
$rc5SupportResultPath = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-support-recovery/result.json"
$rc5CanaryResultPath = Resolve-RepoPath ".workflow/artifacts/rc5-multi-node-canary-proof/result.json"
$rc6ContractPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/installable-signed-payload-channel-contract.md"
$rc6BoundaryPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/bootstrap-installer-consumption-boundary.md"
$rc6ThreatModelPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/tls-storage-signed-payload-threat-model.md"

$rc5FinalAuditHash = Get-FileSha256 $rc5FinalAuditPath
$rc5SupportResultHash = Get-FileSha256 $rc5SupportResultPath
$rc5CanaryResultHash = Get-FileSha256 $rc5CanaryResultPath
$rc6ContractHash = Get-FileSha256 $rc6ContractPath
$rc6BoundaryHash = Get-FileSha256 $rc6BoundaryPath
$rc6ThreatModelHash = Get-FileSha256 $rc6ThreatModelPath

$sourceBindings = [ordered]@{
    rc5_final_audit_sha256 = $rc5FinalAuditHash
    rc5_support_recovery_result_sha256 = $rc5SupportResultHash
    rc5_canary_proof_result_sha256 = $rc5CanaryResultHash
    rc6_payload_channel_contract_sha256 = $rc6ContractHash
    rc6_bootstrap_installer_boundary_sha256 = $rc6BoundaryHash
    rc6_tls_storage_signed_payload_threat_model_sha256 = $rc6ThreatModelHash
}

$metadataSizePolicy = [ordered]@{
    health_json_bytes = 32768
    mirror_json_bytes = 65536
    channel_index_json_bytes = 131072
    payloads_index_json_bytes = 262144
    per_release_manifest_checksum_signature_json_bytes = 524288
    install_bootstrap_json_bytes = 131072
}

$payloadManifest = [ordered]@{
    schema = "agentos.rc6-payload-manifest.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    status = "metadata-preview"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc6"
    install_allowed = $false
    activation_allowed = $false
    payload_storage_mode = "metadata-only"
    large_artifact_storage_deferred = $true
    source_bindings = $sourceBindings
    payloads = @(
        [ordered]@{
            id = "aios-installable-system-image"
            kind = "large-artifact"
            storage_status = "deferred"
            url = $null
            size_bytes = $null
            sha256 = $null
            required_before_install = $true
            blocked_by = @("storage-policy-not-upgraded", "payload-signature-not-published")
        },
        [ordered]@{
            id = "aios-release-metadata-bundle"
            kind = "metadata-bundle"
            storage_status = "hosted"
            paths = @("/health.json", "/.well-known/aios/mirror.json", "/channel/index.json", "/install/bootstrap.json")
            required_before_install = $true
        }
    )
    trust_requirements = @(
        "schema-verification",
        "production-ready-false",
        "rc5-final-audit-binding",
        "payload-manifest-hash",
        "payload-content-hashes",
        "public-signature-or-signed-metadata-reference",
        "revocation-snapshot",
        "freshness-window",
        "installer-compatibility-contract",
        "rollback-baseline"
    )
    forbidden_authority = @(
        "signing",
        "install",
        "activation",
        "rollback-execution",
        "active-slot-mutation",
        "production-ring-mutation",
        "support-upload",
        "remote-dispatch",
        "tui-authority"
    )
}
$payloadManifestText = Get-JsonText $payloadManifest
$payloadManifestHash = Get-StringSha256 $payloadManifestText

$payloadChecksums = [ordered]@{
    schema = "agentos.rc6-payload-checksums.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    production_ready_claim = $false
    manifest_sha256 = $payloadManifestHash
    payload_file_hashes = @()
    metadata_hashes = [ordered]@{
        rc5_final_audit_sha256 = $rc5FinalAuditHash
        rc5_support_recovery_result_sha256 = $rc5SupportResultHash
        rc5_canary_proof_result_sha256 = $rc5CanaryResultHash
        rc6_contract_sha256 = $rc6ContractHash
        rc6_boundary_sha256 = $rc6BoundaryHash
        rc6_threat_model_sha256 = $rc6ThreatModelHash
    }
    large_payload_hashes_deferred = $true
    install_allowed = $false
}
$payloadChecksumsText = Get-JsonText $payloadChecksums
$payloadChecksumsHash = Get-StringSha256 $payloadChecksumsText

$payloadSignatures = [ordered]@{
    schema = "agentos.rc6-payload-signatures.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    status = "signature-required-before-install"
    production_ready_claim = $false
    signature_available = $false
    install_allowed = $false
    activation_allowed = $false
    signing_authority_on_mirror = $false
    placeholder_is_authority = $false
    required_signature_bindings = @(
        "release-id",
        "payload-manifest-sha256",
        "payload-checksums-sha256",
        "revocation-snapshot-sha256",
        "policy-version",
        "expiry"
    )
    blocking_reason = "No public detached signature or signed metadata reference has been published for this RC6 metadata preview."
}
$payloadSignaturesText = Get-JsonText $payloadSignatures
$payloadSignaturesHash = Get-StringSha256 $payloadSignaturesText

$payloadIndex = [ordered]@{
    schema = "agentos.rc6-payload-index.v1"
    generated_at = $generatedAt
    status = "metadata-preview"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc6"
    storage_mode = "metadata-only"
    large_artifact_storage_deferred = $true
    tls_required_before_ga_claim = $true
    entries = @(
        [ordered]@{
            id = $releaseId
            release_id = $releaseId
            status = "verification-blocked"
            reason = "Large payload storage and public signature are deferred."
            manifest_path = "$payloadBasePath/manifest.json"
            checksums_path = "$payloadBasePath/checksums.json"
            signatures_path = "$payloadBasePath/signatures.json"
            manifest_sha256 = $payloadManifestHash
            checksums_sha256 = $payloadChecksumsHash
            signatures_sha256 = $payloadSignaturesHash
            install_allowed = $false
            activation_allowed = $false
            rollback_execution_allowed = $false
            large_payload_deferred = $true
        }
    )
    source_bindings = $sourceBindings
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        support_upload_authority = $false
        tui_authority = $false
    }
}
$payloadIndexText = Get-JsonText $payloadIndex
$payloadIndexHash = Get-StringSha256 $payloadIndexText

$installBootstrap = [ordered]@{
    schema = "agentos.rc6-install-bootstrap.v1"
    generated_at = $generatedAt
    status = "metadata-preflight-only"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc6"
    default_release_id = $releaseId
    payload_index_path = "/payloads/index.json"
    installer_states = @("metadata-unavailable", "metadata-candidate", "verification-blocked", "install-preflight-ready", "install-authorized", "installed")
    rc6_allowed_states = @("metadata-unavailable", "metadata-candidate", "verification-blocked", "install-preflight-ready")
    current_state = "verification-blocked"
    install_allowed = $false
    activation_allowed = $false
    tls_required_before_ga_claim = $true
    storage_policy = "metadata-only"
    metadata_size_policy = $metadataSizePolicy
    endpoints = [ordered]@{
        health = "/health.json"
        mirror_descriptor = "/.well-known/aios/mirror.json"
        channel_index = "/channel/index.json"
        bootstrap_manifest = "/bootstrap/manifest.json"
        payload_index = "/payloads/index.json"
        payload_manifest = "$payloadBasePath/manifest.json"
        payload_checksums = "$payloadBasePath/checksums.json"
        payload_signatures = "$payloadBasePath/signatures.json"
        support_index = "/support/index.json"
        support_recovery = "/support/recovery.json"
    }
    blockers = @(
        "tls-not-yet-ga-gated",
        "large-payload-storage-deferred",
        "payload-signature-not-published",
        "revocation-snapshot-not-published",
        "installer-compatibility-contract-pending",
        "rollback-execution-drill-pending",
        "exact-operator-approval-pending"
    )
    forbidden_authority = $payloadManifest.forbidden_authority
}
$installBootstrapText = Get-JsonText $installBootstrap
$installBootstrapHash = Get-StringSha256 $installBootstrapText

$health = [ordered]@{
    schema = "agentos.rc6-hosted-mirror-health.v1"
    status = "rc6-metadata-portal-ready"
    service = "aios-hosted-mirror"
    domain = $Domain
    generated_at = $generatedAt
    workflow = "WFS-20260608-agentos-production-distro-rc6"
    production_ready_claim = $false
    storage_mode = "metadata-only"
    large_artifact_storage_deferred = $true
    payload_metadata_available = $true
    install_bootstrap_available = $true
    tls_required_before_ga_claim = $true
    signing_authority = $false
    activation_authority = $false
    rollback_execution_authority = $false
    active_slot_mutation_authority = $false
    production_ring_mutation_authority = $false
    support_upload_authority = $false
}
$healthText = Get-JsonText $health
$healthHash = Get-StringSha256 $healthText

$descriptor = [ordered]@{
    schema = "agentos.rc6-hosted-mirror-descriptor.v1"
    status = "rc6-metadata-portal-ready"
    service = "aios-hosted-mirror"
    domain = $Domain
    generated_at = $generatedAt
    workflow = "WFS-20260608-agentos-production-distro-rc6"
    static_root = "/srv/aios-mirror"
    storage_mode = "metadata-only"
    allowed_paths = @(
        "/",
        "/assets/",
        "/health.json",
        "/.well-known/aios/mirror.json",
        "/channel/index.json",
        "/channel/user-release.json",
        "/bootstrap/manifest.json",
        "/install/bootstrap.json",
        "/payloads/",
        "/support/",
        "/releases/"
    )
    disallowed_authority = @(
        "signing",
        "install",
        "activation",
        "rollback-execution",
        "active-slot-mutation",
        "production-ring-mutation",
        "remote-dispatch",
        "support-upload",
        "tui-authority",
        "shell-authority",
        "model-replay-authority"
    )
    frontend = [ordered]@{
        path = "/"
        assets = @("/assets/mirror.css", "/assets/mirror.js")
        external_dependencies = $false
        renders_payload_metadata = $true
        renders_install_bootstrap = $true
    }
    freshness_window = "P7D"
    production_ready_claim = $false
    tls_required_before_ga_claim = $true
}
$descriptorText = Get-JsonText $descriptor
$descriptorHash = Get-StringSha256 $descriptorText

$channelBeforeResponse = Invoke-Curl "http://$Domain/channel/index.json"
$channelBefore = ConvertFrom-JsonTextSafe $channelBeforeResponse.body
$existingEntries = @()
if ($null -ne $channelBefore -and $null -ne $channelBefore.entries) {
    $existingEntries = @($channelBefore.entries | Where-Object {
        $_.path -notin @("/payloads/index.json", "/install/bootstrap.json", "$payloadBasePath/manifest.json", "$payloadBasePath/checksums.json", "$payloadBasePath/signatures.json")
    })
}

$newEntries = @(
    [ordered]@{
        id = "rc6-payload-index"
        status = "available"
        path = "/payloads/index.json"
        kind = "payload-metadata-index"
        sha256 = $payloadIndexHash
        install_allowed = $false
        activation_allowed = $false
        large_payload_deferred = $true
    },
    [ordered]@{
        id = "rc6-install-bootstrap"
        status = "available"
        path = "/install/bootstrap.json"
        kind = "installer-bootstrap-metadata"
        sha256 = $installBootstrapHash
        install_allowed = $false
        activation_allowed = $false
        large_payload_deferred = $true
    },
    [ordered]@{
        id = "rc6-payload-manifest"
        status = "verification-blocked"
        path = "$payloadBasePath/manifest.json"
        kind = "payload-manifest"
        sha256 = $payloadManifestHash
        install_allowed = $false
        activation_allowed = $false
        large_payload_deferred = $true
    },
    [ordered]@{
        id = "rc6-payload-signatures"
        status = "signature-required"
        path = "$payloadBasePath/signatures.json"
        kind = "payload-signature-metadata"
        sha256 = $payloadSignaturesHash
        signature_available = $false
        install_allowed = $false
        activation_allowed = $false
    }
)

$hostedChannel = [ordered]@{
    schema = "agentos.rc6-hosted-channel-index.v1"
    status = "metadata-only"
    channel = "production-candidate-rc6"
    domain = $Domain
    generated_at = $generatedAt
    production_ready_claim = $false
    storage_mode = "metadata-only"
    source_rc4_final_audit_sha256 = if ($null -ne $channelBefore) { $channelBefore.source_rc4_final_audit_sha256 } else { $null }
    hosted_transport_manifest_sha256 = if ($null -ne $channelBefore) { $channelBefore.hosted_transport_manifest_sha256 } else { $null }
    mirror_publication_sha256 = if ($null -ne $channelBefore) { $channelBefore.mirror_publication_sha256 } else { $null }
    freshness_window = "P7D"
    entries = @($existingEntries + $newEntries)
    support_recovery = if ($null -ne $channelBefore) { $channelBefore.support_recovery } else { $null }
    payload_channel = [ordered]@{
        index_path = "/payloads/index.json"
        install_bootstrap_path = "/install/bootstrap.json"
        default_release_id = $releaseId
        payload_index_sha256 = $payloadIndexHash
        install_bootstrap_sha256 = $installBootstrapHash
        metadata_only = $true
        large_artifact_storage_deferred = $true
        signature_available = $false
        install_allowed = $false
    }
    authority = [ordered]@{
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        tui_authority = $false
    }
}
$hostedChannelText = Get-JsonText $hostedChannel
$hostedChannelHash = Get-StringSha256 $hostedChannelText

$indexHtml = @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>AIOS Mirror Portal</title>
  <link rel="stylesheet" href="/assets/mirror.css">
</head>
<body>
  <div id="mirror-app" class="app-shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="AIOS mirror home">
        <span class="brand-mark" aria-hidden="true"><span></span></span>
        <span class="brand-copy">
          <strong>AIOS Mirror</strong>
          <small>aios.w33d.xyz</small>
        </span>
      </a>
      <nav class="nav" aria-label="Mirror metadata">
        <a href="/channel/index.json">Channel</a>
        <a href="/payloads/index.json">Payloads</a>
        <a href="/install/bootstrap.json">Install</a>
        <a href="/support/index.json">Support</a>
      </nav>
    </header>

    <main>
      <section class="hero" aria-labelledby="hero-title">
        <div class="hero-copy">
          <p class="eyebrow">Production Distro RC6</p>
          <h1 id="hero-title">AIOS public mirror portal</h1>
          <p class="lede">Inspectable metadata for bootstrap, payload discovery, support recovery, and local verification.</p>
        </div>
        <div class="hero-status" aria-label="Mirror status">
          <span id="service-status" class="pill neutral">Loading</span>
          <span id="tls-status" class="pill warn">TLS gate</span>
          <span id="storage-status" class="pill neutral">metadata-only</span>
        </div>
      </section>

      <section class="metrics" aria-label="Mirror summary">
        <article>
          <span>Channel</span>
          <strong id="channel-name">-</strong>
          <small id="channel-state">-</small>
        </article>
        <article>
          <span>Payload</span>
          <strong id="payload-state">-</strong>
          <small id="signature-state">-</small>
        </article>
        <article>
          <span>Installer</span>
          <strong id="installer-state">-</strong>
          <small id="install-authority">-</small>
        </article>
        <article>
          <span>Authority</span>
          <strong id="authority-state">transport only</strong>
          <small id="ga-state">non-GA</small>
        </article>
      </section>

      <section class="workspace">
        <article class="panel map-panel">
          <div class="panel-head">
            <h2>Trust Path</h2>
            <span id="path-caption">local verification required</span>
          </div>
          <canvas id="trust-map" width="1000" height="320" aria-label="AIOS mirror trust path"></canvas>
        </article>

        <article class="panel gate-panel">
          <div class="panel-head">
            <h2>Install Gates</h2>
            <span id="gate-count">0 gates</span>
          </div>
          <ul id="gate-list" class="gate-list"></ul>
        </article>
      </section>

      <section class="split">
        <article class="panel">
          <div class="panel-head">
            <h2>Payload Channel</h2>
            <span id="payload-count">0 entries</span>
          </div>
          <div id="payload-list" class="payload-list"></div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <h2>Metadata Endpoints</h2>
            <span id="endpoint-count">0 endpoints</span>
          </div>
          <div id="endpoint-grid" class="endpoint-grid"></div>
        </article>
      </section>

      <section class="panel table-panel">
        <div class="panel-head">
          <h2>Directory</h2>
          <span id="directory-count">0 rows</span>
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
    </main>
  </div>
  <script src="/assets/mirror.js"></script>
</body>
</html>
'@

$css = @'
:root {
  --bg: #f6f8fb;
  --panel: #ffffff;
  --ink: #17202e;
  --muted: #637083;
  --line: #dbe2ec;
  --soft: #eef3f8;
  --green: #1d7f55;
  --green-soft: #e7f6ee;
  --blue: #2563a8;
  --blue-soft: #e8f1fb;
  --amber: #a76400;
  --amber-soft: #fff3d8;
  --red: #b42318;
  --red-soft: #fde8e5;
  --shadow: 0 18px 50px rgba(28, 44, 68, 0.10);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

a { color: inherit; }

.app-shell {
  min-height: 100vh;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  min-height: 72px;
  padding: 14px clamp(18px, 4vw, 48px);
  border-bottom: 1px solid rgba(219, 226, 236, 0.88);
  background: rgba(246, 248, 251, 0.92);
  backdrop-filter: blur(14px);
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  text-decoration: none;
}

.brand-mark {
  width: 40px;
  height: 40px;
  display: grid;
  place-items: center;
  border: 1px solid #c9d5e4;
  background: linear-gradient(145deg, #ffffff, #e7eef7);
  border-radius: 8px;
}

.brand-mark span {
  width: 20px;
  height: 20px;
  display: block;
  border: 3px solid var(--blue);
  border-top-color: var(--green);
  transform: rotate(45deg);
}

.brand-copy {
  display: grid;
}

.brand strong {
  font-size: 17px;
  letter-spacing: 0;
}

.brand small {
  color: var(--muted);
}

.nav {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.nav a {
  min-height: 36px;
  padding: 8px 10px;
  border-radius: 6px;
  color: #344154;
  text-decoration: none;
}

.nav a:hover {
  background: var(--soft);
}

main {
  width: min(1240px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 52px;
}

.hero {
  min-height: 250px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: 28px;
  padding: clamp(26px, 5vw, 54px);
  border: 1px solid #cfd9e7;
  border-radius: 8px;
  background:
    linear-gradient(135deg, rgba(255,255,255,0.96), rgba(235,242,250,0.90)),
    repeating-linear-gradient(90deg, rgba(37,99,168,0.08) 0 1px, transparent 1px 76px),
    repeating-linear-gradient(0deg, rgba(29,127,85,0.07) 0 1px, transparent 1px 76px);
  box-shadow: var(--shadow);
}

.eyebrow {
  margin: 0 0 10px;
  color: var(--blue);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0;
  font-size: 12px;
}

h1, h2, p { margin-top: 0; }

h1 {
  max-width: 760px;
  margin-bottom: 14px;
  font-size: clamp(38px, 7vw, 76px);
  line-height: 0.96;
  letter-spacing: 0;
}

.lede {
  max-width: 700px;
  margin-bottom: 0;
  color: #435166;
  font-size: 18px;
}

.hero-status {
  min-width: 210px;
  display: grid;
  gap: 10px;
}

.pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 34px;
  padding: 7px 12px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--soft);
  color: #344154;
  font-weight: 700;
  white-space: nowrap;
}

.pill.good { border-color: #b8e0cd; background: var(--green-soft); color: var(--green); }
.pill.warn { border-color: #f2d399; background: var(--amber-soft); color: var(--amber); }
.pill.bad { border-color: #f5b7b1; background: var(--red-soft); color: var(--red); }
.pill.neutral { border-color: #cfd9e7; background: #eef3f8; color: #42516a; }

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin: 18px 0;
}

.metrics article,
.panel {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 12px 35px rgba(28, 44, 68, 0.06);
}

.metrics article {
  min-height: 118px;
  display: grid;
  align-content: center;
  gap: 4px;
  padding: 18px;
}

.metrics span,
.metrics small,
.panel-head span,
td {
  color: var(--muted);
}

.metrics strong {
  min-width: 0;
  overflow-wrap: anywhere;
  font-size: 23px;
  line-height: 1.1;
}

.workspace {
  display: grid;
  grid-template-columns: minmax(0, 1.7fr) minmax(300px, 0.8fr);
  gap: 18px;
  margin-bottom: 18px;
}

.split {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 18px;
  margin-bottom: 18px;
}

.panel {
  min-width: 0;
  padding: 18px;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.panel h2 {
  margin: 0;
  font-size: 18px;
  letter-spacing: 0;
}

#trust-map {
  width: 100%;
  height: auto;
  aspect-ratio: 25 / 8;
  display: block;
  border: 1px solid #d8e1ec;
  border-radius: 8px;
  background: #f8fbff;
}

.gate-list {
  display: grid;
  gap: 10px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.gate-list li,
.payload-card,
.endpoint-card {
  border: 1px solid #dfe7f1;
  border-radius: 8px;
  background: #fbfdff;
}

.gate-list li {
  display: grid;
  grid-template-columns: 12px minmax(0, 1fr);
  align-items: start;
  gap: 10px;
  padding: 11px 12px;
}

.gate-list i {
  width: 10px;
  height: 10px;
  margin-top: 6px;
  border-radius: 50%;
  background: var(--amber);
}

.gate-list b,
.payload-card b,
.endpoint-card b {
  display: block;
  overflow-wrap: anywhere;
}

.gate-list small,
.payload-card small,
.endpoint-card small {
  color: var(--muted);
}

.payload-list,
.endpoint-grid {
  display: grid;
  gap: 10px;
}

.payload-card,
.endpoint-card {
  padding: 12px;
}

.payload-card {
  display: grid;
  gap: 8px;
}

.payload-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.payload-meta code,
.endpoint-card code {
  display: inline-block;
  max-width: 100%;
  overflow-wrap: anywhere;
  padding: 3px 6px;
  border-radius: 5px;
  background: #eef3f8;
  color: #26354a;
}

.endpoint-card {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
}

.endpoint-card a {
  color: var(--blue);
  text-decoration: none;
  font-weight: 700;
}

.table-panel {
  margin-bottom: 20px;
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 12px 10px;
  border-top: 1px solid #e4ebf3;
  text-align: left;
  vertical-align: top;
}

th {
  color: #344154;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0;
}

td code {
  overflow-wrap: anywhere;
}

@media (max-width: 860px) {
  .topbar,
  .hero,
  .workspace,
  .split,
  .metrics {
    grid-template-columns: 1fr;
  }

  .topbar {
    align-items: flex-start;
  }

  .hero {
    min-height: 0;
  }

  h1 {
    font-size: 42px;
  }

  .hero-status {
    min-width: 0;
  }
}

@media (max-width: 560px) {
  main {
    width: min(100% - 20px, 1240px);
    padding-top: 16px;
  }

  .topbar {
    padding: 12px;
  }

  .nav {
    justify-content: flex-start;
  }

  .hero,
  .panel,
  .metrics article {
    padding: 14px;
  }

  h1 {
    font-size: 34px;
  }

  .endpoint-card {
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
  installBootstrap: null,
  support: null
};

const endpointDefinitions = [
  { id: "health", label: "Health", path: "/health.json", type: "status" },
  { id: "descriptor", label: "Descriptor", path: "/.well-known/aios/mirror.json", type: "service" },
  { id: "channel", label: "Channel", path: "/channel/index.json", type: "index" },
  { id: "bootstrap", label: "Bootstrap", path: "/bootstrap/manifest.json", type: "legacy bootstrap" },
  { id: "install", label: "Install Bootstrap", path: "/install/bootstrap.json", type: "installer metadata" },
  { id: "payloads", label: "Payloads", path: "/payloads/index.json", type: "payload metadata" },
  { id: "support", label: "Support", path: "/support/index.json", type: "support metadata" },
  { id: "recovery", label: "Recovery", path: "/support/recovery.json", type: "recovery metadata" }
];

function $(id) {
  return document.getElementById(id);
}

function text(id, value) {
  const node = $(id);
  if (node) node.textContent = value == null || value === "" ? "-" : String(value);
}

function setPill(id, value, kind) {
  const node = $(id);
  if (!node) return;
  node.textContent = value;
  node.className = `pill ${kind || "neutral"}`;
}

async function loadJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} ${response.status}`);
  return response.json();
}

function boolLabel(value) {
  return value ? "allowed" : "blocked";
}

function shortHash(value) {
  if (!value) return "-";
  return `${String(value).slice(0, 12)}...${String(value).slice(-8)}`;
}

function renderMetrics() {
  const channel = state.channel || {};
  const payloadEntry = state.payloadIndex?.entries?.[0] || {};
  const signature = payloadEntry.signatures_sha256 ? "signature metadata present" : "signature metadata missing";
  const signatureAllowed = state.payloadIndex?.entries?.some((entry) => entry.install_allowed === true);
  const install = state.installBootstrap || {};

  text("channel-name", channel.channel || "production-candidate-rc6");
  text("channel-state", channel.status || "metadata-only");
  text("payload-state", payloadEntry.status || state.payloadIndex?.status || "metadata-preview");
  text("signature-state", signatureAllowed ? "signed install candidate" : signature);
  text("installer-state", install.current_state || install.status || "verification-blocked");
  text("install-authority", `install ${boolLabel(install.install_allowed === true)}`);
  text("authority-state", "transport only");
  text("ga-state", channel.production_ready_claim ? "GA claim present" : "non-GA");

  const healthy = state.health?.status && state.channel?.status;
  setPill("service-status", healthy ? "metadata online" : "metadata partial", healthy ? "good" : "warn");
  setPill("tls-status", state.health?.tls_required_before_ga_claim ? "TLS required before GA" : "TLS verified", state.health?.tls_required_before_ga_claim ? "warn" : "good");
  setPill("storage-status", state.health?.storage_mode || "metadata-only", "neutral");
}

function renderGates() {
  const gates = [
    { name: "TLS GA gate", detail: state.installBootstrap?.tls_required_before_ga_claim ? "required before GA" : "verified" },
    { name: "Large payload storage", detail: state.payloadIndex?.large_artifact_storage_deferred ? "deferred by policy" : "policy upgraded" },
    { name: "Payload signature", detail: state.payloadIndex?.entries?.[0]?.status || "verification-blocked" },
    { name: "Revocation snapshot", detail: "required before install" },
    { name: "Rollback baseline", detail: "required before activation" },
    { name: "Exact operator approval", detail: "required before canary execution" }
  ];
  const list = $("gate-list");
  list.innerHTML = "";
  gates.forEach((gate) => {
    const li = document.createElement("li");
    li.innerHTML = `<i aria-hidden="true"></i><span><b>${gate.name}</b><small>${gate.detail}</small></span>`;
    list.appendChild(li);
  });
  text("gate-count", `${gates.length} gates`);
}

function renderPayloads() {
  const list = $("payload-list");
  const entries = state.payloadIndex?.entries || [];
  list.innerHTML = "";
  entries.forEach((entry) => {
    const card = document.createElement("div");
    card.className = "payload-card";
    card.innerHTML = `
      <div>
        <b>${entry.release_id || entry.id}</b>
        <small>${entry.reason || entry.status}</small>
      </div>
      <div class="payload-meta">
        <code>${entry.manifest_path || "-"}</code>
        <code>${entry.status || "metadata"}</code>
        <code>install ${boolLabel(entry.install_allowed === true)}</code>
      </div>
      <small>manifest ${shortHash(entry.manifest_sha256)} / signatures ${shortHash(entry.signatures_sha256)}</small>
    `;
    list.appendChild(card);
  });
  if (entries.length === 0) {
    const empty = document.createElement("div");
    empty.className = "payload-card";
    empty.innerHTML = "<b>No payload metadata</b><small>Payload index did not return entries.</small>";
    list.appendChild(empty);
  }
  text("payload-count", `${entries.length} entries`);
}

function renderEndpoints() {
  const grid = $("endpoint-grid");
  grid.innerHTML = "";
  endpointDefinitions.forEach((endpoint) => {
    const card = document.createElement("div");
    card.className = "endpoint-card";
    card.innerHTML = `
      <span><b>${endpoint.label}</b><small>${endpoint.type}</small></span>
      <a href="${endpoint.path}"><code>${endpoint.path}</code></a>
    `;
    grid.appendChild(card);
  });
  text("endpoint-count", `${endpointDefinitions.length} endpoints`);
}

function renderDirectory() {
  const rows = [
    { path: "/", type: "portal", status: "static", authority: "read-only" },
    { path: "/health.json", type: "health", status: state.health?.status || "metadata", authority: "read-only" },
    { path: "/.well-known/aios/mirror.json", type: "descriptor", status: state.descriptor?.status || "metadata", authority: "read-only" },
    { path: "/channel/index.json", type: "channel", status: state.channel?.status || "metadata-only", authority: "candidate only" },
    { path: "/payloads/index.json", type: "payload index", status: state.payloadIndex?.status || "metadata-preview", authority: "candidate only" },
    { path: "/install/bootstrap.json", type: "installer bootstrap", status: state.installBootstrap?.status || "metadata-preflight-only", authority: "no side effects" },
    { path: "/support/index.json", type: "support", status: state.support?.status || "metadata-only", authority: "no upload" }
  ];
  const body = $("directory-rows");
  body.innerHTML = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><code>${row.path}</code></td><td>${row.type}</td><td>${row.status}</td><td>${row.authority}</td>`;
    body.appendChild(tr);
  });
  text("directory-count", `${rows.length} rows`);
}

function drawTrustMap() {
  const canvas = $("trust-map");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const scale = window.devicePixelRatio || 1;
  canvas.width = Math.max(900, Math.floor(rect.width * scale));
  canvas.height = Math.floor(canvas.width * 0.32);
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#f8fbff";
  ctx.fillRect(0, 0, w, h);

  const nodes = [
    { label: "Mirror", detail: "static metadata", x: 0.10, y: 0.48, color: "#2563a8" },
    { label: "Payload index", detail: "hash bound", x: 0.32, y: 0.30, color: "#1d7f55" },
    { label: "Installer", detail: "preflight only", x: 0.55, y: 0.58, color: "#a76400" },
    { label: "Approval", detail: "not granted", x: 0.76, y: 0.34, color: "#b42318" },
    { label: "Activation", detail: "blocked", x: 0.90, y: 0.60, color: "#637083" }
  ];

  ctx.lineWidth = Math.max(2, w * 0.003);
  ctx.strokeStyle = "#c7d4e4";
  ctx.beginPath();
  nodes.forEach((node, index) => {
    const x = node.x * w;
    const y = node.y * h;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  nodes.forEach((node) => {
    const x = node.x * w;
    const y = node.y * h;
    const radius = Math.max(26, w * 0.035);
    ctx.beginPath();
    ctx.fillStyle = "#ffffff";
    ctx.strokeStyle = node.color;
    ctx.lineWidth = Math.max(3, w * 0.004);
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = "#17202e";
    ctx.font = `700 ${Math.max(16, w * 0.018)}px system-ui, sans-serif`;
    ctx.textAlign = "center";
    ctx.fillText(node.label, x, y + radius + Math.max(22, w * 0.024));
    ctx.fillStyle = "#637083";
    ctx.font = `500 ${Math.max(13, w * 0.014)}px system-ui, sans-serif`;
    ctx.fillText(node.detail, x, y + radius + Math.max(42, w * 0.044));
  });
}

function render() {
  renderMetrics();
  renderGates();
  renderPayloads();
  renderEndpoints();
  renderDirectory();
  drawTrustMap();
}

async function boot() {
  try {
    const [health, descriptor, channel, payloadIndex, installBootstrap, support] = await Promise.all([
      loadJson("/health.json"),
      loadJson("/.well-known/aios/mirror.json"),
      loadJson("/channel/index.json"),
      loadJson("/payloads/index.json"),
      loadJson("/install/bootstrap.json"),
      loadJson("/support/index.json").catch(() => null)
    ]);
    state.health = health;
    state.descriptor = descriptor;
    state.channel = channel;
    state.payloadIndex = payloadIndex;
    state.installBootstrap = installBootstrap;
    state.support = support;
    render();
  } catch (error) {
    setPill("service-status", "metadata unavailable", "bad");
    text("channel-state", error.message);
    renderEndpoints();
    drawTrustMap();
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
    add_header X-AIOS-Mirror "rc6-metadata-portal" always;
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

    location /channel/ {
        default_type application/json;
        autoindex off;
        add_header Cache-Control "no-cache" always;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /bootstrap/ {
        default_type application/json;
        autoindex off;
        add_header Cache-Control "no-cache" always;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /install/ {
        default_type application/json;
        autoindex off;
        add_header Cache-Control "no-cache" always;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /payloads/ {
        default_type application/json;
        autoindex off;
        add_header Cache-Control "no-cache" always;
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
    health = Join-Path $resolvedArtifactDir "health.json"
    descriptor = Join-Path $resolvedArtifactDir "mirror-descriptor.json"
    channel = Join-Path $resolvedArtifactDir "hosted-channel-index.json"
    payload_index = Join-Path $resolvedArtifactDir "payloads-index.json"
    payload_manifest = Join-Path $resolvedArtifactDir "payload-manifest.json"
    payload_checksums = Join-Path $resolvedArtifactDir "payload-checksums.json"
    payload_signatures = Join-Path $resolvedArtifactDir "payload-signatures.json"
    install_bootstrap = Join-Path $resolvedArtifactDir "install-bootstrap.json"
    nginx = Join-Path $resolvedArtifactDir "nginx-aios.w33d.xyz.conf"
}

Write-TextFile -Path $localFiles.index_html -Text $indexHtml
Write-TextFile -Path $localFiles.mirror_css -Text $css
Write-TextFile -Path $localFiles.mirror_js -Text $js
Write-TextFile -Path $localFiles.nginx -Text $nginxConfig
Write-Json -Value $health -Path $localFiles.health
Write-Json -Value $descriptor -Path $localFiles.descriptor
Write-Json -Value $hostedChannel -Path $localFiles.channel
Write-Json -Value $payloadIndex -Path $localFiles.payload_index
Write-Json -Value $payloadManifest -Path $localFiles.payload_manifest
Write-Json -Value $payloadChecksums -Path $localFiles.payload_checksums
Write-Json -Value $payloadSignatures -Path $localFiles.payload_signatures
Write-Json -Value $installBootstrap -Path $localFiles.install_bootstrap

$localOutputPaths = @($localFiles.Values)
$localOutputsReady = @($localOutputPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -eq @($localOutputPaths).Count
$localOutputsSafe = Test-NoSensitiveFiles -Paths $localOutputPaths
$localMetadataSizeReady = ((Get-Item -LiteralPath $localFiles.health).Length -le $metadataSizePolicy.health_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.descriptor).Length -le $metadataSizePolicy.mirror_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.channel).Length -le $metadataSizePolicy.channel_index_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.payload_index).Length -le $metadataSizePolicy.payloads_index_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.payload_manifest).Length -le $metadataSizePolicy.per_release_manifest_checksum_signature_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.payload_checksums).Length -le $metadataSizePolicy.per_release_manifest_checksum_signature_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.payload_signatures).Length -le $metadataSizePolicy.per_release_manifest_checksum_signature_json_bytes) -and
    ((Get-Item -LiteralPath $localFiles.install_bootstrap).Length -le $metadataSizePolicy.install_bootstrap_json_bytes)

Add-Check "local.outputs.ready" $localOutputsReady "RC6 mirror portal and metadata outputs must be generated locally before remote publication." ([ordered]@{ files = @($localFiles.Keys) })
Add-Check "local.outputs.secret_safe" $localOutputsSafe "Generated portal and metadata must not contain private key or token markers." $null
Add-Check "local.metadata_size_policy" $localMetadataSizeReady "Generated metadata must fit RC6 metadata-only size ceilings." ([ordered]@{
    health = (Get-Item -LiteralPath $localFiles.health).Length
    descriptor = (Get-Item -LiteralPath $localFiles.descriptor).Length
    channel = (Get-Item -LiteralPath $localFiles.channel).Length
    payload_index = (Get-Item -LiteralPath $localFiles.payload_index).Length
    install_bootstrap = (Get-Item -LiteralPath $localFiles.install_bootstrap).Length
})
Add-Check "channel.before.available" ($channelBeforeResponse.status_code -eq 200 -and $null -ne $channelBefore) "Existing channel index must be reachable before RC6 publication." ([ordered]@{ status_code = $channelBeforeResponse.status_code })
Add-Check "source.bindings.present" ($rc5FinalAuditHash -and $rc5SupportResultHash -and $rc5CanaryResultHash -and $rc6ContractHash -and $rc6BoundaryHash -and $rc6ThreatModelHash) "RC6 metadata must bind RC5 final evidence and RC6 boundary documents." $sourceBindings
Add-Check "payload.no_install_authority" ($payloadIndex.entries[0].install_allowed -eq $false -and $payloadSignatures.signature_available -eq $false -and $payloadSignatures.signing_authority_on_mirror -eq $false) "Payload metadata must remain verification-blocked until signatures and storage policy exist." ([ordered]@{ entry = $payloadIndex.entries[0].status; signature_available = $payloadSignatures.signature_available })
Add-Check "install.bootstrap.no_side_effects" ($installBootstrap.install_allowed -eq $false -and $installBootstrap.activation_allowed -eq $false -and $installBootstrap.current_state -eq "verification-blocked") "Install bootstrap must remain metadata-preflight-only." ([ordered]@{ state = $installBootstrap.current_state; blockers = $installBootstrap.blockers })

Set-RemoteTextFile -Path "/srv/aios-mirror/index.html" -Text $indexHtml
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.css" -Text $css
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.js" -Text $js
Set-RemoteTextFile -Path "/srv/aios-mirror/health.json" -Text $healthText
Set-RemoteTextFile -Path "/srv/aios-mirror/.well-known/aios/mirror.json" -Text $descriptorText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text $hostedChannelText
Set-RemoteTextFile -Path "/srv/aios-mirror/payloads/index.json" -Text $payloadIndexText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/manifest.json" -Text $payloadManifestText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/checksums.json" -Text $payloadChecksumsText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/signatures.json" -Text $payloadSignaturesText
Set-RemoteTextFile -Path "/srv/aios-mirror/install/bootstrap.json" -Text $installBootstrapText
Set-RemoteTextFile -Path "/etc/nginx/sites-available/aios.w33d.xyz" -Text $nginxConfig

$remoteCheck = Invoke-Remote "set -eu; ln -sfn /etc/nginx/sites-available/aios.w33d.xyz /etc/nginx/sites-enabled/aios.w33d.xyz; nginx -t; systemctl reload nginx; systemctl is-active nginx; cd /srv/aios-mirror; find assets channel bootstrap install payloads support -maxdepth 4 -type f -printf '%P %s\n' | sort; sha256sum index.html assets/mirror.css assets/mirror.js health.json .well-known/aios/mirror.json channel/index.json payloads/index.json install/bootstrap.json $($payloadBasePath.TrimStart('/'))/manifest.json $($payloadBasePath.TrimStart('/'))/checksums.json $($payloadBasePath.TrimStart('/'))/signatures.json"

$indexResponse = Invoke-Curl "http://$Domain/"
$htmlResponse = Invoke-Curl "http://$Domain/index.html"
$cssResponse = Invoke-Curl "http://$Domain/assets/mirror.css"
$jsResponse = Invoke-Curl "http://$Domain/assets/mirror.js"
$healthResponse = Invoke-Curl "http://$Domain/health.json"
$descriptorResponse = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$payloadIndexResponse = Invoke-Curl "http://$Domain/payloads/index.json"
$payloadManifestResponse = Invoke-Curl "http://$Domain$payloadBasePath/manifest.json"
$payloadChecksumsResponse = Invoke-Curl "http://$Domain$payloadBasePath/checksums.json"
$payloadSignaturesResponse = Invoke-Curl "http://$Domain$payloadBasePath/signatures.json"
$installBootstrapResponse = Invoke-Curl "http://$Domain/install/bootstrap.json"
$supportResponse = Invoke-Curl "http://$Domain/support/index.json"
$payloadDirResponse = Invoke-Curl "http://$Domain/payloads/"
$postRootResponse = Invoke-Curl "http://$Domain/" -Method "POST"
$postPayloadResponse = Invoke-Curl "http://$Domain/payloads/index.json" -Method "POST"

$healthLive = ConvertFrom-JsonTextSafe $healthResponse.body
$descriptorLive = ConvertFrom-JsonTextSafe $descriptorResponse.body
$channelLive = ConvertFrom-JsonTextSafe $channelResponse.body
$payloadIndexLive = ConvertFrom-JsonTextSafe $payloadIndexResponse.body
$payloadManifestLive = ConvertFrom-JsonTextSafe $payloadManifestResponse.body
$payloadChecksumsLive = ConvertFrom-JsonTextSafe $payloadChecksumsResponse.body
$payloadSignaturesLive = ConvertFrom-JsonTextSafe $payloadSignaturesResponse.body
$installBootstrapLive = ConvertFrom-JsonTextSafe $installBootstrapResponse.body

$allRemoteHttpReady = $indexResponse.status_code -eq 200 -and
    $htmlResponse.status_code -eq 200 -and
    $cssResponse.status_code -eq 200 -and
    $jsResponse.status_code -eq 200 -and
    $healthResponse.status_code -eq 200 -and
    $descriptorResponse.status_code -eq 200 -and
    $channelResponse.status_code -eq 200 -and
    $payloadIndexResponse.status_code -eq 200 -and
    $payloadManifestResponse.status_code -eq 200 -and
    $payloadChecksumsResponse.status_code -eq 200 -and
    $payloadSignaturesResponse.status_code -eq 200 -and
    $installBootstrapResponse.status_code -eq 200 -and
    $supportResponse.status_code -eq 200

$remoteSemanticsReady = $null -ne $healthLive -and
    $null -ne $descriptorLive -and
    $null -ne $channelLive -and
    $null -ne $payloadIndexLive -and
    $null -ne $payloadManifestLive -and
    $null -ne $payloadChecksumsLive -and
    $null -ne $payloadSignaturesLive -and
    $null -ne $installBootstrapLive -and
    $healthLive.production_ready_claim -eq $false -and
    $payloadIndexLive.production_ready_claim -eq $false -and
    $payloadIndexLive.entries[0].install_allowed -eq $false -and
    $payloadManifestLive.install_allowed -eq $false -and
    $payloadChecksumsLive.install_allowed -eq $false -and
    $payloadSignaturesLive.signature_available -eq $false -and
    $payloadSignaturesLive.signing_authority_on_mirror -eq $false -and
    $installBootstrapLive.install_allowed -eq $false -and
    $installBootstrapLive.activation_allowed -eq $false -and
    $channelLive.payload_channel.install_allowed -eq $false -and
    (Has-FalseAuthority $channelLive.authority)

$frontendReady = $indexResponse.body -match 'AIOS Mirror Portal' -and
    $indexResponse.body -match 'id="mirror-app"' -and
    $jsResponse.body -match '/payloads/index.json' -and
    $jsResponse.body -match '/install/bootstrap.json' -and
    $jsResponse.body -match 'drawTrustMap' -and
    $cssResponse.body -match 'grid-template-columns'

$noExternalDeps = $indexResponse.body -notmatch 'https?://' -and
    $cssResponse.body -notmatch 'https?://' -and
    $jsResponse.body -notmatch 'https?://'

$remoteSecretSafe = Test-NoSensitiveText -Values @(
    $indexResponse.body,
    $cssResponse.body,
    $jsResponse.body,
    $healthResponse.body,
    $descriptorResponse.body,
    $channelResponse.body,
    $payloadIndexResponse.body,
    $payloadManifestResponse.body,
    $payloadChecksumsResponse.body,
    $payloadSignaturesResponse.body,
    $installBootstrapResponse.body
)

Add-Check "nginx.reload" ($remoteCheck -match "active") "Nginx must validate and reload with RC6 portal locations." ($remoteCheck -split "`n")
Add-Check "remote.http.ready" $allRemoteHttpReady "Portal assets and RC6 metadata endpoints must return HTTP 200 through resolve-pinned validation." ([ordered]@{
    root = $indexResponse.status_code
    css = $cssResponse.status_code
    js = $jsResponse.status_code
    health = $healthResponse.status_code
    descriptor = $descriptorResponse.status_code
    channel = $channelResponse.status_code
    payload_index = $payloadIndexResponse.status_code
    install_bootstrap = $installBootstrapResponse.status_code
})
Add-Check "remote.semantics.no_authority" $remoteSemanticsReady "Live RC6 metadata must remain non-GA, metadata-only, unsigned, and non-authoritative." ([ordered]@{
    payload_status = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].status } else { $null }
    signature_available = if ($null -ne $payloadSignaturesLive) { $payloadSignaturesLive.signature_available } else { $null }
    install_state = if ($null -ne $installBootstrapLive) { $installBootstrapLive.current_state } else { $null }
})
Add-Check "frontend.portal.ready" $frontendReady "Root frontend must render the RC6 mirror portal app shell, endpoint grid, and trust path." $null
Add-Check "frontend.no_external_dependencies" $noExternalDeps "Frontend must not depend on external scripts, styles, images, or fonts." $null
Add-Check "remote.secret_safe" $remoteSecretSafe "Remote portal and metadata responses must not expose private key or token markers." $null
Add-Check "remote.directory_listing.blocked" (@(403, 404) -contains $payloadDirResponse.status_code) "Payload directory listing must be blocked." $payloadDirResponse.status_code
Add-Check "remote.write_methods.blocked" ((@(403, 405) -contains $postRootResponse.status_code) -and (@(403, 405) -contains $postPayloadResponse.status_code)) "POST must be blocked for root and payload metadata." ([ordered]@{ root = $postRootResponse.status_code; payload_index = $postPayloadResponse.status_code })
$remoteHashBindingsReady = $null -ne $payloadIndexLive -and
    $null -ne $channelLive -and
    $null -ne $installBootstrapLive -and
    $payloadIndexLive.entries[0].manifest_sha256 -eq $payloadManifestHash -and
    $payloadIndexLive.entries[0].checksums_sha256 -eq $payloadChecksumsHash -and
    $payloadIndexLive.entries[0].signatures_sha256 -eq $payloadSignaturesHash -and
    $channelLive.payload_channel.payload_index_sha256 -eq $payloadIndexHash -and
    $channelLive.payload_channel.install_bootstrap_sha256 -eq $installBootstrapHash -and
    $installBootstrapLive.payload_index_path -eq "/payloads/index.json"

Add-Check "remote.hash_bindings.match" $remoteHashBindingsReady "Live RC6 metadata must carry the local projection hashes and endpoint bindings." ([ordered]@{
    manifest_expected = $payloadManifestHash
    manifest_live = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].manifest_sha256 } else { $null }
    checksums_expected = $payloadChecksumsHash
    checksums_live = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].checksums_sha256 } else { $null }
    signatures_expected = $payloadSignaturesHash
    signatures_live = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].signatures_sha256 } else { $null }
    channel_payload_index_expected = $payloadIndexHash
    channel_payload_index_live = if ($null -ne $channelLive) { $channelLive.payload_channel.payload_index_sha256 } else { $null }
    channel_install_bootstrap_expected = $installBootstrapHash
    channel_install_bootstrap_live = if ($null -ne $channelLive) { $channelLive.payload_channel.install_bootstrap_sha256 } else { $null }
})

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-mirror-portal-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC6-004"
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
    published_endpoints = @(
        "http://$Domain/",
        "http://$Domain/health.json",
        "http://$Domain/.well-known/aios/mirror.json",
        "http://$Domain/channel/index.json",
        "http://$Domain/payloads/index.json",
        "http://$Domain$payloadBasePath/manifest.json",
        "http://$Domain$payloadBasePath/checksums.json",
        "http://$Domain$payloadBasePath/signatures.json",
        "http://$Domain/install/bootstrap.json"
    )
    local_outputs = [ordered]@{
        index_html = Get-StablePath $localFiles.index_html
        mirror_css = Get-StablePath $localFiles.mirror_css
        mirror_js = Get-StablePath $localFiles.mirror_js
        health = Get-StablePath $localFiles.health
        descriptor = Get-StablePath $localFiles.descriptor
        channel = Get-StablePath $localFiles.channel
        payload_index = Get-StablePath $localFiles.payload_index
        payload_manifest = Get-StablePath $localFiles.payload_manifest
        payload_checksums = Get-StablePath $localFiles.payload_checksums
        payload_signatures = Get-StablePath $localFiles.payload_signatures
        install_bootstrap = Get-StablePath $localFiles.install_bootstrap
        nginx = Get-StablePath $localFiles.nginx
    }
    output_hashes = [ordered]@{
        index_html_sha256 = Get-StringSha256 $indexResponse.body
        mirror_css_sha256 = Get-StringSha256 $cssResponse.body
        mirror_js_sha256 = Get-StringSha256 $jsResponse.body
        health_sha256 = Get-StringSha256 $healthResponse.body
        descriptor_sha256 = Get-StringSha256 $descriptorResponse.body
        channel_sha256 = Get-StringSha256 $channelResponse.body
        payload_index_sha256 = Get-StringSha256 $payloadIndexResponse.body
        payload_manifest_sha256 = Get-StringSha256 $payloadManifestResponse.body
        payload_checksums_sha256 = Get-StringSha256 $payloadChecksumsResponse.body
        payload_signatures_sha256 = Get-StringSha256 $payloadSignaturesResponse.body
        install_bootstrap_sha256 = Get-StringSha256 $installBootstrapResponse.body
    }
    source_bindings = $sourceBindings
    invariants = [ordered]@{
        static_frontend_only = $true
        no_external_dependencies = $true
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
        rc6_004_complete = $passed
        frontend_url = "http://$Domain/"
        payload_index = "http://$Domain/payloads/index.json"
        install_bootstrap = "http://$Domain/install/bootstrap.json"
        production_ready_claim = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC6 mirror portal $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
