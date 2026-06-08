param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-bootstrap-installer-preflight",
    [string]$ResultPath = "",
    [string]$HostedPayloadMetadataResultPath = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json",
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

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function ConvertFrom-JsonTextSafe {
    param([Parameter(Mandatory = $true)][string]$Text)
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Invoke-Curl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $url = "http://$Domain$Path"
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
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
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        json = if ($statusCode -eq 200 -and $body) { ConvertFrom-JsonTextSafe $body } else { $null }
    }
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null,
        [string]$Severity = "blocking"
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = $Severity
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed -and $Severity -eq "blocking") {
        $script:taskBlockers += $entry
    }
}

function Add-PreflightStep {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "blocked" }
        message = $Message
        evidence = $Evidence
    }
    $script:preflightSteps += $entry
    if (-not $Passed) {
        $script:preflightBlockers += $entry
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

function Has-Value {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }
    return $true
}

function Test-FreshIsoDate {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [int]$MaxAgeDays = 7
    )
    try {
        $dt = [DateTimeOffset]::Parse($Value)
        return (([DateTimeOffset]::Now - $dt).TotalDays -le $MaxAgeDays)
    } catch {
        return $false
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:taskBlockers = @()
$script:preflightSteps = @()
$script:preflightBlockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath
$resolvedHostedPayloadMetadataResultPath = Resolve-RepoPath $HostedPayloadMetadataResultPath
$hostedResult = Read-Json $resolvedHostedPayloadMetadataResultPath

$generatedAt = (Get-Date).ToString("o")
$fetches = [ordered]@{}
foreach ($path in @(
    "/health.json",
    "/.well-known/aios/mirror.json",
    "/channel/index.json",
    "/install/bootstrap.json",
    "/payloads/index.json",
    "/support/index.json"
)) {
    $fetches[$path] = Invoke-Curl $path
}

$payloadIndex = $fetches["/payloads/index.json"].json
$installBootstrap = $fetches["/install/bootstrap.json"].json
$channelIndex = $fetches["/channel/index.json"].json
$health = $fetches["/health.json"].json
$descriptor = $fetches["/.well-known/aios/mirror.json"].json
$support = $fetches["/support/index.json"].json

$entry = if ($null -ne $payloadIndex -and $null -ne $payloadIndex.entries) { @($payloadIndex.entries)[0] } else { $null }
$manifestPath = if ($null -ne $entry) { $entry.manifest_path } else { "" }
$checksumsPath = if ($null -ne $entry) { $entry.checksums_path } else { "" }
$signaturesPath = if ($null -ne $entry) { $entry.signatures_path } else { "" }

if (Has-Value $manifestPath) { $fetches[$manifestPath] = Invoke-Curl $manifestPath }
if (Has-Value $checksumsPath) { $fetches[$checksumsPath] = Invoke-Curl $checksumsPath }
if (Has-Value $signaturesPath) { $fetches[$signaturesPath] = Invoke-Curl $signaturesPath }

$manifest = if (Has-Value $manifestPath) { $fetches[$manifestPath].json } else { $null }
$checksums = if (Has-Value $checksumsPath) { $fetches[$checksumsPath].json } else { $null }
$signatures = if (Has-Value $signaturesPath) { $fetches[$signaturesPath].json } else { $null }

Add-Check "hosted_payload_metadata.result" ($hostedResult.status -eq "passed" -and $hostedResult.summary.blockers -eq 0) "RC6-011 hosted payload metadata result must be passed." $hostedResult.summary
Add-Check "fetch.required_endpoints" (@($fetches.Values | Where-Object { $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0) "All required hosted metadata endpoints must return JSON 200." (@($fetches.Values) | ForEach-Object { [ordered]@{ path = $_.path; status = $_.status_code; parsed = $null -ne $_.json } })

Add-PreflightStep "fetch-health-descriptor-channel-bootstrap" (@($fetches.Values | Where-Object { $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0) "Fetched health, descriptor, channel, install bootstrap, payload index, payload details, and support metadata." (@($fetches.Keys))
Add-PreflightStep "verify-schema-and-production-ready-false" (
    $health.schema -eq "agentos.rc6-hosted-mirror-health.v1" -and
    $descriptor.schema -eq "agentos.rc6-hosted-mirror-descriptor.v1" -and
    $channelIndex.schema -eq "agentos.rc6-hosted-channel-index.v1" -and
    $installBootstrap.schema -eq "agentos.rc6-install-bootstrap.v1" -and
    $payloadIndex.schema -eq "agentos.rc6-hosted-payload-index.v1" -and
    $manifest.schema -eq "agentos.rc6-installable-payload-manifest.v1" -and
    $checksums.schema -eq "agentos.rc6-installable-payload-checksums.v1" -and
    $signatures.schema -eq "agentos.rc6-installable-payload-signatures.v1" -and
    $health.production_ready_claim -eq $false -and
    $channelIndex.production_ready_claim -eq $false -and
    $payloadIndex.production_ready_claim -eq $false -and
    $manifest.production_ready_claim -eq $false -and
    $signatures.production_ready_claim -eq $false
) "Schemas are recognized and production_ready_claim remains false."
Add-PreflightStep "verify-rc5-final-audit-binding" (Has-Value $payloadIndex.source_bindings.rc5_final_audit.sha256) "Payload metadata binds RC5 final audit evidence." $(if ($null -ne $payloadIndex) { $payloadIndex.source_bindings.rc5_final_audit } else { $null })
Add-PreflightStep "verify-payload-index-binding" (
    $channelIndex.payload_channel.default_release_id -eq $entry.release_id -and
    $installBootstrap.default_release_id -eq $entry.release_id -and
    $channelIndex.payload_channel.payload_index_sha256 -eq $installBootstrap.projection.payload_index_sha256
) "Channel and install bootstrap point at the same payload index and release id." ([ordered]@{ channel_release = $channelIndex.payload_channel.default_release_id; install_release = $installBootstrap.default_release_id; payload_release = $entry.release_id })
Add-PreflightStep "verify-payload-manifest-hash" ($entry.manifest_sha256 -eq $hostedResult.output_hashes.payload_manifest_content_sha256 -and $checksums.payload_manifest_sha256 -eq $entry.manifest_sha256) "Payload manifest hash is bound by payload index and checksums metadata." ([ordered]@{ entry_manifest = $entry.manifest_sha256; checksums_manifest = $checksums.payload_manifest_sha256 })
Add-PreflightStep "verify-payload-content-hashes" (@($checksums.component_hashes | Where-Object { -not (Has-Value $_.sha256) }).Count -eq 0) "Payload component hashes are present in checksums metadata." ([ordered]@{ components = @($checksums.component_hashes).Count })
Add-PreflightStep "verify-signature-or-signed-metadata-reference" ($signatures.signature_available -eq $true -and (Has-Value $signatures.signed_metadata_reference)) "Public signature or signed metadata reference must exist before install." ([ordered]@{ signature_available = $signatures.signature_available; signed_metadata_reference = $signatures.signed_metadata_reference })
Add-PreflightStep "verify-revocation-snapshot" (Has-Value $signatures.revocation_snapshot_sha256) "Revocation snapshot hash must exist before install." ([ordered]@{ revocation_snapshot_sha256 = $signatures.revocation_snapshot_sha256 })
Add-PreflightStep "verify-freshness-window" ((Test-FreshIsoDate $payloadIndex.generated_at) -and (Test-FreshIsoDate $installBootstrap.generated_at)) "Payload and install metadata must be within freshness window." ([ordered]@{ payload_generated_at = $payloadIndex.generated_at; install_generated_at = $installBootstrap.generated_at })
Add-PreflightStep "verify-installer-compatibility-contract" (Has-Value $manifest.install_policy.installer_compatibility_contract_sha256) "Installer compatibility contract hash must exist before install." $manifest.install_policy
Add-PreflightStep "verify-rollback-baseline-hash" (Has-Value $manifest.install_policy.rollback_baseline_sha256) "Rollback baseline hash must exist before install." $manifest.install_policy
Add-PreflightStep "verify-storage-policy-for-large-payloads" ($manifest.storage_policy.large_payload_storage_enabled -eq $false -and -not (Has-Value $manifest.storage_policy.large_payload_url)) "Large payload storage remains deferred and no large payload URL is advertised." $manifest.storage_policy

$preflightState = if (@($script:preflightBlockers).Count -eq 0) { "install-preflight-ready" } else { "verification-blocked" }
$preflightReport = [ordered]@{
    schema = "agentos.rc6-bootstrap-installer-preflight-report.v1"
    generated_at = $generatedAt
    production_ready_claim = $false
    release_id = if ($null -ne $entry) { $entry.release_id } else { $null }
    domain = $Domain
    validation_used_local_dns = $false
    validation_resolve_override = "$Domain`:80`:$RemoteHost"
    state = $preflightState
    allowed_outputs = @(
        "preflight-report",
        "missing-checks-list",
        "payload-candidate-explanation",
        "rollback-readiness-explanation"
    )
    steps = @($script:preflightSteps)
    blockers = @($script:preflightBlockers)
    side_effects = [ordered]@{
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}
$preflightReportPath = Join-Path $resolvedArtifactDir "preflight-report.json"
Write-Json -Value $preflightReport -Path $preflightReportPath

$reportText = Get-Content -Raw -LiteralPath $preflightReportPath
Add-Check "preflight.report.generated" (Test-Path -LiteralPath $preflightReportPath -PathType Leaf) "Preflight report must be generated." (Get-StablePath $preflightReportPath)
Add-Check "preflight.expected_state" ($preflightReport.state -eq "verification-blocked" -and @($preflightReport.blockers).Count -gt 0) "RC6 preflight should be verification-blocked until signature, revocation, compatibility, and rollback evidence exist." ([ordered]@{ state = $preflightReport.state; blockers = @($preflightReport.blockers).Count })
Add-Check "preflight.no_side_effects" ($preflightReport.side_effects.install_performed -eq $false -and $preflightReport.side_effects.activation_performed -eq $false -and $preflightReport.side_effects.rollback_execution_performed -eq $false -and $preflightReport.side_effects.remote_dispatch_enabled -eq $false) "Preflight must not perform install, activation, rollback, or dispatch side effects." $preflightReport.side_effects
Add-Check "preflight.secret_safe" (Test-NoSensitiveText -Values @($reportText)) "Preflight report must not contain private key or token markers." $null

$passed = @($script:taskBlockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-bootstrap-installer-preflight-result.v1"
    generated_at = $generatedAt
    task = "RC6-020"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    preflight = [ordered]@{
        report_path = Get-StablePath $preflightReportPath
        report_sha256 = Get-FileSha256 $preflightReportPath
        state = $preflightReport.state
        blockers = @($preflightReport.blockers).Count
        release_id = $preflightReport.release_id
    }
    fetched_endpoints = @($fetches.Values | ForEach-Object {
        [ordered]@{ path = $_.path; status_code = $_.status_code; parsed_json = $null -ne $_.json }
    })
    source = [ordered]@{
        hosted_payload_metadata_result = [ordered]@{ path = Get-StablePath $resolvedHostedPayloadMetadataResultPath; sha256 = Get-FileSha256 $resolvedHostedPayloadMetadataResultPath }
    }
    invariants = [ordered]@{
        metadata_preflight_only = $true
        validation_used_local_dns = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        install_allowed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
    checks = $script:checks
    task_blockers = $script:taskBlockers
    preflight_steps = $script:preflightSteps
    preflight_blockers = $script:preflightBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        task_blockers = @($script:taskBlockers).Count
        preflight_steps = @($script:preflightSteps).Count
        preflight_blockers = @($script:preflightBlockers).Count
        preflight_state = $preflightReport.state
        rc6_020_complete = $passed
        next_task = "RC6-021"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC6 bootstrap installer preflight $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:taskBlockers).Count -gt 0) {
    exit 1
}
