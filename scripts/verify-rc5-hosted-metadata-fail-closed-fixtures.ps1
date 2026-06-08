param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-hosted-metadata-fail-closed",
    [string]$OutputPath = "",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Invoke-CurlBody {
    param([Parameter(Mandatory = $true)][string]$Url)
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-fsS",
        $Url
    )
    $output = & curl.exe @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "curl failed ($exitCode) for ${Url}: $text"
    }
    return $text
}

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string]$Value)
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
    foreach ($marker in $markers) {
        if ($Value.Contains($marker, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}

function New-ValidationResult {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Status,
        [string[]]$Reasons = @()
    )
    return [ordered]@{
        kind = $Kind
        status = $Status
        reasons = $Reasons
    }
}

function Test-HealthMetadata {
    param([Parameter(Mandatory = $true)][string]$Text)
    $reasons = @()
    if ($Text.Length -gt 65536) { $reasons += "metadata-too-large" }
    if (-not (Test-NoSensitiveContent $Text)) { $reasons += "secret-marker" }
    try {
        $json = $Text | ConvertFrom-Json
    } catch {
        return New-ValidationResult "health" "rejected" @($reasons + "malformed-json")
    }
    if ($json.schema -ne "agentos.rc5-hosted-mirror-health.v1") { $reasons += "bad-schema" }
    if ($json.domain -ne $Domain) { $reasons += "domain-mismatch" }
    if ($json.production_ready_claim -ne $false) { $reasons += "ga-claim" }
    if ($json.storage_mode -ne "metadata-only") { $reasons += "storage-mode-not-metadata-only" }
    if ($json.signing_authority -ne $false) { $reasons += "signing-authority" }
    if ($json.activation_authority -ne $false) { $reasons += "activation-authority" }
    if ($json.production_ring_mutation_authority -ne $false) { $reasons += "production-ring-authority" }
    return New-ValidationResult "health" $(if ($reasons.Count -eq 0) { "accepted" } else { "rejected" }) $reasons
}

function Test-ChannelMetadata {
    param([Parameter(Mandatory = $true)][string]$Text)
    $reasons = @()
    if ($Text.Length -gt 65536) { $reasons += "metadata-too-large" }
    if (-not (Test-NoSensitiveContent $Text)) { $reasons += "secret-marker" }
    try {
        $json = $Text | ConvertFrom-Json
    } catch {
        return New-ValidationResult "channel" "rejected" @($reasons + "malformed-json")
    }
    if ($json.schema -ne "agentos.rc5-hosted-channel-index.v1") { $reasons += "bad-schema" }
    if ($json.production_ready_claim -ne $false) { $reasons += "ga-claim" }
    if ($json.storage_mode -ne "metadata-only") { $reasons += "storage-mode-not-metadata-only" }
    if ($json.source_rc4_final_audit_sha256 -ne $script:expectedRc4FinalAudit) { $reasons += "rc4-final-audit-hash-mismatch" }
    if ($json.hosted_transport_manifest_sha256 -ne $script:expectedHostedManifest) { $reasons += "hosted-transport-hash-mismatch" }
    if ($json.mirror_publication_sha256 -ne $script:expectedMirrorPublication) { $reasons += "mirror-publication-hash-mismatch" }
    if ($json.authority.signing_authority -ne $false) { $reasons += "signing-authority" }
    if ($json.authority.activation_authority -ne $false) { $reasons += "activation-authority" }
    if ($json.authority.tui_authority -ne $false) { $reasons += "tui-authority" }
    try {
        $generatedAt = [DateTimeOffset]::Parse($json.generated_at)
        if ($generatedAt -lt ([DateTimeOffset]::Now.AddDays(-7))) { $reasons += "stale-metadata" }
    } catch {
        $reasons += "bad-generated-at"
    }
    foreach ($entry in @($json.entries)) {
        $path = [string]$entry.path
        if ($path -match "\.(iso|img|qcow2|tar|tar\.gz|zip)$" -and $entry.large_payload_deferred -ne $true) {
            $reasons += "large-payload-reference-before-storage-upgrade"
        }
        if ($entry.activation_allowed -ne $false) {
            $reasons += "entry-activation-allowed"
        }
    }
    return New-ValidationResult "channel" $(if ($reasons.Count -eq 0) { "accepted" } else { "rejected" }) $reasons
}

function Copy-Json {
    param([Parameter(Mandatory = $true)]$Value)
    return (Get-JsonText $Value) | ConvertFrom-Json
}

function New-NegativeCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$ExpectedReason
    )
    $validation = if ($Kind -eq "health") { Test-HealthMetadata $Text } else { Test-ChannelMetadata $Text }
    $passed = $validation.status -eq "rejected" -and @($validation.reasons) -contains $ExpectedReason
    return [ordered]@{
        id = $Id
        kind = $Kind
        status = if ($passed) { "passed" } else { "failed" }
        expected_reason = $ExpectedReason
        validation = $validation
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$rc4FinalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json"
$rc4HostedManifestPath = Resolve-RepoPath ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json"
$rc4MirrorPublicationPath = Resolve-RepoPath ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json"
$rc5VerifierResultPath = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-endpoint-verifier/result.json"

$script:expectedRc4FinalAudit = Get-FileSha256 $rc4FinalAuditPath
$script:expectedHostedManifest = Get-FileSha256 $rc4HostedManifestPath
$script:expectedMirrorPublication = Get-FileSha256 $rc4MirrorPublicationPath

$healthText = Invoke-CurlBody "http://$Domain/health.json"
$channelText = Invoke-CurlBody "http://$Domain/channel/index.json"
$healthJson = $healthText | ConvertFrom-Json
$channelJson = $channelText | ConvertFrom-Json

$baselineHealth = Test-HealthMetadata $healthText
$baselineChannel = Test-ChannelMetadata $channelText

$cases = @()
$cases += New-NegativeCase "health.malformed-json" "health" "{" "malformed-json"
$healthBadSchema = Copy-Json $healthJson
$healthBadSchema.schema = "agentos.bad.v1"
$cases += New-NegativeCase "health.bad-schema" "health" (Get-JsonText $healthBadSchema) "bad-schema"
$healthGa = Copy-Json $healthJson
$healthGa.production_ready_claim = $true
$cases += New-NegativeCase "health.ga-claim" "health" (Get-JsonText $healthGa) "ga-claim"
$healthSigning = Copy-Json $healthJson
$healthSigning.signing_authority = $true
$cases += New-NegativeCase "health.signing-authority" "health" (Get-JsonText $healthSigning) "signing-authority"
$healthSecret = (Get-JsonText $healthJson) + "`nBEGIN PRIVATE KEY"
$cases += New-NegativeCase "health.secret-marker" "health" $healthSecret "secret-marker"

$cases += New-NegativeCase "channel.malformed-json" "channel" "[" "malformed-json"
$channelMissingRc4 = Copy-Json $channelJson
$channelMissingRc4.source_rc4_final_audit_sha256 = $null
$cases += New-NegativeCase "channel.missing-rc4-binding" "channel" (Get-JsonText $channelMissingRc4) "rc4-final-audit-hash-mismatch"
$channelHashDrift = Copy-Json $channelJson
$channelHashDrift.hosted_transport_manifest_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
$cases += New-NegativeCase "channel.hosted-hash-drift" "channel" (Get-JsonText $channelHashDrift) "hosted-transport-hash-mismatch"
$channelStale = Copy-Json $channelJson
$channelStale.generated_at = ([DateTimeOffset]::Now.AddDays(-30)).ToString("o")
$cases += New-NegativeCase "channel.stale" "channel" (Get-JsonText $channelStale) "stale-metadata"
$channelActivation = Copy-Json $channelJson
$channelActivation.authority.activation_authority = $true
$cases += New-NegativeCase "channel.activation-authority" "channel" (Get-JsonText $channelActivation) "activation-authority"
$channelTui = Copy-Json $channelJson
$channelTui.authority.tui_authority = $true
$cases += New-NegativeCase "channel.tui-authority" "channel" (Get-JsonText $channelTui) "tui-authority"
$channelPayload = Copy-Json $channelJson
$channelPayload.entries = @([ordered]@{
    id = "oversized-payload"
    status = "bad"
    path = "/releases/aios.iso"
    activation_allowed = $false
    large_payload_deferred = $false
})
$cases += New-NegativeCase "channel.large-payload-reference" "channel" (Get-JsonText $channelPayload) "large-payload-reference-before-storage-upgrade"
$channelEntryActivation = Copy-Json $channelJson
$channelEntryActivation.entries = @([ordered]@{
    id = "activation-entry"
    status = "bad"
    path = "/releases/README.txt"
    activation_allowed = $true
    large_payload_deferred = $true
})
$cases += New-NegativeCase "channel.entry-activation" "channel" (Get-JsonText $channelEntryActivation) "entry-activation-allowed"
$channelSecret = (Get-JsonText $channelJson) + "`nsigning-key.pem"
$cases += New-NegativeCase "channel.secret-marker" "channel" $channelSecret "secret-marker"

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$passed = $baselineHealth.status -eq "accepted" -and $baselineChannel.status -eq "accepted" -and @($failedCases).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc5-hosted-metadata-fail-closed-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC5-012"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    target = [ordered]@{
        domain = $Domain
        remote_host = $RemoteHost
        validation_used_local_dns = $false
        resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source_artifacts = [ordered]@{
        rc4_final_audit = [ordered]@{ path = Get-StablePath $rc4FinalAuditPath; sha256 = $script:expectedRc4FinalAudit }
        rc4_hosted_transport_manifest = [ordered]@{ path = Get-StablePath $rc4HostedManifestPath; sha256 = $script:expectedHostedManifest }
        rc4_mirror_publication = [ordered]@{ path = Get-StablePath $rc4MirrorPublicationPath; sha256 = $script:expectedMirrorPublication }
        rc5_hosted_endpoint_verifier = [ordered]@{ path = Get-StablePath $rc5VerifierResultPath; sha256 = Get-FileSha256 $rc5VerifierResultPath }
    }
    baseline = [ordered]@{
        health = $baselineHealth
        channel = $baselineChannel
    }
    negative_cases = $cases
    blockers = $failedCases
    summary = [ordered]@{
        negative_cases = @($cases).Count
        negative_passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        blockers = @($failedCases).Count
        rc5_012_complete = $passed
        production_ready_claim = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC5 hosted metadata fail-closed $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
