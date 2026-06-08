param(
    [string]$ArtifactDir = ".workflow/artifacts/rc6-installer-fail-closed",
    [string]$ResultPath = "",
    [string]$BootstrapPreflightResultPath = ".workflow/artifacts/rc6-bootstrap-installer-preflight/result.json",
    [string]$BootstrapPreflightReportPath = ".workflow/artifacts/rc6-bootstrap-installer-preflight/preflight-report.json",
    [string]$HostedPayloadIndexPath = ".workflow/artifacts/rc6-hosted-payload-metadata/hosted-payload-index.json",
    [string]$HostedInstallBootstrapPath = ".workflow/artifacts/rc6-hosted-payload-metadata/install-bootstrap.json",
    [string]$HostedChannelIndexPath = ".workflow/artifacts/rc6-hosted-payload-metadata/hosted-channel-index-after-payload-metadata.json",
    [string]$PayloadManifestPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-manifest.json",
    [string]$PayloadChecksumsPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-checksums.json",
    [string]$PayloadSignaturesPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-signatures.json",
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

function Convert-JsonClone {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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

function Add-Reason {
    param(
        [System.Collections.Generic.List[string]]$Reasons,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    if (-not $Reasons.Contains($Reason)) {
        $Reasons.Add($Reason)
    }
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

function Test-FreshDate {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [int]$MaxAgeDays = 7
    )
    try {
        $dt = [DateTimeOffset]::Parse([string]$Value)
        return (([DateTimeOffset]::Now - $dt).TotalDays -le $MaxAgeDays)
    } catch {
        return $false
    }
}

function Test-MetadataSize {
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)][int]$LimitBytes,
        [Parameter(Mandatory = $true)][string]$Reason,
        [System.Collections.Generic.List[string]]$Reasons
    )
    $simulated = $Document.simulated_size_bytes
    if ($null -ne $simulated -and [int64]$simulated -gt $LimitBytes) {
        Add-Reason $Reasons $Reason
    }
}

function Invoke-InstallerFixture {
    param(
        [Parameter(Mandatory = $true)]$PayloadIndex,
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)]$Checksums,
        [Parameter(Mandatory = $true)]$Signatures,
        [Parameter(Mandatory = $true)]$InstallBootstrap,
        [Parameter(Mandatory = $true)]$ChannelIndex
    )
    $reasons = [System.Collections.Generic.List[string]]::new()
    $entry = @($PayloadIndex.entries)[0]

    if ($PayloadIndex.production_ready_claim -eq $true -or $Manifest.production_ready_claim -eq $true -or $Signatures.production_ready_claim -eq $true -or $InstallBootstrap.production_ready_claim -eq $true) {
        Add-Reason $reasons "production-ready-claim"
    }
    if ($PayloadIndex.schema -ne "agentos.rc6-hosted-payload-index.v1") {
        Add-Reason $reasons "bad-payload-index-schema"
    }
    if ($Manifest.schema -ne "agentos.rc6-installable-payload-manifest.v1") {
        Add-Reason $reasons "bad-payload-manifest-schema"
    }
    if ($Checksums.schema -ne "agentos.rc6-installable-payload-checksums.v1") {
        Add-Reason $reasons "bad-checksums-schema"
    }
    if ($Signatures.schema -ne "agentos.rc6-installable-payload-signatures.v1") {
        Add-Reason $reasons "bad-signatures-schema"
    }

    if ($null -eq $entry) {
        Add-Reason $reasons "missing-payload-index-entry"
    } else {
        if ($entry.status -ne "verification-blocked") {
            Add-Reason $reasons "payload-status-not-blocked"
        }
        if ($entry.manifest_sha256 -ne $script:expectedManifestHash) {
            Add-Reason $reasons "manifest-hash-mismatch"
        }
        if ($entry.checksums_sha256 -ne $script:expectedChecksumsHash) {
            Add-Reason $reasons "checksums-hash-mismatch"
        }
        if ($entry.signatures_sha256 -ne $script:expectedSignaturesHash) {
            Add-Reason $reasons "signatures-hash-mismatch"
        }
        if ($entry.install_allowed -eq $true -or $entry.activation_allowed -eq $true -or $entry.rollback_execution_allowed -eq $true) {
            Add-Reason $reasons "payload-authority-broadening"
        }
    }

    Test-MetadataSize -Document $PayloadIndex -LimitBytes 262144 -Reason "oversized-payload-index" -Reasons $reasons
    Test-MetadataSize -Document $Manifest -LimitBytes 524288 -Reason "oversized-payload-manifest" -Reasons $reasons
    Test-MetadataSize -Document $Checksums -LimitBytes 524288 -Reason "oversized-payload-checksums" -Reasons $reasons
    Test-MetadataSize -Document $Signatures -LimitBytes 524288 -Reason "oversized-payload-signatures" -Reasons $reasons
    Test-MetadataSize -Document $InstallBootstrap -LimitBytes 131072 -Reason "oversized-install-bootstrap" -Reasons $reasons

    if (-not (Test-FreshDate $PayloadIndex.generated_at)) {
        Add-Reason $reasons "stale-payload-index"
    }
    if (-not (Test-FreshDate $Manifest.generated_at)) {
        Add-Reason $reasons "stale-payload-manifest"
    }
    if (-not (Test-FreshDate $Signatures.generated_at)) {
        Add-Reason $reasons "stale-signature-metadata"
    }

    if ($Checksums.payload_manifest_sha256 -ne $script:expectedManifestHash) {
        Add-Reason $reasons "checksums-manifest-binding-mismatch"
    }
    if (@($Checksums.component_hashes | Where-Object { -not (Has-Value $_.sha256) }).Count -gt 0) {
        Add-Reason $reasons "missing-component-hash"
    }

    if ($Signatures.signature_available -ne $true) {
        Add-Reason $reasons "unsigned-payload"
    }
    if (-not (Has-Value $Signatures.signed_metadata_reference)) {
        Add-Reason $reasons "missing-signed-metadata-reference"
    }
    if ($Signatures.signing_authority_on_mirror -eq $true) {
        Add-Reason $reasons "mirror-signing-authority"
    }
    if ($Signatures.PSObject.Properties.Name -contains "revocation_status" -and $Signatures.revocation_status -eq "revoked") {
        Add-Reason $reasons "revoked-signing-key"
    }
    if (-not (Has-Value $Signatures.revocation_snapshot_sha256)) {
        Add-Reason $reasons "missing-revocation-snapshot"
    }
    if ($Signatures.PSObject.Properties.Name -contains "freshness_status" -and $Signatures.freshness_status -eq "stale") {
        Add-Reason $reasons "stale-signature-metadata"
    }

    if ($Manifest.storage_policy.large_payload_storage_enabled -eq $true) {
        Add-Reason $reasons "large-payload-storage-enabled"
    }
    if ((Has-Value $Manifest.storage_policy.large_payload_url) -and $Manifest.storage_policy.large_payload_storage_enabled -ne $true) {
        Add-Reason $reasons "large-payload-url-before-storage-policy"
    }
    if ($Manifest.drift_policy.installable_media_declared_hash_drift_count -gt 0 -and $Manifest.drift_policy.drift_blocks_install -ne $true) {
        Add-Reason $reasons "declared-hash-drift-not-blocking"
    }
    if (-not (Has-Value $Manifest.install_policy.rollback_baseline_sha256)) {
        Add-Reason $reasons "missing-rollback-baseline"
    }
    if (-not (Has-Value $Manifest.install_policy.installer_compatibility_contract_sha256)) {
        Add-Reason $reasons "missing-installer-compatibility-contract"
    }
    if ($Manifest.install_policy.install_allowed -eq $true -or $Manifest.install_policy.activation_allowed -eq $true -or $Manifest.install_policy.rollback_execution_allowed -eq $true) {
        Add-Reason $reasons "manifest-authority-broadening"
    }
    if ($InstallBootstrap.install_allowed -eq $true -or $InstallBootstrap.activation_allowed -eq $true) {
        Add-Reason $reasons "install-bootstrap-authority-broadening"
    }
    if ($ChannelIndex.payload_channel.install_allowed -eq $true -or $ChannelIndex.authority.signing_authority -eq $true -or $ChannelIndex.authority.activation_authority -eq $true -or $ChannelIndex.authority.rollback_execution_authority -eq $true -or $ChannelIndex.authority.remote_dispatch_authority -eq $true -or $ChannelIndex.authority.tui_authority -eq $true) {
        Add-Reason $reasons "channel-authority-broadening"
    }

    return [ordered]@{
        state = if ($reasons.Count -eq 0) { "install-preflight-ready" } else { "verification-blocked" }
        install_allowed = $false
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
        reasons = @($reasons)
    }
}

function New-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][scriptblock]$Mutate,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons
    )
    $payloadIndex = Convert-JsonClone $script:baselinePayloadIndex
    $manifest = Convert-JsonClone $script:baselineManifest
    $checksums = Convert-JsonClone $script:baselineChecksums
    $signatures = Convert-JsonClone $script:baselineSignatures
    $install = Convert-JsonClone $script:baselineInstallBootstrap
    $channel = Convert-JsonClone $script:baselineChannelIndex

    & $Mutate $payloadIndex $manifest $checksums $signatures $install $channel
    $result = Invoke-InstallerFixture -PayloadIndex $payloadIndex -Manifest $manifest -Checksums $checksums -Signatures $signatures -InstallBootstrap $install -ChannelIndex $channel
    $hasExpectedReasons = @($ExpectedReasons | Where-Object { $result.reasons -notcontains $_ }).Count -eq 0
    $noSideEffects = $result.side_effects.install_performed -eq $false -and
        $result.side_effects.activation_performed -eq $false -and
        $result.side_effects.rollback_execution_performed -eq $false -and
        $result.side_effects.remote_dispatch_enabled -eq $false
    return [ordered]@{
        id = $Id
        status = if ($result.state -eq "verification-blocked" -and $hasExpectedReasons -and $noSideEffects) { "passed" } else { "failed" }
        expected_reasons = @($ExpectedReasons)
        observed_state = $result.state
        observed_reasons = @($result.reasons)
        side_effects = $result.side_effects
    }
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

$resolvedBootstrapPreflightResultPath = Resolve-RepoPath $BootstrapPreflightResultPath
$resolvedBootstrapPreflightReportPath = Resolve-RepoPath $BootstrapPreflightReportPath
$resolvedHostedPayloadIndexPath = Resolve-RepoPath $HostedPayloadIndexPath
$resolvedHostedInstallBootstrapPath = Resolve-RepoPath $HostedInstallBootstrapPath
$resolvedHostedChannelIndexPath = Resolve-RepoPath $HostedChannelIndexPath
$resolvedPayloadManifestPath = Resolve-RepoPath $PayloadManifestPath
$resolvedPayloadChecksumsPath = Resolve-RepoPath $PayloadChecksumsPath
$resolvedPayloadSignaturesPath = Resolve-RepoPath $PayloadSignaturesPath

$preflightResult = Read-Json $resolvedBootstrapPreflightResultPath
$preflightReport = Read-Json $resolvedBootstrapPreflightReportPath
$script:baselinePayloadIndex = Read-Json $resolvedHostedPayloadIndexPath
$script:baselineInstallBootstrap = Read-Json $resolvedHostedInstallBootstrapPath
$script:baselineChannelIndex = Read-Json $resolvedHostedChannelIndexPath
$script:baselineManifest = Read-Json $resolvedPayloadManifestPath
$script:baselineChecksums = Read-Json $resolvedPayloadChecksumsPath
$script:baselineSignatures = Read-Json $resolvedPayloadSignaturesPath
$script:expectedManifestHash = $script:baselinePayloadIndex.entries[0].manifest_sha256
$script:expectedChecksumsHash = $script:baselinePayloadIndex.entries[0].checksums_sha256
$script:expectedSignaturesHash = $script:baselinePayloadIndex.entries[0].signatures_sha256

Add-Check "bootstrap_preflight.result" ($preflightResult.status -eq "passed" -and $preflightResult.summary.task_blockers -eq 0) "RC6-020 bootstrap installer preflight must be passed before fail-closed behavior proof." $preflightResult.summary
Add-Check "bootstrap_preflight.blocked" ($preflightReport.state -eq "verification-blocked" -and @($preflightReport.blockers).Count -gt 0) "Baseline preflight must be verification-blocked." ([ordered]@{ state = $preflightReport.state; blockers = @($preflightReport.blockers).Count })
Add-Check "baseline.no_install" ($script:baselinePayloadIndex.entries[0].install_allowed -eq $false -and $script:baselineInstallBootstrap.install_allowed -eq $false) "Baseline hosted payload and install bootstrap must not allow install." ([ordered]@{ payload_install = $script:baselinePayloadIndex.entries[0].install_allowed; bootstrap_install = $script:baselineInstallBootstrap.install_allowed })

$cases = @(
    (New-Case -Id "unsigned-payload" -ExpectedReasons @("unsigned-payload", "missing-signed-metadata-reference") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.signature_available = $false; $s.PSObject.Properties.Remove("signed_metadata_reference") })
    (New-Case -Id "stale-payload-index" -ExpectedReasons @("stale-payload-index") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.generated_at = "2000-01-01T00:00:00Z" })
    (New-Case -Id "stale-payload-manifest" -ExpectedReasons @("stale-payload-manifest") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.generated_at = "2000-01-01T00:00:00Z" })
    (New-Case -Id "stale-signature-metadata" -ExpectedReasons @("stale-signature-metadata") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.generated_at = "2000-01-01T00:00:00Z"; $s | Add-Member -NotePropertyName "freshness_status" -NotePropertyValue "stale" -Force })
    (New-Case -Id "revoked-signing-key" -ExpectedReasons @("revoked-signing-key") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.signature_available = $true; $s | Add-Member -NotePropertyName "signed_metadata_reference" -NotePropertyValue "/payloads/signature.sig" -Force; $s | Add-Member -NotePropertyName "revocation_status" -NotePropertyValue "revoked" -Force })
    (New-Case -Id "oversized-payload-index" -ExpectedReasons @("oversized-payload-index") -Mutate { param($p,$m,$c,$s,$i,$ch) $p | Add-Member -NotePropertyName "simulated_size_bytes" -NotePropertyValue 262145 -Force })
    (New-Case -Id "oversized-payload-manifest" -ExpectedReasons @("oversized-payload-manifest") -Mutate { param($p,$m,$c,$s,$i,$ch) $m | Add-Member -NotePropertyName "simulated_size_bytes" -NotePropertyValue 524289 -Force })
    (New-Case -Id "oversized-payload-checksums" -ExpectedReasons @("oversized-payload-checksums") -Mutate { param($p,$m,$c,$s,$i,$ch) $c | Add-Member -NotePropertyName "simulated_size_bytes" -NotePropertyValue 524289 -Force })
    (New-Case -Id "oversized-payload-signatures" -ExpectedReasons @("oversized-payload-signatures") -Mutate { param($p,$m,$c,$s,$i,$ch) $s | Add-Member -NotePropertyName "simulated_size_bytes" -NotePropertyValue 524289 -Force })
    (New-Case -Id "large-payload-url-before-policy" -ExpectedReasons @("large-payload-url-before-storage-policy") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.storage_policy.large_payload_url = "https://example.invalid/aios.img"; $m.storage_policy.large_payload_storage_enabled = $false })
    (New-Case -Id "manifest-hash-mismatch" -ExpectedReasons @("manifest-hash-mismatch") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.entries[0].manifest_sha256 = "0000" })
    (New-Case -Id "install-authority-broadening" -ExpectedReasons @("install-bootstrap-authority-broadening") -Mutate { param($p,$m,$c,$s,$i,$ch) $i.install_allowed = $true })
)

$passedCases = @($cases | Where-Object { $_.status -eq "passed" })
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "cases.all_fail_closed" ($failedCases.Count -eq 0 -and $passedCases.Count -eq $cases.Count) "All installer negative cases must fail closed without side effects." ([ordered]@{ passed = $passedCases.Count; failed = $failedCases.Count })

$caseText = $cases | ConvertTo-Json -Depth 100
Add-Check "cases.secret_safe" (Test-NoSensitiveText -Values @($caseText)) "Installer fail-closed case results must not contain private key or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-installer-fail-closed-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC6-021"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    source = [ordered]@{
        bootstrap_preflight_result = [ordered]@{ path = Get-StablePath $resolvedBootstrapPreflightResultPath; sha256 = Get-FileSha256 $resolvedBootstrapPreflightResultPath }
        bootstrap_preflight_report = [ordered]@{ path = Get-StablePath $resolvedBootstrapPreflightReportPath; sha256 = Get-FileSha256 $resolvedBootstrapPreflightReportPath }
        hosted_payload_index = [ordered]@{ path = Get-StablePath $resolvedHostedPayloadIndexPath; sha256 = Get-FileSha256 $resolvedHostedPayloadIndexPath }
        payload_manifest = [ordered]@{ path = Get-StablePath $resolvedPayloadManifestPath; sha256 = Get-FileSha256 $resolvedPayloadManifestPath }
        payload_checksums = [ordered]@{ path = Get-StablePath $resolvedPayloadChecksumsPath; sha256 = Get-FileSha256 $resolvedPayloadChecksumsPath }
        payload_signatures = [ordered]@{ path = Get-StablePath $resolvedPayloadSignaturesPath; sha256 = Get-FileSha256 $resolvedPayloadSignaturesPath }
    }
    cases = @($cases)
    failed_cases = @($failedCases | ForEach-Object { $_.id })
    invariants = [ordered]@{
        local_fixture_only = $true
        remote_mutation_performed = $false
        large_payload_storage_enabled = $false
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
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        cases = @($cases).Count
        passed_cases = @($passedCases).Count
        failed_cases = @($failedCases).Count
        rc6_021_complete = $passed
        next_task = "RC6-030"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC6 installer fail-closed $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
