param(
    [string]$ArtifactDir = ".workflow/artifacts/rc6-signed-payload-fail-closed",
    [string]$ResultPath = "",
    [string]$HostedPayloadMetadataResultPath = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json",
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

function Add-Reason {
    param(
        [System.Collections.Generic.List[string]]$Reasons,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    if (-not $Reasons.Contains($Reason)) {
        $Reasons.Add($Reason)
    }
}

function Test-PayloadMetadata {
    param(
        [Parameter(Mandatory = $true)]$PayloadIndex,
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)]$Checksums,
        [Parameter(Mandatory = $true)]$Signatures,
        [Parameter(Mandatory = $true)]$InstallBootstrap,
        [Parameter(Mandatory = $true)]$ChannelIndex
    )

    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($PayloadIndex.schema -notin @("agentos.rc6-hosted-payload-index.v1", "agentos.rc6-installable-payload-index-projection.v1")) {
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
    if ($InstallBootstrap.schema -ne "agentos.rc6-install-bootstrap.v1") {
        Add-Reason $reasons "bad-install-bootstrap-schema"
    }

    foreach ($doc in @($PayloadIndex, $Manifest, $Checksums, $Signatures, $InstallBootstrap, $ChannelIndex)) {
        if ($doc.production_ready_claim -eq $true) {
            Add-Reason $reasons "production-ready-claim"
        }
    }

    $entry = @($PayloadIndex.entries)[0]
    if ($null -eq $entry) {
        Add-Reason $reasons "missing-payload-index-entry"
    } else {
        if ($entry.manifest_sha256 -ne $script:baselineManifestContentSha256) {
            Add-Reason $reasons "manifest-hash-mismatch"
        }
        if ($entry.checksums_sha256 -ne $script:baselineChecksumsContentSha256) {
            Add-Reason $reasons "checksums-hash-mismatch"
        }
        if ($entry.signatures_sha256 -ne $script:baselineSignaturesContentSha256) {
            Add-Reason $reasons "signatures-hash-mismatch"
        }
        if ($entry.install_allowed -eq $true -or $entry.activation_allowed -eq $true -or $entry.rollback_execution_allowed -eq $true) {
            Add-Reason $reasons "payload-entry-authority-broadening"
        }
    }

    if ($Checksums.payload_manifest_sha256 -ne $script:baselineManifestContentSha256) {
        Add-Reason $reasons "checksums-manifest-binding-mismatch"
    }
    if ($Manifest.production_ready_claim -eq $true -or $Manifest.payload_status -ne "verification-blocked") {
        Add-Reason $reasons "manifest-not-verification-blocked"
    }
    if ($Manifest.storage_policy.large_payload_storage_enabled -eq $true) {
        Add-Reason $reasons "large-payload-storage-enabled"
    }
    if ((Has-Value $Manifest.storage_policy.large_payload_url) -and $Manifest.storage_policy.large_payload_storage_enabled -ne $true) {
        Add-Reason $reasons "large-payload-url-before-storage-policy"
    }
    if ($Manifest.install_policy.install_allowed -eq $true -or $Manifest.install_policy.activation_allowed -eq $true -or $Manifest.install_policy.rollback_execution_allowed -eq $true) {
        Add-Reason $reasons "manifest-install-authority-broadening"
    }
    if ($Manifest.drift_policy.installable_media_declared_hash_drift_count -gt 0 -and $Manifest.drift_policy.drift_blocks_install -ne $true) {
        Add-Reason $reasons "declared-hash-drift-not-blocking"
    }
    if ($Manifest.install_policy.PSObject.Properties.Name -notcontains "rollback_baseline_sha256") {
        Add-Reason $reasons "missing-rollback-baseline"
    } elseif (-not (Has-Value $Manifest.install_policy.rollback_baseline_sha256)) {
        Add-Reason $reasons "missing-rollback-baseline"
    }
    if ($Manifest.install_policy.PSObject.Properties.Name -notcontains "installer_compatibility_contract_sha256") {
        Add-Reason $reasons "missing-installer-compatibility-contract"
    } elseif (-not (Has-Value $Manifest.install_policy.installer_compatibility_contract_sha256)) {
        Add-Reason $reasons "missing-installer-compatibility-contract"
    }

    if ($Signatures.signature_available -ne $true) {
        Add-Reason $reasons "missing-signature-reference"
    }
    if ($Signatures.placeholder_is_authority -eq $true) {
        Add-Reason $reasons "placeholder-signature-authority"
    }
    if ($Signatures.signing_authority_on_mirror -eq $true) {
        Add-Reason $reasons "mirror-signing-authority"
    }
    if ($Signatures.PSObject.Properties.Name -notcontains "revocation_snapshot_sha256") {
        Add-Reason $reasons "missing-revocation-snapshot"
    } elseif (-not (Has-Value $Signatures.revocation_snapshot_sha256)) {
        Add-Reason $reasons "missing-revocation-snapshot"
    }
    if ($Signatures.PSObject.Properties.Name -contains "revocation_status" -and $Signatures.revocation_status -eq "revoked") {
        Add-Reason $reasons "revoked-signing-key"
    }
    if ($Signatures.PSObject.Properties.Name -contains "freshness_status" -and $Signatures.freshness_status -eq "stale") {
        Add-Reason $reasons "stale-payload-metadata"
    }

    if ($InstallBootstrap.install_allowed -eq $true -or $InstallBootstrap.activation_allowed -eq $true) {
        Add-Reason $reasons "install-bootstrap-authority-broadening"
    }
    if ($InstallBootstrap.current_state -notin @("metadata-unavailable", "metadata-candidate", "verification-blocked", "install-preflight-ready")) {
        Add-Reason $reasons "install-state-outside-rc6"
    }
    if ($InstallBootstrap.current_state -eq "install-preflight-ready" -and $Signatures.signature_available -ne $true) {
        Add-Reason $reasons "preflight-ready-without-signature"
    }

    if ($ChannelIndex.payload_channel.install_allowed -eq $true -or $ChannelIndex.authority.signing_authority -eq $true -or $ChannelIndex.authority.activation_authority -eq $true -or $ChannelIndex.authority.rollback_execution_authority -eq $true -or $ChannelIndex.authority.remote_dispatch_authority -eq $true -or $ChannelIndex.authority.tui_authority -eq $true) {
        Add-Reason $reasons "channel-authority-broadening"
    }

    $status = if ($reasons.Count -eq 0) { "accepted" } else { "blocked" }
    return [ordered]@{
        status = $status
        reasons = @($reasons)
    }
}

function New-FixtureCase {
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

    $validation = Test-PayloadMetadata -PayloadIndex $payloadIndex -Manifest $manifest -Checksums $checksums -Signatures $signatures -InstallBootstrap $install -ChannelIndex $channel
    $hasExpectedReasons = @($ExpectedReasons | Where-Object { $validation.reasons -notcontains $_ }).Count -eq 0
    return [ordered]@{
        id = $Id
        status = if ($validation.status -eq "blocked" -and $hasExpectedReasons) { "passed" } else { "failed" }
        expected_reasons = @($ExpectedReasons)
        observed_status = $validation.status
        observed_reasons = @($validation.reasons)
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

$resolvedHostedPayloadMetadataResultPath = Resolve-RepoPath $HostedPayloadMetadataResultPath
$resolvedHostedPayloadIndexPath = Resolve-RepoPath $HostedPayloadIndexPath
$resolvedHostedInstallBootstrapPath = Resolve-RepoPath $HostedInstallBootstrapPath
$resolvedHostedChannelIndexPath = Resolve-RepoPath $HostedChannelIndexPath
$resolvedPayloadManifestPath = Resolve-RepoPath $PayloadManifestPath
$resolvedPayloadChecksumsPath = Resolve-RepoPath $PayloadChecksumsPath
$resolvedPayloadSignaturesPath = Resolve-RepoPath $PayloadSignaturesPath

$hostedResult = Read-Json $resolvedHostedPayloadMetadataResultPath
$script:baselinePayloadIndex = Read-Json $resolvedHostedPayloadIndexPath
$script:baselineInstallBootstrap = Read-Json $resolvedHostedInstallBootstrapPath
$script:baselineChannelIndex = Read-Json $resolvedHostedChannelIndexPath
$script:baselineManifest = Read-Json $resolvedPayloadManifestPath
$script:baselineChecksums = Read-Json $resolvedPayloadChecksumsPath
$script:baselineSignatures = Read-Json $resolvedPayloadSignaturesPath

$script:baselineManifestContentSha256 = $hostedResult.output_hashes.payload_manifest_content_sha256
$script:baselineChecksumsContentSha256 = $hostedResult.output_hashes.payload_checksums_content_sha256
$script:baselineSignaturesContentSha256 = $hostedResult.output_hashes.payload_signatures_content_sha256

Add-Check "hosted_payload_metadata.ready" ($hostedResult.status -eq "passed" -and $hostedResult.summary.blockers -eq 0) "RC6-011 hosted payload metadata must be passed before fail-closed fixtures." $hostedResult.summary
Add-Check "baseline.payload_index.schema" ($script:baselinePayloadIndex.schema -eq "agentos.rc6-hosted-payload-index.v1") "Hosted payload index baseline schema must be exact." $script:baselinePayloadIndex.schema
Add-Check "baseline.payload.blocked" ($script:baselinePayloadIndex.entries[0].status -eq "verification-blocked" -and $script:baselineInstallBootstrap.current_state -eq "verification-blocked") "Baseline hosted payload metadata must remain verification-blocked." ([ordered]@{ payload = $script:baselinePayloadIndex.entries[0].status; install = $script:baselineInstallBootstrap.current_state })

$cases = @(
    (New-FixtureCase -Id "bad-payload-index-schema" -ExpectedReasons @("bad-payload-index-schema") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.schema = "bad.schema" })
    (New-FixtureCase -Id "production-ready-claim" -ExpectedReasons @("production-ready-claim") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.production_ready_claim = $true })
    (New-FixtureCase -Id "manifest-hash-mismatch" -ExpectedReasons @("manifest-hash-mismatch") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.entries[0].manifest_sha256 = "0000" })
    (New-FixtureCase -Id "checksums-hash-mismatch" -ExpectedReasons @("checksums-hash-mismatch") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.entries[0].checksums_sha256 = "0000" })
    (New-FixtureCase -Id "signatures-hash-mismatch" -ExpectedReasons @("signatures-hash-mismatch") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.entries[0].signatures_sha256 = "0000" })
    (New-FixtureCase -Id "missing-signature-reference" -ExpectedReasons @("missing-signature-reference") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.signature_available = $false })
    (New-FixtureCase -Id "placeholder-signature-authority" -ExpectedReasons @("placeholder-signature-authority") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.signature_available = $true; $s | Add-Member -NotePropertyName "placeholder_is_authority" -NotePropertyValue $true -Force })
    (New-FixtureCase -Id "mirror-signing-authority" -ExpectedReasons @("mirror-signing-authority") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.signing_authority_on_mirror = $true })
    (New-FixtureCase -Id "missing-revocation-snapshot" -ExpectedReasons @("missing-revocation-snapshot") -Mutate { param($p,$m,$c,$s,$i,$ch) $s.PSObject.Properties.Remove("revocation_snapshot_sha256") })
    (New-FixtureCase -Id "revoked-signing-key" -ExpectedReasons @("revoked-signing-key") -Mutate { param($p,$m,$c,$s,$i,$ch) $s | Add-Member -NotePropertyName "revocation_status" -NotePropertyValue "revoked" -Force })
    (New-FixtureCase -Id "stale-payload-metadata" -ExpectedReasons @("stale-payload-metadata") -Mutate { param($p,$m,$c,$s,$i,$ch) $s | Add-Member -NotePropertyName "freshness_status" -NotePropertyValue "stale" -Force })
    (New-FixtureCase -Id "large-payload-url-before-policy" -ExpectedReasons @("large-payload-url-before-storage-policy") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.storage_policy.large_payload_url = "https://example.invalid/aios.img" })
    (New-FixtureCase -Id "large-payload-storage-enabled" -ExpectedReasons @("large-payload-storage-enabled") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.storage_policy.large_payload_storage_enabled = $true })
    (New-FixtureCase -Id "declared-drift-not-blocking" -ExpectedReasons @("declared-hash-drift-not-blocking") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.drift_policy.drift_blocks_install = $false })
    (New-FixtureCase -Id "missing-rollback-baseline" -ExpectedReasons @("missing-rollback-baseline") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.install_policy.PSObject.Properties.Remove("rollback_baseline_sha256") })
    (New-FixtureCase -Id "missing-installer-compatibility-contract" -ExpectedReasons @("missing-installer-compatibility-contract") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.install_policy.PSObject.Properties.Remove("installer_compatibility_contract_sha256") })
    (New-FixtureCase -Id "payload-entry-authority-broadening" -ExpectedReasons @("payload-entry-authority-broadening") -Mutate { param($p,$m,$c,$s,$i,$ch) $p.entries[0].install_allowed = $true })
    (New-FixtureCase -Id "manifest-install-authority-broadening" -ExpectedReasons @("manifest-install-authority-broadening") -Mutate { param($p,$m,$c,$s,$i,$ch) $m.install_policy.install_allowed = $true })
    (New-FixtureCase -Id "install-bootstrap-authority-broadening" -ExpectedReasons @("install-bootstrap-authority-broadening") -Mutate { param($p,$m,$c,$s,$i,$ch) $i.install_allowed = $true })
    (New-FixtureCase -Id "preflight-ready-without-signature" -ExpectedReasons @("preflight-ready-without-signature") -Mutate { param($p,$m,$c,$s,$i,$ch) $i.current_state = "install-preflight-ready"; $s.signature_available = $false })
    (New-FixtureCase -Id "channel-authority-broadening" -ExpectedReasons @("channel-authority-broadening") -Mutate { param($p,$m,$c,$s,$i,$ch) $ch.authority.tui_authority = $true })
)

$passedCases = @($cases | Where-Object { $_.status -eq "passed" })
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "fixtures.all_blocked" ($failedCases.Count -eq 0 -and $passedCases.Count -eq $cases.Count) "All signed payload metadata negative fixtures must fail closed." ([ordered]@{ passed = $passedCases.Count; failed = $failedCases.Count })

$resultPreviewText = ($cases | ConvertTo-Json -Depth 100)
Add-Check "fixtures.secret_safe" (Test-NoSensitiveText -Values @($resultPreviewText)) "Fail-closed fixture results must not contain private key or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-signed-payload-fail-closed-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC6-012"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    source = [ordered]@{
        hosted_payload_metadata_result = [ordered]@{ path = Get-StablePath $resolvedHostedPayloadMetadataResultPath; sha256 = Get-FileSha256 $resolvedHostedPayloadMetadataResultPath }
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
        activation_allowed = $false
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
        rc6_012_complete = $passed
        next_task = "RC6-020"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC6 signed payload fail-closed fixtures $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
