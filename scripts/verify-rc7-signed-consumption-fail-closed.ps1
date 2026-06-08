param(
    [string]$ArtifactDir = ".workflow/artifacts/rc7-signed-consumption-fail-closed",
    [string]$ResultPath = "",
    [string]$Rc7ConsumptionResultPath = ".workflow/artifacts/rc7-installer-signed-consumption/result.json",
    [string]$Rc7ConsumptionReportPath = ".workflow/artifacts/rc7-installer-signed-consumption/consumption-report.json",
    [string]$Rc7SignedMetadataResultPath = ".workflow/artifacts/rc7-signed-metadata-revocation/result.json",
    [string]$PayloadIndexPath = ".workflow/artifacts/rc7-signed-metadata-revocation/hosted-payload-index-after-signed-metadata.json",
    [string]$InstallBootstrapPath = ".workflow/artifacts/rc7-signed-metadata-revocation/install-bootstrap-after-signed-metadata.json",
    [string]$PayloadSignaturesPath = ".workflow/artifacts/rc7-signed-metadata-revocation/payload-signatures-after-rc7.json",
    [string]$SignedMetadataPath = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json",
    [string]$RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$Rc7CompatibilityContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/installer-compatibility-rollback-baseline-contract.md",
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

function Get-JsonSha256 {
    param([Parameter(Mandatory = $true)]$Value)
    return Get-StringSha256 ($Value | ConvertTo-Json -Depth 100)
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

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
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

function Test-StaleDate {
    param($Value)
    if (-not (Has-Value $Value)) {
        return $true
    }
    try {
        $dt = [DateTimeOffset]::Parse([string]$Value)
        return $dt -lt [DateTimeOffset]::Now
    } catch {
        return $true
    }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function New-FixtureState {
    return [ordered]@{
        payload_index = Convert-JsonClone $script:payloadIndex
        install_bootstrap = Convert-JsonClone $script:installBootstrap
        signatures = Convert-JsonClone $script:payloadSignatures
        signed_metadata = Convert-JsonClone $script:signedMetadata
        revocations = Convert-JsonClone $script:revocationSnapshot
        compatibility = $null
        rollback_baseline = $null
        hosted_byte_hashes_match = $script:hostedByteHashesMatch
        exact_approval_present = $false
        tls_verified = $false
    }
}

function Invoke-InstallerEvaluation {
    param([Parameter(Mandatory = $true)]$Fixture)

    $reasons = [System.Collections.Generic.List[string]]::new()
    $payloadIndex = $Fixture.payload_index
    $install = $Fixture.install_bootstrap
    $signatures = $Fixture.signatures
    $signed = $Fixture.signed_metadata
    $revocations = $Fixture.revocations
    $entry = if ($null -ne $payloadIndex -and $null -ne $payloadIndex.entries) { @($payloadIndex.entries)[0] } else { $null }

    if ($payloadIndex.schema -ne "agentos.rc7-hosted-payload-index.v1") {
        Add-Reason $reasons "bad-payload-index-schema"
    }
    if ($install.schema -ne "agentos.rc7-install-bootstrap.v1") {
        Add-Reason $reasons "bad-install-bootstrap-schema"
    }
    if ($signatures.schema -ne "agentos.rc7-installable-payload-signatures.v1") {
        Add-Reason $reasons "bad-signatures-schema"
    }
    if ($signed.schema -ne "agentos.rc7-signed-metadata-projection.v1") {
        Add-Reason $reasons "bad-signed-metadata-schema"
    }
    if ($revocations.schema -ne "agentos.rc7-revocation-snapshot.v1") {
        Add-Reason $reasons "bad-revocation-schema"
    }

    if ($payloadIndex.production_ready_claim -eq $true -or $install.production_ready_claim -eq $true -or $signatures.production_ready_claim -eq $true -or $signed.production_ready_claim -eq $true -or $revocations.production_ready_claim -eq $true) {
        Add-Reason $reasons "production-ready-claim"
    }

    if ($null -eq $entry) {
        Add-Reason $reasons "missing-payload-index-entry"
    } else {
        if ($entry.status -ne "verification-blocked") {
            Add-Reason $reasons "payload-status-not-blocked"
        }
        if ($entry.install_allowed -eq $true -or $entry.activation_allowed -eq $true -or $entry.rollback_execution_allowed -eq $true) {
            Add-Reason $reasons "payload-authority-broadening"
        }
        if ($entry.manifest_sha256 -ne $script:expectedManifestHash) {
            Add-Reason $reasons "payload-manifest-hash-mismatch"
        }
        if ($entry.checksums_sha256 -ne $script:expectedChecksumsHash) {
            Add-Reason $reasons "payload-checksums-hash-mismatch"
        }
        if (-not (Has-Value $entry.signatures_path) -or -not (Has-Value $signatures.signed_metadata_path) -or -not (Has-Value $entry.signed_metadata_path)) {
            Add-Reason $reasons "missing-signed-metadata-reference"
        } elseif ($entry.signatures_sha256 -ne $script:expectedSignaturesHash -or $entry.signed_metadata_sha256 -ne $script:expectedSignedMetadataHash -or $signatures.signed_metadata_sha256 -ne $script:expectedSignedMetadataHash) {
            Add-Reason $reasons "signed-metadata-hash-mismatch"
        }
        if (-not (Has-Value $entry.revocations_path) -or -not (Has-Value $signatures.revocation_snapshot_path) -or -not (Has-Value $signatures.revocation_snapshot_sha256)) {
            Add-Reason $reasons "missing-revocation-snapshot"
        } elseif ($entry.revocation_snapshot_sha256 -ne $script:expectedRevocationHash -or $signatures.revocation_snapshot_sha256 -ne $script:expectedRevocationHash) {
            Add-Reason $reasons "revocation-snapshot-hash-mismatch"
        }
        if ($entry.installable_media_declared_hash_drift_count -gt 0) {
            Add-Reason $reasons "declared-current-hash-drift"
        }
        if ($entry.large_payload_deferred -eq $true -or $payloadIndex.storage_mode -eq "metadata-only") {
            Add-Reason $reasons "large-payload-storage-policy-pending"
        }
    }

    if ($signatures.signing_authority_on_mirror -eq $true -or $payloadIndex.authority.signing_authority -eq $true) {
        Add-Reason $reasons "mirror-signing-authority"
    }
    if ($signatures.cryptographic_signature_present -ne $true -or $signatures.signature_available -ne $true -or $signed.cryptographic_signature_present -ne $true -or -not (Has-Value $signed.signature_value)) {
        Add-Reason $reasons "cryptographic-signature-not-present"
    }
    if ($signed.signature_claims.release_id -ne $entry.release_id) {
        Add-Reason $reasons "signature-claims-release-mismatch"
    }
    if ($signed.signature_claims.payload_manifest_content_sha256 -ne $entry.manifest_sha256) {
        Add-Reason $reasons "signature-claims-payload-mismatch"
    }
    if ($signed.signature_claims.revocation_snapshot_sha256 -ne $signatures.revocation_snapshot_sha256) {
        Add-Reason $reasons "signature-claims-revocation-mismatch"
    }

    if ($revocations.revocation_status -eq "revoked") {
        Add-Reason $reasons "revoked-signing-key"
    }
    if (Test-StaleDate $revocations.valid_until) {
        Add-Reason $reasons "stale-revocation-snapshot"
    }

    if ($Fixture.hosted_byte_hashes_match -ne $true) {
        Add-Reason $reasons "hosted-byte-hash-canonicalization"
    }

    if ($null -eq $Fixture.compatibility) {
        Add-Reason $reasons "missing-installer-compatibility-contract"
    } elseif ($Fixture.compatibility.schema -ne "agentos.rc7-installer-compatibility.v1") {
        Add-Reason $reasons "compatibility-schema-mismatch"
    } else {
        $compatHash = Get-JsonSha256 $Fixture.compatibility
        $installCompatHash = if ($install.projection.PSObject.Properties.Name -contains "installer_compatibility_sha256") { $install.projection.installer_compatibility_sha256 } else { $null }
        if ($installCompatHash -ne $compatHash) {
            Add-Reason $reasons "compatibility-hash-mismatch"
        }
        if ($Fixture.compatibility.release_id -ne $entry.release_id) {
            Add-Reason $reasons "compatibility-release-mismatch"
        }
    }

    if ($null -eq $Fixture.rollback_baseline) {
        Add-Reason $reasons "missing-rollback-baseline"
    } elseif ($Fixture.rollback_baseline.schema -ne "agentos.rc7-rollback-baseline.v1") {
        Add-Reason $reasons "rollback-baseline-schema-mismatch"
    } else {
        $rollbackHash = Get-JsonSha256 $Fixture.rollback_baseline
        $installRollbackHash = if ($install.projection.PSObject.Properties.Name -contains "rollback_baseline_sha256") { $install.projection.rollback_baseline_sha256 } else { $null }
        if ($installRollbackHash -ne $rollbackHash) {
            Add-Reason $reasons "rollback-baseline-hash-mismatch"
        }
        if ($Fixture.rollback_baseline.release_id -ne $entry.release_id) {
            Add-Reason $reasons "rollback-baseline-release-mismatch"
        }
    }

    if ($install.tls_required_before_ga_claim -eq $true -and $Fixture.tls_verified -ne $true) {
        Add-Reason $reasons "tls-required-before-ga-claim"
    }
    if ($Fixture.exact_approval_present -ne $true) {
        Add-Reason $reasons "exact-approval-not-present"
    }
    if ($install.install_allowed -eq $true -or $install.activation_allowed -eq $true -or $payloadIndex.authority.activation_authority -eq $true -or $payloadIndex.authority.rollback_execution_authority -eq $true -or $payloadIndex.authority.remote_dispatch_authority -eq $true -or $payloadIndex.authority.tui_authority -eq $true) {
        Add-Reason $reasons "authority-broadening"
    }

    $state = if ($reasons.Count -eq 0) { "signed-consumption-ready" } else { "verification-blocked" }
    return [ordered]@{
        observed_state = $state
        observed_reasons = @($reasons)
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
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons,
        [scriptblock]$Mutate
    )
    $fixture = New-FixtureState
    if ($null -ne $Mutate) {
        & $Mutate $fixture
    }
    $evaluation = Invoke-InstallerEvaluation $fixture
    $missing = @($ExpectedReasons | Where-Object { $_ -notin $evaluation.observed_reasons })
    $sideEffectsClear = (
        $evaluation.side_effects.install_performed -eq $false -and
        $evaluation.side_effects.activation_performed -eq $false -and
        $evaluation.side_effects.rollback_execution_performed -eq $false -and
        $evaluation.side_effects.production_ring_mutated -eq $false -and
        $evaluation.side_effects.remote_dispatch_enabled -eq $false -and
        $evaluation.side_effects.tui_authority -eq $false
    )
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0 -and $evaluation.observed_state -eq "verification-blocked" -and $sideEffectsClear) { "passed" } else { "failed" }
        expected_reasons = $ExpectedReasons
        missing_expected_reasons = $missing
        observed_state = $evaluation.observed_state
        observed_reasons = $evaluation.observed_reasons
        side_effects = $evaluation.side_effects
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

$resolvedRc7ConsumptionResultPath = Resolve-RepoPath $Rc7ConsumptionResultPath
$resolvedRc7ConsumptionReportPath = Resolve-RepoPath $Rc7ConsumptionReportPath
$resolvedRc7SignedMetadataResultPath = Resolve-RepoPath $Rc7SignedMetadataResultPath
$resolvedPayloadIndexPath = Resolve-RepoPath $PayloadIndexPath
$resolvedInstallBootstrapPath = Resolve-RepoPath $InstallBootstrapPath
$resolvedPayloadSignaturesPath = Resolve-RepoPath $PayloadSignaturesPath
$resolvedSignedMetadataPath = Resolve-RepoPath $SignedMetadataPath
$resolvedRevocationSnapshotPath = Resolve-RepoPath $RevocationSnapshotPath
$resolvedRc7CompatibilityContractPath = Resolve-RepoPath $Rc7CompatibilityContractPath

$generatedAt = (Get-Date).ToString("o")
$rc7ConsumptionResult = Read-Json $resolvedRc7ConsumptionResultPath
$rc7ConsumptionReport = Read-Json $resolvedRc7ConsumptionReportPath
$rc7SignedResult = Read-Json $resolvedRc7SignedMetadataResultPath
$script:payloadIndex = Read-Json $resolvedPayloadIndexPath
$script:installBootstrap = Read-Json $resolvedInstallBootstrapPath
$script:payloadSignatures = Read-Json $resolvedPayloadSignaturesPath
$script:signedMetadata = Read-Json $resolvedSignedMetadataPath
$script:revocationSnapshot = Read-Json $resolvedRevocationSnapshotPath
$compatContractText = Get-Content -Raw -LiteralPath $resolvedRc7CompatibilityContractPath

$script:entry = @($script:payloadIndex.entries)[0]
$script:expectedManifestHash = $rc7SignedResult.output_hashes.payload_manifest_content_sha256
$script:expectedChecksumsHash = $rc7SignedResult.output_hashes.payload_checksums_content_sha256
$script:expectedSignaturesHash = $rc7SignedResult.output_hashes.payload_signatures_sha256
$script:expectedSignedMetadataHash = $rc7SignedResult.output_hashes.signed_metadata_sha256
$script:expectedRevocationHash = $rc7SignedResult.output_hashes.revocation_snapshot_sha256
$script:hostedByteHashesMatch = -not (@($rc7ConsumptionReport.installer_blockers | Where-Object { $_.id -eq "verify-hosted-byte-hash-canonicalization" }).Count -gt 0)

Add-Check "source.rc7_010.result" ($rc7ConsumptionResult.status -eq "passed" -and $rc7ConsumptionResult.summary.blockers -eq 0 -and $rc7ConsumptionResult.consumption_summary.signed_metadata_observed -eq $true -and $rc7ConsumptionResult.consumption_summary.revocation_snapshot_observed -eq $true) "RC7-010 consumption report must pass and observe signed metadata plus revocation references." $rc7ConsumptionResult.summary
Add-Check "source.rc7_010.blocked_installer" ($rc7ConsumptionReport.state -eq "verification-blocked" -and @($rc7ConsumptionReport.installer_blockers).Count -ge 7) "RC7-010 installer state must remain verification-blocked with recorded blockers." ([ordered]@{ state = $rc7ConsumptionReport.state; installer_blockers = @($rc7ConsumptionReport.installer_blockers).Count })
Add-Check "source.rc7_003.contract" ($compatContractText.Contains("Fail-Closed Cases") -and $compatContractText.Contains("/install/compatibility.json") -and $compatContractText.Contains("/install/rollback-baseline.json")) "RC7-003 contract must define compatibility, rollback baseline, and fail-closed cases." (Get-StablePath $resolvedRc7CompatibilityContractPath)

$cases = @()
$cases += Invoke-Case "base-current-consumption-remains-blocked" @("hosted-byte-hash-canonicalization", "cryptographic-signature-not-present", "missing-installer-compatibility-contract", "missing-rollback-baseline")
$cases += Invoke-Case "missing-signed-metadata-reference" @("missing-signed-metadata-reference") {
    param($f)
    Set-JsonProperty $f.signatures "signed_metadata_path" $null
    Set-JsonProperty $f.signatures "signed_metadata_sha256" $null
}
$cases += Invoke-Case "signed-metadata-hash-mismatch" @("signed-metadata-hash-mismatch") {
    param($f)
    $entry = @($f.payload_index.entries)[0]
    $entry.signed_metadata_sha256 = "bad-signed-metadata-sha256"
}
$cases += Invoke-Case "signature-claims-revocation-mismatch" @("signature-claims-revocation-mismatch") {
    param($f)
    $f.signed_metadata.signature_claims.revocation_snapshot_sha256 = "bad-revocation-sha256"
}
$cases += Invoke-Case "missing-revocation-snapshot" @("missing-revocation-snapshot") {
    param($f)
    $entry = @($f.payload_index.entries)[0]
    $entry.revocations_path = $null
    $entry.revocation_snapshot_sha256 = $null
    Set-JsonProperty $f.signatures "revocation_snapshot_path" $null
    Set-JsonProperty $f.signatures "revocation_snapshot_sha256" $null
}
$cases += Invoke-Case "revocation-snapshot-hash-mismatch" @("revocation-snapshot-hash-mismatch", "signature-claims-revocation-mismatch") {
    param($f)
    $f.signatures.revocation_snapshot_sha256 = "bad-revocation-sha256"
}
$cases += Invoke-Case "revoked-signing-key" @("revoked-signing-key") {
    param($f)
    $f.revocations.revocation_status = "revoked"
}
$cases += Invoke-Case "stale-revocation-snapshot" @("stale-revocation-snapshot") {
    param($f)
    $f.revocations.valid_until = "2020-01-01T00:00:00+00:00"
}
$cases += Invoke-Case "cryptographic-signature-missing" @("cryptographic-signature-not-present") {
    param($f)
    $f.signatures.signature_available = $false
    $f.signatures.cryptographic_signature_present = $false
    $f.signed_metadata.cryptographic_signature_present = $false
    $f.signed_metadata.signature_value = $null
}
$cases += Invoke-Case "mirror-signing-authority" @("mirror-signing-authority") {
    param($f)
    $f.signatures.signing_authority_on_mirror = $true
}
$cases += Invoke-Case "missing-installer-compatibility-contract" @("missing-installer-compatibility-contract") {
    param($f)
    $f.compatibility = $null
}
$cases += Invoke-Case "compatibility-schema-mismatch" @("compatibility-schema-mismatch") {
    param($f)
    $f.compatibility = [pscustomobject][ordered]@{
        schema = "bad.schema"
        release_id = $script:entry.release_id
        status = "compatibility-projected-verification-blocked"
    }
}
$cases += Invoke-Case "compatibility-hash-mismatch" @("compatibility-hash-mismatch") {
    param($f)
    $f.compatibility = [pscustomobject][ordered]@{
        schema = "agentos.rc7-installer-compatibility.v1"
        release_id = $script:entry.release_id
        status = "compatibility-projected-verification-blocked"
    }
    Set-JsonProperty $f.install_bootstrap.projection "installer_compatibility_sha256" "bad-compatibility-sha256"
}
$cases += Invoke-Case "missing-rollback-baseline" @("missing-rollback-baseline") {
    param($f)
    $f.rollback_baseline = $null
}
$cases += Invoke-Case "rollback-baseline-schema-mismatch" @("rollback-baseline-schema-mismatch") {
    param($f)
    $f.rollback_baseline = [pscustomobject][ordered]@{
        schema = "bad.schema"
        release_id = $script:entry.release_id
        status = "rollback-baseline-projected-execution-blocked"
    }
}
$cases += Invoke-Case "rollback-baseline-hash-mismatch" @("rollback-baseline-hash-mismatch") {
    param($f)
    $f.rollback_baseline = [pscustomobject][ordered]@{
        schema = "agentos.rc7-rollback-baseline.v1"
        release_id = $script:entry.release_id
        status = "rollback-baseline-projected-execution-blocked"
    }
    Set-JsonProperty $f.install_bootstrap.projection "rollback_baseline_sha256" "bad-rollback-sha256"
}
$cases += Invoke-Case "production-ready-claim" @("production-ready-claim") {
    param($f)
    $f.payload_index.production_ready_claim = $true
}
$cases += Invoke-Case "payload-authority-broadening" @("payload-authority-broadening", "authority-broadening") {
    param($f)
    $entry = @($f.payload_index.entries)[0]
    $entry.install_allowed = $true
    $f.install_bootstrap.install_allowed = $true
}
$cases += Invoke-Case "remote-dispatch-or-tui-authority" @("authority-broadening") {
    param($f)
    $f.payload_index.authority.remote_dispatch_authority = $true
    $f.payload_index.authority.tui_authority = $true
}
$cases += Invoke-Case "storage-drift-not-resolved" @("declared-current-hash-drift", "large-payload-storage-policy-pending") {
    param($f)
    $entry = @($f.payload_index.entries)[0]
    $entry.installable_media_declared_hash_drift_count = 3
    $entry.large_payload_deferred = $true
    $f.payload_index.storage_mode = "metadata-only"
}
$cases += Invoke-Case "tls-and-exact-approval-missing" @("tls-required-before-ga-claim", "exact-approval-not-present") {
    param($f)
    $f.tls_verified = $false
    $f.exact_approval_present = $false
}

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "fixtures.all_cases_passed" ($failedCases.Count -eq 0) "All RC7 signed consumption negative fixtures must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = $failedCases.Count })
Add-Check "fixtures.no_side_effects" (@($cases | Where-Object { $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.production_ring_mutated -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.tui_authority }).Count -eq 0) "Fixtures must not perform install, activation, rollback, ring mutation, dispatch, or TUI authority." $null

$result = [ordered]@{
    schema = "agentos.rc7-signed-consumption-fail-closed-result.v1"
    generated_at = $generatedAt
    task = "RC7-011"
    status = if (@($script:blockers).Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    source = [ordered]@{
        rc7_consumption_result = New-ArtifactRef $resolvedRc7ConsumptionResultPath $rc7ConsumptionResult
        rc7_consumption_report = New-ArtifactRef $resolvedRc7ConsumptionReportPath $rc7ConsumptionReport
        rc7_signed_metadata_revocation = New-ArtifactRef $resolvedRc7SignedMetadataResultPath $rc7SignedResult
        payload_index = New-ArtifactRef $resolvedPayloadIndexPath $script:payloadIndex
        install_bootstrap = New-ArtifactRef $resolvedInstallBootstrapPath $script:installBootstrap
        payload_signatures = New-ArtifactRef $resolvedPayloadSignaturesPath $script:payloadSignatures
        signed_metadata = New-ArtifactRef $resolvedSignedMetadataPath $script:signedMetadata
        revocation_snapshot = New-ArtifactRef $resolvedRevocationSnapshotPath $script:revocationSnapshot
        rc7_compatibility_rollback_contract = [ordered]@{
            path = Get-StablePath $resolvedRc7CompatibilityContractPath
            sha256 = Get-FileSha256 $resolvedRc7CompatibilityContractPath
        }
    }
    cases = $cases
    invariants = [ordered]@{
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        remote_publication_performed = $false
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
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = $failedCases.Count
        rc7_011_complete = @($script:blockers).Count -eq 0
        next_task = "RC7-012"
    }
}

Write-Json $result $resolvedResultPath
$resultText = Get-Content -Raw -LiteralPath $resolvedResultPath
if (-not (Test-NoSensitiveText -Values @($resultText))) {
    throw "Sensitive marker detected in RC7-011 result."
}

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}

Write-Host "RC7 signed consumption fail-closed fixtures: $($result.status)"
Write-Host "Cases: $(@($cases).Count), failed: $($failedCases.Count)"
Write-Host "Result: $(Get-StablePath $resolvedResultPath)"
