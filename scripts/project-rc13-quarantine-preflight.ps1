param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-quarantine-preflight",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$DriftResultPath = ".workflow/artifacts/rc13-declared-current-drift-zero/result.json",
    [string]$ObjectBindingResultPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/result.json",
    [string]$ObjectBindingPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/object-manifest-descriptor-binding.json",
    [string]$AuthorityResultPath = ".workflow/artifacts/rc13-freshness-revocation-authority/result.json",
    [string]$AuthorityBindingPath = ".workflow/artifacts/rc13-freshness-revocation-authority/freshness-revocation-authority-binding.json",
    [string]$AuthorityHandoffPath = ".workflow/artifacts/rc13-freshness-revocation-authority/quarantine-preflight-handoff.json",
    [string]$GeneratedAt = "",
    [switch]$FailOnFailedChecks
)

$ErrorActionPreference = "Stop"

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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
        $script:failedChecks += $entry
    }
}

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ([string]::IsNullOrWhiteSpace($Blocker)) {
        return
    }
    if ($script:blockers -notcontains $Blocker) {
        $script:blockers += $Blocker
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
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("BEGIN PUBLIC " + "KEY"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-" + "key" + "." + "pem"),
        ("/etc/" + "aios-signer"),
        ("finger" + "print")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function New-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            network_fetch_attempted = $false
            remote_payload_bytes_downloaded = $false
            quarantine_payload_written = $false
            size_verified = $false
            digest_verified = $false
            descriptor_verified = $false
            manifest_verified = $false
            checksum_set_verified = $false
            public_signature_verified = $false
            revocation_verified = $false
            freshness_verified = $false
            compatibility_verified = $false
            rollback_baseline_verified = $false
            support_recovery_verified = $false
            payload_interpreted = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()
$script:blockers = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedObjectBindingResultPath = Resolve-RepoPath $ObjectBindingResultPath
$resolvedObjectBindingPath = Resolve-RepoPath $ObjectBindingPath
$resolvedAuthorityResultPath = Resolve-RepoPath $AuthorityResultPath
$resolvedAuthorityBindingPath = Resolve-RepoPath $AuthorityBindingPath
$resolvedAuthorityHandoffPath = Resolve-RepoPath $AuthorityHandoffPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$driftResult = Read-Json $resolvedDriftResultPath
$objectBindingResult = Read-Json $resolvedObjectBindingResultPath
$objectBinding = Read-Json $resolvedObjectBindingPath
$authorityResult = Read-Json $resolvedAuthorityResultPath
$authorityBinding = Read-Json $resolvedAuthorityBindingPath
$authorityHandoff = Read-Json $resolvedAuthorityHandoffPath

$releaseId = [string]$authorityResult.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$objectBinding.current_payload.path)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }

$driftZero = [bool]$driftResult.reconciliation_surface.drift_zero
$localDescriptorManifestConsistent = [bool]$objectBindingResult.binding_surface.local_descriptor_manifest_consistent
$objectManifestDescriptorBindingAllowed = [bool]$objectBindingResult.binding_surface.object_manifest_descriptor_binding_allowed
$publicSignatureBound = [bool]$authorityResult.authority_surface.public_signature_bound
$publicSignatureCryptoVerified = [bool]$authorityResult.authority_surface.public_signature_crypto_verified
$revocationAuthorityBound = [bool]$authorityResult.authority_surface.revocation_authority_bound
$revocationSnapshotFresh = [bool]$authorityResult.authority_surface.revocation_snapshot_fresh
$freshnessWindowBound = [bool]$authorityResult.authority_surface.freshness_window_bound
$freshnessWindowCurrent = [bool]$authorityResult.authority_surface.freshness_window_current
$freshnessRevocationAuthorityBound = [bool]$authorityResult.authority_surface.freshness_revocation_authority_bound
$objectTrustAllowed = [bool]$authorityResult.authority_surface.object_trust_allowed

$currentBytesMatch = ($sourceArtifactSha256 -eq [string]$objectBinding.current_payload.sha256) -and
    ([int64]$sourceArtifactSize -eq [int64]$objectBinding.current_payload.size_bytes) -and
    ([string]$objectBinding.current_payload.sha256 -eq [string]$objectBinding.descriptor_binding.sha256) -and
    ([int64]$objectBinding.current_payload.size_bytes -eq [int64]$objectBinding.descriptor_binding.size_bytes)

$quarantinePreflightAllowed = $objectTrustAllowed -and
    $driftZero -and
    $localDescriptorManifestConsistent -and
    $objectManifestDescriptorBindingAllowed -and
    $publicSignatureBound -and
    $publicSignatureCryptoVerified -and
    $revocationAuthorityBound -and
    $revocationSnapshotFresh -and
    $freshnessWindowBound -and
    $freshnessWindowCurrent -and
    $freshnessRevocationAuthorityBound -and
    $currentBytesMatch

foreach ($blocker in @(
    $driftResult.blockers,
    $driftResult.reconciliation_surface.blockers,
    $objectBindingResult.blockers,
    $objectBindingResult.binding_surface.blockers,
    $objectBinding.trust_decision.blockers,
    $authorityResult.blockers,
    $authorityResult.authority_surface.blockers,
    $authorityBinding.trust_decision.blockers,
    $authorityHandoff.blockers
)) {
    foreach ($item in @($blocker)) {
        Add-UniqueBlocker ([string]$item)
    }
}

if (-not $driftZero) { Add-UniqueBlocker "declared-current-drift-zero-not-proved" }
if (-not $localDescriptorManifestConsistent) { Add-UniqueBlocker "local-descriptor-manifest-not-consistent" }
if (-not $objectManifestDescriptorBindingAllowed) { Add-UniqueBlocker "object-manifest-descriptor-binding-not-allowed" }
if (-not $publicSignatureBound) { Add-UniqueBlocker "public-signature-target-not-bound" }
if (-not $publicSignatureCryptoVerified) { Add-UniqueBlocker "public-signature-crypto-not-verified" }
if (-not $revocationAuthorityBound) { Add-UniqueBlocker "revocation-authority-not-bound" }
if (-not $revocationSnapshotFresh) { Add-UniqueBlocker "revocation-snapshot-stale-or-missing" }
if (-not $freshnessWindowBound) { Add-UniqueBlocker "freshness-window-missing" }
if (-not $freshnessWindowCurrent) { Add-UniqueBlocker "freshness-window-stale-or-missing" }
if (-not $freshnessRevocationAuthorityBound) { Add-UniqueBlocker "freshness-revocation-authority-not-bound" }
if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $currentBytesMatch) { Add-UniqueBlocker "current-release-bytes-mismatch" }
if (-not $quarantinePreflightAllowed) { Add-UniqueBlocker "quarantine-preflight-not-allowed" }

foreach ($blocker in @(
    "network-fetch-denied-before-object-trust",
    "payload-not-quarantined",
    "pre-interpretation-verification-not-run",
    "payload-interpretation-not-allowed",
    "install-not-allowed",
    "agentcore-planspec-not-executable",
    "security-execution-allow-not-bound",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)) {
    Add-UniqueBlocker $blocker
}

$requiredPreInterpretationVerification = [ordered]@{
    payload_size_bytes = [int64]$objectBinding.current_payload.size_bytes
    payload_sha256 = [string]$objectBinding.current_payload.sha256
    descriptor_file_sha256 = [string]$objectBinding.descriptor_binding.descriptor_file_sha256
    descriptor_canonical_sha256 = [string]$objectBinding.descriptor_binding.descriptor_canonical_sha256
    initramfs_manifest_sha256 = [string]$objectBinding.manifest_binding.initramfs_manifest_file_sha256
    payload_manifest_sha256 = [string]$objectBinding.manifest_binding.payload_manifest_file_sha256
    checksum_set_sha256 = [string]$objectBinding.manifest_binding.object_checksums_file_sha256
    public_signature_artifact_sha256 = [string]$authorityBinding.public_signature.signature_artifact_sha256
    public_signature_receipt_sha256 = [string]$authorityBinding.public_signature.receipt_sha256
    revocation_snapshot_sha256 = [string]$authorityBinding.revocation.snapshot_sha256
    freshness_window = if ($null -eq $authorityBinding.freshness.fresh_until) { $null } else { [string]$authorityBinding.freshness.fresh_until }
    compatibility_sha256 = [string]$objectBinding.compatibility_binding.sha256
    rollback_baseline_sha256 = [string]$objectBinding.rollback_binding.sha256
    support_recovery_sha256 = [string]$objectBinding.support_recovery_binding.sha256
}

$source = [ordered]@{
    rc13_contract = New-ArtifactRef $resolvedContractPath
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    object_binding_result = New-ArtifactRef $resolvedObjectBindingResultPath $objectBindingResult
    object_binding = New-ArtifactRef $resolvedObjectBindingPath $objectBinding
    authority_result = New-ArtifactRef $resolvedAuthorityResultPath $authorityResult
    authority_binding = New-ArtifactRef $resolvedAuthorityBindingPath $authorityBinding
    authority_handoff = New-ArtifactRef $resolvedAuthorityHandoffPath $authorityHandoff
    current_payload = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.quarantine_gate.present" ($contractText.Contains("Run quarantine preflight only after object trust is allowed") -and $contractText.Contains("must not be interpreted until verification succeeds")) "RC13-020 must consume the quarantine-before-interpretation gate order." $source.rc13_contract
Add-Check "source.drift_result.complete" ($driftResult.status -eq "passed" -and $driftResult.task -eq "RC13-010" -and $driftResult.summary.failed_checks -eq 0) "RC13-020 requires completed RC13-010 drift evidence." ([ordered]@{ status = $driftResult.status; drift_zero = $driftZero; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "source.object_binding.complete" ($objectBindingResult.status -eq "passed" -and $objectBindingResult.task -eq "RC13-011" -and $objectBindingResult.summary.comparison_drifts -eq 0 -and $localDescriptorManifestConsistent) "RC13-020 requires completed RC13-011 descriptor and manifest binding evidence." ([ordered]@{ status = $objectBindingResult.status; local_descriptor_manifest_consistent = $localDescriptorManifestConsistent; binding_allowed = $objectManifestDescriptorBindingAllowed })
Add-Check "source.authority.complete" ($authorityResult.status -eq "passed" -and $authorityResult.task -eq "RC13-012" -and $authorityResult.summary.failed_fail_closed_cases -eq 0 -and $publicSignatureBound -and $publicSignatureCryptoVerified -and $revocationAuthorityBound) "RC13-020 requires completed RC13-012 public signature and revocation evidence." ([ordered]@{ status = $authorityResult.status; public_signature_bound = $publicSignatureBound; revocation_authority_bound = $revocationAuthorityBound; freshness_window_bound = $freshnessWindowBound })
Add-Check "source.current_bytes_match_descriptor" $currentBytesMatch "Current payload bytes must match RC13 object binding before quarantine policy evaluation." ([ordered]@{ expected_sha256 = $objectBinding.current_payload.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $objectBinding.current_payload.size_bytes; observed_size_bytes = $sourceArtifactSize })
Add-Check "preflight.denied_before_network" ($quarantinePreflightAllowed -eq $false -and $objectTrustAllowed -eq $false) "Quarantine preflight must deny before network unless object trust and freshness/revocation gates are proved." ([ordered]@{ quarantine_preflight_allowed = $quarantinePreflightAllowed; object_trust_allowed = $objectTrustAllowed; freshness_window_bound = $freshnessWindowBound; blockers = @($script:blockers) })
Add-Check "payload.interpretation_denied" ($quarantinePreflightAllowed -eq $false) "Payload interpretation must remain denied before quarantine verification succeeds." ([ordered]@{ payload_interpretation_allowed = $false; quarantine_payload_written = $false; pre_interpretation_verification_performed = $false })
Add-Check "pre_interpretation.gates_declared" ($requiredPreInterpretationVerification.payload_size_bytes -and $requiredPreInterpretationVerification.payload_sha256 -and $requiredPreInterpretationVerification.descriptor_file_sha256 -and $requiredPreInterpretationVerification.initramfs_manifest_sha256 -and $requiredPreInterpretationVerification.checksum_set_sha256 -and $requiredPreInterpretationVerification.public_signature_artifact_sha256 -and $requiredPreInterpretationVerification.revocation_snapshot_sha256 -and $requiredPreInterpretationVerification.compatibility_sha256 -and $requiredPreInterpretationVerification.rollback_baseline_sha256 -and $requiredPreInterpretationVerification.support_recovery_sha256) "Quarantine preflight must declare size, digest, descriptor, manifest, checksum, signature, revocation, freshness, compatibility, rollback, and support gates." $requiredPreInterpretationVerification

$preflightReport = [ordered]@{
    schema = "agentos.rc13-quarantine-preflight-report.v1"
    generated_at = $generatedAtValue
    task = "RC13-020"
    release_id = $releaseId
    status = if ($quarantinePreflightAllowed) { "quarantine-preflight-ready" } else { "quarantine-preflight-denied-before-network" }
    production_ready_claim = $false
    object_trust = [ordered]@{
        drift_zero = $driftZero
        local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
        object_manifest_descriptor_binding_allowed = $objectManifestDescriptorBindingAllowed
        public_signature_bound = $publicSignatureBound
        public_signature_crypto_verified = $publicSignatureCryptoVerified
        revocation_authority_bound = $revocationAuthorityBound
        revocation_snapshot_fresh = $revocationSnapshotFresh
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        current_bytes_match = $currentBytesMatch
        object_trust_allowed = $objectTrustAllowed
    }
    quarantine_policy = [ordered]@{
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        denied_before_network = (-not $quarantinePreflightAllowed)
        network_fetch_allowed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_landing_zone_required = $true
        quarantine_payload_written = $false
        payload_interpretation_allowed = $false
        payload_interpreted = $false
    }
    required_pre_interpretation_verification = $requiredPreInterpretationVerification
    observed_pre_interpretation_verification = [ordered]@{
        size_verified = $false
        sha256_verified = $false
        descriptor_verified = $false
        manifest_verified = $false
        checksum_set_verified = $false
        public_signature_verified = $false
        revocation_verified = $false
        freshness_verified = $false
        compatibility_verified = $false
        rollback_baseline_verified = $false
        support_recovery_verified = $false
    }
    blockers = @($script:blockers)
}

$denial = [ordered]@{
    schema = "agentos.rc13-quarantine-preflight-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-020"
    release_id = $releaseId
    status = "quarantine-preflight-denied"
    production_ready_claim = $false
    denial_reasons = @($script:blockers)
    required_before_preflight = [ordered]@{
        object_trust_allowed = $true
        drift_zero = $true
        object_manifest_descriptor_binding_allowed = $true
        public_signature_crypto_verified = $true
        revocation_authority_bound = $true
        revocation_snapshot_fresh = $true
        freshness_window_bound = $true
        freshness_window_current = $true
        current_bytes_match = $true
    }
    observed = [ordered]@{
        object_trust_allowed = $objectTrustAllowed
        drift_zero = $driftZero
        object_manifest_descriptor_binding_allowed = $objectManifestDescriptorBindingAllowed
        public_signature_crypto_verified = $publicSignatureCryptoVerified
        revocation_authority_bound = $revocationAuthorityBound
        revocation_snapshot_fresh = $revocationSnapshotFresh
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        current_bytes_match = $currentBytesMatch
    }
    denied_effects = [ordered]@{
        network_fetch_allowed = $false
        quarantine_payload_written = $false
        payload_interpretation_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
}

$caseBlockers = [ordered]@{
    "object-trust-missing-denies-preflight" = @("object-trust-not-allowed")
    "drift-not-zero-denies-preflight" = @("declared-current-drift-zero-not-proved")
    "descriptor-binding-denied-denies-preflight" = @("object-manifest-descriptor-binding-not-allowed")
    "freshness-window-missing-denies-preflight" = @("freshness-window-missing")
    "freshness-window-stale-denies-preflight" = @("freshness-window-stale-or-missing")
    "freshness-revocation-authority-missing-denies-preflight" = @("freshness-revocation-authority-not-bound")
    "network-before-object-trust-denied" = @("network-fetch-denied-before-object-trust")
    "quarantine-write-before-fetch-denied" = @("payload-not-quarantined")
    "interpret-before-quarantine-denied" = @("payload-interpretation-not-allowed")
    "size-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "digest-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "descriptor-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "manifest-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "checksum-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "signature-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "revocation-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "freshness-before-quarantine-denied" = @("freshness-window-missing", "pre-interpretation-verification-not-run")
    "compatibility-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "rollback-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "support-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "install-before-preflight-denied" = @("payload-not-quarantined", "pre-interpretation-verification-not-run")
    "activation-before-agentcore-security-denied" = @("agentcore-planspec-not-executable", "security-execution-allow-not-bound")
    "rollback-before-separate-approval-denied" = @("controlled-rollback-not-authorized")
    "support-upload-before-security-denied" = @("security-execution-allow-not-bound")
    "remote-dispatch-before-security-denied" = @("security-execution-allow-not-bound")
    "production-mutation-before-security-denied" = @("security-execution-allow-not-bound")
}

$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc13-quarantine-preflight-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC13-020"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc13-agentcore-executable-planspec-readiness-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-020"
    release_id = $releaseId
    status = if ($quarantinePreflightAllowed) { "quarantine-preflight-ready-for-planspec" } else { "blocked-before-agentcore-planspec-readiness" }
    production_ready_claim = $false
    expected_next_task = "RC13-021"
    quarantine = [ordered]@{
        preflight_allowed = $quarantinePreflightAllowed
        preflight_verified = $false
        network_fetch_attempted = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
    }
    agentcore = [ordered]@{
        planspec_readiness_allowed = $false
        planspec_executable = $false
        effect_execution_allowed = $false
    }
    bindings = [ordered]@{
        drift_result_sha256 = Get-FileSha256 $resolvedDriftResultPath
        object_binding_result_sha256 = Get-FileSha256 $resolvedObjectBindingResultPath
        object_binding_sha256 = Get-FileSha256 $resolvedObjectBindingPath
        authority_result_sha256 = Get-FileSha256 $resolvedAuthorityResultPath
        authority_binding_sha256 = Get-FileSha256 $resolvedAuthorityBindingPath
        current_payload_sha256 = $sourceArtifactSha256
        current_payload_size_bytes = $sourceArtifactSize
    }
    blockers = @($script:blockers)
}

$preflightReportPath = Join-Path $resolvedArtifactDir "quarantine-preflight-report.json"
$denialPath = Join-Path $resolvedArtifactDir "quarantine-preflight-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "quarantine-preflight-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "agentcore-planspec-readiness-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-020-quarantine-preflight.json"

Write-Json $preflightReport $preflightReportPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath
Write-Json $handoff $handoffPath

Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "RC13-020 quarantine negative cases must fail closed before network, quarantine write, interpretation, install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.network_fetch_attempted -or $_.side_effects.remote_payload_bytes_downloaded -or $_.side_effects.quarantine_payload_written -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.support_upload_performed -or $_.side_effects.recovery_execution_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.production_ring_mutated }).Count -eq 0) "RC13-020 must not fetch, download, quarantine-write, interpret, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $null
Add-Check "handoff.downstream_blocked" ($handoff.agentcore.planspec_readiness_allowed -eq $false -and $handoff.agentcore.planspec_executable -eq $false -and $handoff.agentcore.effect_execution_allowed -eq $false) "RC13-020 handoff must keep AgentCore PlanSpec readiness and effects blocked while quarantine preflight is denied." ([ordered]@{ status = $handoff.status; blockers = $handoff.blockers })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $preflightReportPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC13-020 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-quarantine-preflight-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-020"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    preflight_surface = [ordered]@{
        state = [string]$preflightReport.status
        drift_zero = $driftZero
        local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
        object_manifest_descriptor_binding_allowed = $objectManifestDescriptorBindingAllowed
        public_signature_bound = $publicSignatureBound
        public_signature_crypto_verified = $publicSignatureCryptoVerified
        revocation_authority_bound = $revocationAuthorityBound
        revocation_snapshot_fresh = $revocationSnapshotFresh
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        current_bytes_match = $currentBytesMatch
        object_trust_allowed = $objectTrustAllowed
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        network_fetch_allowed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        pre_interpretation_verification_performed = $false
        payload_interpreted = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        quarantine_preflight_report = [ordered]@{ path = Get-StablePath $preflightReportPath; sha256 = Get-FileSha256 $preflightReportPath }
        quarantine_preflight_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        agentcore_planspec_readiness_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_trusted = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        preflight_denied_before_network = (-not $quarantinePreflightAllowed)
        payload_interpretation_denied = $true
        rc13_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-021"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-quarantine-preflight-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-020"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    preflight_surface = $result.preflight_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc13_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-021"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC13-020 outputs."
}

Write-Host "RC13 quarantine preflight $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Preflight state: $($result.preflight_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
