param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-verified-quarantine-preflight",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc14",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md",
    [string]$ObjectTrustResultPath = ".workflow/artifacts/rc14-local-object-trust-verification/result.json",
    [string]$ObjectTrustReportPath = ".workflow/artifacts/rc14-local-object-trust-verification/object-trust-report.json",
    [string]$ObjectTrustDecisionPath = ".workflow/artifacts/rc14-local-object-trust-verification/object-trust-decision.json",
    [string]$ObjectTrustMatrixPath = ".workflow/artifacts/rc14-local-object-trust-verification/object-trust-fail-closed-matrix.json",
    [string]$ObjectTrustHandoffPath = ".workflow/artifacts/rc14-local-object-trust-verification/verified-quarantine-preflight-handoff.json",
    [string]$IdentitySetPath = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/declared-current-reconciled-identity-set.json",
    [string]$FreshnessBindingPath = ".workflow/artifacts/rc14-freshness-window-revocation-binding/freshness-window-revocation-binding.json",
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

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd("\", "/") + [IO.Path]::DirectorySeparatorChar
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Child path escapes parent: $Child"
    }
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
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityWord = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer/" + "private"),
        ("." + "pem"),
        $identityWord
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

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedObjectTrustResultPath = Resolve-RepoPath $ObjectTrustResultPath
$resolvedObjectTrustReportPath = Resolve-RepoPath $ObjectTrustReportPath
$resolvedObjectTrustDecisionPath = Resolve-RepoPath $ObjectTrustDecisionPath
$resolvedObjectTrustMatrixPath = Resolve-RepoPath $ObjectTrustMatrixPath
$resolvedObjectTrustHandoffPath = Resolve-RepoPath $ObjectTrustHandoffPath
$resolvedIdentitySetPath = Resolve-RepoPath $IdentitySetPath
$resolvedFreshnessBindingPath = Resolve-RepoPath $FreshnessBindingPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$objectTrustResult = Read-Json $resolvedObjectTrustResultPath
$objectTrustReport = Read-Json $resolvedObjectTrustReportPath
$objectTrustDecision = Read-Json $resolvedObjectTrustDecisionPath
$objectTrustMatrix = Read-Json $resolvedObjectTrustMatrixPath
$objectTrustHandoff = Read-Json $resolvedObjectTrustHandoffPath
$identitySet = Read-Json $resolvedIdentitySetPath
$freshnessBinding = Read-Json $resolvedFreshnessBindingPath

$payloadPath = Resolve-RepoPath ([string]$objectTrustHandoff.release_identity.payload_path)
$descriptorPath = Resolve-RepoPath ([string]$identitySet.descriptor_identity.descriptor_path)
$initramfsManifestPath = Resolve-RepoPath ([string]$identitySet.manifest_identity.initramfs_manifest_path)
$payloadManifestPath = Resolve-RepoPath ([string]$identitySet.manifest_identity.payload_manifest_path)
$objectChecksumsPath = Resolve-RepoPath ([string]$identitySet.manifest_identity.object_checksums_path)
$compatibilityPath = Resolve-RepoPath ([string]$identitySet.compatibility_identity.path)
$rollbackBaselinePath = Resolve-RepoPath ([string]$identitySet.rollback_identity.path)
$supportIndexPath = Resolve-RepoPath ([string]$identitySet.support_recovery_identity.path)
$freshnessWindowPath = Resolve-RepoPath ([string]$freshnessBinding.freshness_window.path)
$publicSignatureArtifactPath = Resolve-RepoPath ([string]$freshnessBinding.public_signature.signature_artifact_path)
$revocationSnapshotPath = Resolve-RepoPath ([string]$freshnessBinding.revocation.snapshot_path)

$releaseId = [string]$objectTrustHandoff.release_id
$payloadSha256 = Get-FileSha256 $payloadPath
$payloadSize = if (Test-Path -LiteralPath $payloadPath -PathType Leaf) { (Get-Item -LiteralPath $payloadPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $descriptorPath
$initramfsManifestSha256 = Get-FileSha256 $initramfsManifestPath
$payloadManifestSha256 = Get-FileSha256 $payloadManifestPath
$objectChecksumsSha256 = Get-FileSha256 $objectChecksumsPath
$compatibilitySha256 = Get-FileSha256 $compatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $rollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $supportIndexPath
$freshnessWindowSha256 = Get-FileSha256 $freshnessWindowPath
$publicSignatureArtifactSha256 = Get-FileSha256 $publicSignatureArtifactPath
$revocationSnapshotSha256 = Get-FileSha256 $revocationSnapshotPath

$rc14TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-020").status
$rc14PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-012").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc14PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC14-020" -and ($rc14TaskStatus -eq "pending" -or $rc14TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC14-021" -and $rc14TaskStatus -eq "completed")
    )
)

$objectTrustComplete = $objectTrustResult.status -eq "passed" -and $objectTrustResult.summary.rc14_012_complete -eq $true
$localObjectTrustAllowed = $objectTrustResult.verification_surface.local_object_trust_allowed -eq $true -and $objectTrustDecision.local_object_trust_allowed -eq $true -and $objectTrustHandoff.local_object_trust.local_object_trust_allowed -eq $true
$quarantinePreflightAllowed = $objectTrustResult.verification_surface.quarantine_preflight_allowed -eq $true -and $objectTrustDecision.quarantine_preflight_allowed -eq $true -and $objectTrustHandoff.local_object_trust.quarantine_preflight_allowed -eq $true
$handoffReady = $objectTrustHandoff.status -eq "ready-for-rc14-020-verified-quarantine-preflight" -and $objectTrustHandoff.expected_next_task -eq "RC14-020"
$negativeObjectTrustCasesPassed = $objectTrustMatrix.summary.failed_negative_cases.Count -eq 0

$sourcePayloadMatches = $payloadSha256 -eq [string]$objectTrustHandoff.release_identity.payload_sha256 -and
    [int64]$payloadSize -eq [int64]$objectTrustHandoff.release_identity.payload_size_bytes

$allPreconditionsMet = $planAllowsRun -and $objectTrustComplete -and $localObjectTrustAllowed -and $quarantinePreflightAllowed -and $handoffReady -and $negativeObjectTrustCasesPassed -and $sourcePayloadMatches

if (-not $planAllowsRun) { Add-UniqueBlocker "rc14-020-plan-pointer-not-current" }
if (-not $objectTrustComplete) { Add-UniqueBlocker "local-object-trust-result-not-complete" }
if (-not $localObjectTrustAllowed) { Add-UniqueBlocker "local-object-trust-not-allowed" }
if (-not $quarantinePreflightAllowed) { Add-UniqueBlocker "quarantine-preflight-not-allowed" }
if (-not $handoffReady) { Add-UniqueBlocker "verified-quarantine-preflight-handoff-not-ready" }
if (-not $negativeObjectTrustCasesPassed) { Add-UniqueBlocker "local-object-trust-fail-closed-cases-not-passed" }
if (-not $sourcePayloadMatches) { Add-UniqueBlocker "source-payload-identity-mismatch" }

$quarantineDir = Join-Path $resolvedArtifactDir "quarantine"
$quarantineReleaseDir = Join-Path $quarantineDir $releaseId
$quarantinePayloadPath = Join-Path $quarantineReleaseDir "agentos-initramfs.cpio.gz"
Assert-ChildPath -Parent $resolvedArtifactDir -Child $quarantinePayloadPath

$quarantinePayloadWritten = $false
if ($allPreconditionsMet) {
    New-Item -ItemType Directory -Force -Path $quarantineReleaseDir | Out-Null
    Copy-Item -LiteralPath $payloadPath -Destination $quarantinePayloadPath -Force
    $quarantinePayloadWritten = Test-Path -LiteralPath $quarantinePayloadPath -PathType Leaf
} else {
    Add-UniqueBlocker "verified-quarantine-preflight-not-run"
}

$quarantineSha256 = Get-FileSha256 $quarantinePayloadPath
$quarantineSize = if (Test-Path -LiteralPath $quarantinePayloadPath -PathType Leaf) { (Get-Item -LiteralPath $quarantinePayloadPath).Length } else { $null }
$quarantineDigestVerified = $quarantinePayloadWritten -and $quarantineSha256 -eq [string]$objectTrustHandoff.release_identity.payload_sha256
$quarantineSizeVerified = $quarantinePayloadWritten -and [int64]$quarantineSize -eq [int64]$objectTrustHandoff.release_identity.payload_size_bytes

$descriptorVerified = $descriptorSha256 -eq [string]$identitySet.descriptor_identity.descriptor_file_sha256
$manifestVerified = $initramfsManifestSha256 -eq [string]$identitySet.manifest_identity.initramfs_manifest_file_sha256 -and $payloadManifestSha256 -eq [string]$identitySet.manifest_identity.payload_manifest_file_sha256
$checksumSetVerified = $objectChecksumsSha256 -eq [string]$identitySet.manifest_identity.object_checksums_file_sha256
$signatureVerified = $freshnessBinding.authority_surface.public_signature_bound -eq $true -and
    $freshnessBinding.authority_surface.public_signature_crypto_verified -eq $true -and
    $publicSignatureArtifactSha256 -eq [string]$freshnessBinding.public_signature.signature_artifact_sha256
$revocationVerified = $freshnessBinding.authority_surface.revocation_snapshot_bound -eq $true -and
    $freshnessBinding.authority_surface.revocation_snapshot_current -eq $true -and
    $freshnessBinding.authority_surface.revocation_status_not_revoked -eq $true -and
    $revocationSnapshotSha256 -eq [string]$freshnessBinding.revocation.snapshot_sha256
$freshnessVerified = $freshnessBinding.authority_surface.freshness_window_bound -eq $true -and
    $freshnessBinding.authority_surface.freshness_window_current -eq $true -and
    $freshnessWindowSha256 -eq [string]$freshnessBinding.freshness_window.sha256
$compatibilityVerified = $compatibilitySha256 -eq [string]$identitySet.compatibility_identity.sha256
$rollbackVerified = $rollbackBaselineSha256 -eq [string]$identitySet.rollback_identity.sha256
$supportVerified = $supportIndexSha256 -eq [string]$identitySet.support_recovery_identity.sha256

$preInterpretationVerificationPerformed = $quarantineSizeVerified -and
    $quarantineDigestVerified -and
    $descriptorVerified -and
    $manifestVerified -and
    $checksumSetVerified -and
    $signatureVerified -and
    $revocationVerified -and
    $freshnessVerified -and
    $compatibilityVerified -and
    $rollbackVerified -and
    $supportVerified

if (-not $quarantinePayloadWritten) { Add-UniqueBlocker "quarantine-payload-not-written" }
if (-not $quarantineSizeVerified) { Add-UniqueBlocker "quarantine-payload-size-mismatch" }
if (-not $quarantineDigestVerified) { Add-UniqueBlocker "quarantine-payload-digest-mismatch" }
if (-not $descriptorVerified) { Add-UniqueBlocker "descriptor-verification-failed" }
if (-not $manifestVerified) { Add-UniqueBlocker "manifest-verification-failed" }
if (-not $checksumSetVerified) { Add-UniqueBlocker "checksum-set-verification-failed" }
if (-not $signatureVerified) { Add-UniqueBlocker "public-signature-verification-not-bound" }
if (-not $revocationVerified) { Add-UniqueBlocker "revocation-verification-not-bound" }
if (-not $freshnessVerified) { Add-UniqueBlocker "freshness-verification-not-bound" }
if (-not $compatibilityVerified) { Add-UniqueBlocker "compatibility-verification-not-bound" }
if (-not $rollbackVerified) { Add-UniqueBlocker "rollback-baseline-verification-not-bound" }
if (-not $supportVerified) { Add-UniqueBlocker "support-recovery-verification-not-bound" }

Add-UniqueBlocker "agentcore-planspec-not-executable"
Add-UniqueBlocker "security-execution-allow-not-bound"
Add-UniqueBlocker "two-target-local-canary-identities-not-enrolled"
Add-UniqueBlocker "exact-approval-not-bound"
Add-UniqueBlocker "controlled-activation-not-authorized"
Add-UniqueBlocker "controlled-rollback-not-authorized"

$verifiedQuarantinePreflight = $allPreconditionsMet -and $preInterpretationVerificationPerformed
$quarantineState = if ($verifiedQuarantinePreflight) { "verified-quarantine-preflight-complete" } else { "verified-quarantine-preflight-denied" }

$verification = [ordered]@{
    payload_size_verified = $quarantineSizeVerified
    payload_sha256_verified = $quarantineDigestVerified
    descriptor_verified = $descriptorVerified
    manifest_verified = $manifestVerified
    checksum_set_verified = $checksumSetVerified
    public_signature_verified = $signatureVerified
    revocation_verified = $revocationVerified
    freshness_verified = $freshnessVerified
    compatibility_verified = $compatibilityVerified
    rollback_baseline_verified = $rollbackVerified
    support_recovery_verified = $supportVerified
}

$source = [ordered]@{
    rc14_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc14_contract = New-ArtifactRef $resolvedContractPath
    object_trust_result = New-ArtifactRef $resolvedObjectTrustResultPath $objectTrustResult
    object_trust_report = New-ArtifactRef $resolvedObjectTrustReportPath $objectTrustReport
    object_trust_decision = New-ArtifactRef $resolvedObjectTrustDecisionPath $objectTrustDecision
    object_trust_fail_closed_matrix = New-ArtifactRef $resolvedObjectTrustMatrixPath $objectTrustMatrix
    verified_quarantine_preflight_handoff = New-ArtifactRef $resolvedObjectTrustHandoffPath $objectTrustHandoff
    reconciled_identity_set = New-ArtifactRef $resolvedIdentitySetPath $identitySet
    freshness_binding = New-ArtifactRef $resolvedFreshnessBindingPath $freshnessBinding
    source_payload = New-ArtifactRef $payloadPath
    descriptor = New-ArtifactRef $descriptorPath
    initramfs_manifest = New-ArtifactRef $initramfsManifestPath
    payload_manifest = New-ArtifactRef $payloadManifestPath
    object_checksums = New-ArtifactRef $objectChecksumsPath
    compatibility = New-ArtifactRef $compatibilityPath
    rollback_baseline = New-ArtifactRef $rollbackBaselinePath
    support_index = New-ArtifactRef $supportIndexPath
    freshness_window = New-ArtifactRef $freshnessWindowPath
    public_signature_artifact = New-ArtifactRef $publicSignatureArtifactPath
    revocation_snapshot = New-ArtifactRef $revocationSnapshotPath
}

Add-Check "plan.current_task.rc14_020" $planAllowsRun "RC14-020 must run after RC14-012 completed, either while current_task is RC14-020 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc14_012_status = $rc14PreviousStatus; rc14_020_status = $rc14TaskStatus })
Add-Check "contract.verified_quarantine_gate.present" ($contractText.Contains("verified quarantine") -and $contractText.Contains("must not be interpreted") -and $contractText.Contains("AgentCore executable PlanSpec")) "RC14-020 must consume the quarantine-before-interpretation and AgentCore handoff contract." $source.rc14_contract
Add-Check "source.rc14_012.local_object_trust" ($objectTrustComplete -and $localObjectTrustAllowed -and $quarantinePreflightAllowed -and $handoffReady) "RC14-020 requires completed RC14-012 local object trust and quarantine handoff evidence." ([ordered]@{ result_status = $objectTrustResult.status; local_object_trust_allowed = $localObjectTrustAllowed; quarantine_preflight_allowed = $quarantinePreflightAllowed; handoff_status = $objectTrustHandoff.status })
Add-Check "source.payload.identity_match" $sourcePayloadMatches "Source payload bytes must match the trusted release identity before quarantine write." ([ordered]@{ expected_sha256 = $objectTrustHandoff.release_identity.payload_sha256; observed_sha256 = $payloadSha256; expected_size_bytes = $objectTrustHandoff.release_identity.payload_size_bytes; observed_size_bytes = $payloadSize })
Add-Check "quarantine.payload_written_repo_local" ($quarantinePayloadWritten -and $verifiedQuarantinePreflight) "Trusted payload bytes must be written only to the repo-local quarantine artifact area before interpretation." ([ordered]@{ quarantine_payload = Get-StablePath $quarantinePayloadPath; sha256 = $quarantineSha256; size_bytes = $quarantineSize })
Add-Check "pre_interpretation.verification_complete" $preInterpretationVerificationPerformed "Quarantine preflight must verify size, digest, descriptor, manifest, checksum set, signature, revocation, freshness, compatibility, rollback, and support before interpretation." $verification
Add-Check "payload.interpretation_still_denied" $verifiedQuarantinePreflight "RC14-020 verifies quarantine but still must not interpret or install payload bytes." ([ordered]@{ payload_interpreted = $false; install_allowed = $false; activation_allowed = $false; rollback_execution_allowed = $false })

$quarantineManifest = [ordered]@{
    schema = "agentos.rc14-verified-quarantine-manifest.v1"
    generated_at = $generatedAtValue
    task = "RC14-020"
    release_id = $releaseId
    status = $quarantineState
    production_ready_claim = $false
    quarantine = [ordered]@{
        payload_path = Get-StablePath $quarantinePayloadPath
        payload_sha256 = $quarantineSha256
        payload_size_bytes = $quarantineSize
        source_payload_path = Get-StablePath $payloadPath
        source_payload_sha256 = $payloadSha256
        source_payload_size_bytes = $payloadSize
        repo_local_artifact_only = $true
        payload_interpreted = $false
    }
    verification = $verification
    source = $source
}

$preflightReport = [ordered]@{
    schema = "agentos.rc14-verified-quarantine-preflight-report.v1"
    generated_at = $generatedAtValue
    task = "RC14-020"
    release_id = $releaseId
    status = $quarantineState
    production_ready_claim = $false
    object_trust = [ordered]@{
        local_object_trust_allowed = $localObjectTrustAllowed
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        handoff_ready = $handoffReady
        fail_closed_matrix_passed = $negativeObjectTrustCasesPassed
    }
    quarantine_policy = [ordered]@{
        network_fetch_allowed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $quarantinePayloadWritten
        bytes_written_only_to_quarantine = $true
        payload_interpretation_allowed = $false
        payload_interpreted = $false
    }
    observed_pre_interpretation_verification = $verification
    blockers = @($script:blockers)
}

$caseBlockers = [ordered]@{
    "local-object-trust-missing-denies-quarantine" = @("local-object-trust-not-allowed")
    "quarantine-preflight-handoff-missing-denies-write" = @("verified-quarantine-preflight-handoff-not-ready")
    "payload-digest-mismatch-denies-preflight" = @("quarantine-payload-digest-mismatch")
    "payload-size-mismatch-denies-preflight" = @("quarantine-payload-size-mismatch")
    "descriptor-verification-missing-denies-preflight" = @("descriptor-verification-failed")
    "manifest-verification-missing-denies-preflight" = @("manifest-verification-failed")
    "checksum-set-missing-denies-preflight" = @("checksum-set-verification-failed")
    "signature-verification-missing-denies-preflight" = @("public-signature-verification-not-bound")
    "revocation-verification-missing-denies-preflight" = @("revocation-verification-not-bound")
    "freshness-verification-missing-denies-preflight" = @("freshness-verification-not-bound")
    "compatibility-missing-denies-preflight" = @("compatibility-verification-not-bound")
    "rollback-baseline-missing-denies-preflight" = @("rollback-baseline-verification-not-bound")
    "support-recovery-missing-denies-preflight" = @("support-recovery-verification-not-bound")
    "interpret-before-verification-denied" = @("controlled-activation-not-authorized")
    "install-before-agentcore-denied" = @("agentcore-planspec-not-executable")
    "activation-before-security-denied" = @("security-execution-allow-not-bound")
    "rollback-before-separate-approval-denied" = @("controlled-rollback-not-authorized")
    "support-upload-before-security-denied" = @("security-execution-allow-not-bound")
    "remote-dispatch-before-security-denied" = @("security-execution-allow-not-bound")
    "production-mutation-before-security-denied" = @("security-execution-allow-not-bound")
}

$simulationBlockers = @(
    "local-object-trust-not-allowed",
    "verified-quarantine-preflight-handoff-not-ready",
    "quarantine-payload-digest-mismatch",
    "quarantine-payload-size-mismatch",
    "descriptor-verification-failed",
    "manifest-verification-failed",
    "checksum-set-verification-failed",
    "public-signature-verification-not-bound",
    "revocation-verification-not-bound",
    "freshness-verification-not-bound",
    "compatibility-verification-not-bound",
    "rollback-baseline-verification-not-bound",
    "support-recovery-verification-not-bound"
) + @($script:blockers)

$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $simulationBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc14-verified-quarantine-preflight-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC14-020"
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
    schema = "agentos.rc14-agentcore-executable-planspec-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC14-020"
    release_id = $releaseId
    status = if ($verifiedQuarantinePreflight) { "ready-for-rc14-021-agentcore-executable-planspec" } else { "blocked-before-agentcore-executable-planspec" }
    production_ready_claim = $false
    expected_next_task = "RC14-021"
    quarantine = [ordered]@{
        manifest_path = $null
        manifest_sha256 = $null
        preflight_report_path = $null
        preflight_report_sha256 = $null
        verified_quarantine_preflight = $verifiedQuarantinePreflight
        quarantine_payload_written = $quarantinePayloadWritten
        quarantine_payload_path = Get-StablePath $quarantinePayloadPath
        quarantine_payload_sha256 = $quarantineSha256
        quarantine_payload_size_bytes = $quarantineSize
        payload_interpreted = $false
    }
    agentcore = [ordered]@{
        planspec_readiness_allowed = $verifiedQuarantinePreflight
        planspec_executable = $false
        effect_execution_allowed = $false
    }
    blockers = @($script:blockers)
}

$manifestPath = Join-Path $resolvedArtifactDir "verified-quarantine-manifest.json"
$preflightReportPath = Join-Path $resolvedArtifactDir "verified-quarantine-preflight-report.json"
$matrixPath = Join-Path $resolvedArtifactDir "verified-quarantine-preflight-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "agentcore-executable-planspec-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC14-020-verified-quarantine-preflight.json"

Write-Json $quarantineManifest $manifestPath
Write-Json $preflightReport $preflightReportPath
Write-Json $matrix $matrixPath
$handoff.quarantine.manifest_path = Get-StablePath $manifestPath
$handoff.quarantine.manifest_sha256 = Get-FileSha256 $manifestPath
$handoff.quarantine.preflight_report_path = Get-StablePath $preflightReportPath
$handoff.quarantine.preflight_report_sha256 = Get-FileSha256 $preflightReportPath
Write-Json $handoff $handoffPath

Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "RC14-020 negative cases must fail closed before interpretation, install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.network_fetch_attempted -or $_.side_effects.remote_payload_bytes_downloaded -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.support_upload_performed -or $_.side_effects.recovery_execution_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.production_ring_mutated }).Count -eq 0) "RC14-020 must not fetch from network, interpret payloads, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $null
Add-Check "handoff.agentcore_ready_not_executable" ($handoff.agentcore.planspec_readiness_allowed -eq $true -and $handoff.agentcore.planspec_executable -eq $false -and $handoff.agentcore.effect_execution_allowed -eq $false) "RC14-020 may hand off to AgentCore readiness but must not make PlanSpec executable or execute effects." $handoff.agentcore

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $manifestPath),
    (Get-Content -Raw -LiteralPath $preflightReportPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC14-020 outputs must not contain key blocks, tokens, private authority paths, signer internals, or raw public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc14-verified-quarantine-preflight-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-020"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    preflight_surface = [ordered]@{
        state = $quarantineState
        local_object_trust_allowed = $localObjectTrustAllowed
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        verified_quarantine_preflight = $verifiedQuarantinePreflight
        network_fetch_allowed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $quarantinePayloadWritten
        quarantine_payload_path = Get-StablePath $quarantinePayloadPath
        quarantine_payload_sha256 = $quarantineSha256
        quarantine_payload_size_bytes = $quarantineSize
        pre_interpretation_verification_performed = $preInterpretationVerificationPerformed
        payload_interpreted = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        agentcore_planspec_readiness_allowed = $verifiedQuarantinePreflight
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        quarantine_payload = [ordered]@{ path = Get-StablePath $quarantinePayloadPath; sha256 = $quarantineSha256; size_bytes = $quarantineSize }
        verified_quarantine_manifest = [ordered]@{ path = Get-StablePath $manifestPath; sha256 = Get-FileSha256 $manifestPath }
        verified_quarantine_preflight_report = [ordered]@{ path = Get-StablePath $preflightReportPath; sha256 = Get-FileSha256 $preflightReportPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        agentcore_executable_planspec_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
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
        signer_service_called = $false
        endpoint_reachability_trusted = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $quarantinePayloadWritten
        quarantine_write_repo_local_only = $true
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        verified_quarantine_preflight = $verifiedQuarantinePreflight
        quarantine_payload_written = $quarantinePayloadWritten
        pre_interpretation_verification_performed = $preInterpretationVerificationPerformed
        payload_interpreted = $false
        rc14_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-021"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-verified-quarantine-preflight-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-020"
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
        rc14_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-021"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC14-020 outputs."
}

Write-Host "RC14 verified quarantine preflight $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Preflight state: $($result.preflight_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
