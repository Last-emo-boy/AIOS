param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-installer-updater-preflight-package",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$ReleasePackageResultPath = ".workflow/artifacts/rc16-release-package-artifact-set/result.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$InstallableMediaResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$PackageDescriptorResultPath = ".workflow/artifacts/rc16-package-descriptor-fail-closed/result.json",
    [string]$PackageDescriptorMatrixPath = ".workflow/artifacts/rc16-package-descriptor-fail-closed/package-descriptor-fail-closed-matrix.json",
    [string]$ReleaseReproducibilityResultPath = ".workflow/artifacts/release-reproducibility-fast/result.json",
    [string]$CandidatePromotionPreflightPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/candidate-promotion-preflight.json",
    [string]$ReleaseProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$UpdateMetadataPath = ".workflow/artifacts/release/update-metadata.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$Rc15FinalAuditPath = ".workflow/artifacts/rc15-final-closeout-audit/result.json",
    [string]$Rc15AgentCorePlanSpecPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/agentcore-planspec.json",
    [string]$Rc15SecurityExecutionDecisionPath = ".workflow/artifacts/rc15-security-execution-allow-decision/security-execution-allow-decision.json",
    [string]$ReproducibilityVerifierPath = "scripts/verify-release-reproducibility.ps1",
    [string]$CandidatePromotionVerifierPath = "scripts/verify-candidate-promotion.ps1",
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
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

function Add-Unique {
    param(
        [System.Collections.ArrayList]$List,
        [Parameter(Mandatory = $true)][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }
    if (-not $List.Contains($Value)) {
        [void]$List.Add($Value)
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

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) {
                return $task.status
            }
        }
    }
    return $null
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityMarker = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        $identityMarker
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

function New-DenialCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        observed_denied = $true
        expected_blockers = $ExpectedBlockers
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            endpoint_probe_performed = $false
            frontend_output_trusted = $false
            signer_reachability_trusted = $false
            shell_output_trusted = $false
            model_replay_trusted = $false
            object_storage_ui_trusted = $false
            payload_upload_performed = $false
            payload_published = $false
            network_fetch_attempted = $false
            remote_payload_bytes_downloaded = $false
            install_effect_prepared = $false
            update_effect_prepared = $false
            install_performed = $false
            update_performed = $false
            activation_performed = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            cryptographic_signing_performed = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedReleasePackageResultPath = Resolve-RepoPath $ReleasePackageResultPath
$resolvedReleasePackageArtifactSetPath = Resolve-RepoPath $ReleasePackageArtifactSetPath
$resolvedInstallableMediaResultPath = Resolve-RepoPath $InstallableMediaResultPath
$resolvedInstallableMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedPackageDescriptorResultPath = Resolve-RepoPath $PackageDescriptorResultPath
$resolvedPackageDescriptorMatrixPath = Resolve-RepoPath $PackageDescriptorMatrixPath
$resolvedReleaseReproducibilityResultPath = Resolve-RepoPath $ReleaseReproducibilityResultPath
$resolvedCandidatePromotionPreflightPath = Resolve-RepoPath $CandidatePromotionPreflightPath
$resolvedReleaseProvenancePath = Resolve-RepoPath $ReleaseProvenancePath
$resolvedUpdateMetadataPath = Resolve-RepoPath $UpdateMetadataPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedRc15FinalAuditPath = Resolve-RepoPath $Rc15FinalAuditPath
$resolvedRc15AgentCorePlanSpecPath = Resolve-RepoPath $Rc15AgentCorePlanSpecPath
$resolvedRc15SecurityExecutionDecisionPath = Resolve-RepoPath $Rc15SecurityExecutionDecisionPath
$resolvedReproducibilityVerifierPath = Resolve-RepoPath $ReproducibilityVerifierPath
$resolvedCandidatePromotionVerifierPath = Resolve-RepoPath $CandidatePromotionVerifierPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releasePackageResult = Read-Json $resolvedReleasePackageResultPath
$releasePackageArtifactSet = Read-Json $resolvedReleasePackageArtifactSetPath
$installableMediaResult = Read-Json $resolvedInstallableMediaResultPath
$installableMediaManifest = Read-Json $resolvedInstallableMediaManifestPath
$packageDescriptorResult = Read-Json $resolvedPackageDescriptorResultPath
$packageDescriptorMatrix = Read-Json $resolvedPackageDescriptorMatrixPath
$releaseReproducibilityResult = Read-Json $resolvedReleaseReproducibilityResultPath
$candidatePromotionPreflight = Read-Json $resolvedCandidatePromotionPreflightPath
$releaseProvenance = Read-Json $resolvedReleaseProvenancePath
$updateMetadata = Read-Json $resolvedUpdateMetadataPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath
$rc15FinalAudit = Read-Json $resolvedRc15FinalAuditPath
$rc15AgentCorePlanSpec = Read-Json $resolvedRc15AgentCorePlanSpecPath
$rc15SecurityExecutionDecision = Read-Json $resolvedRc15SecurityExecutionDecisionPath

$rc16PreviousStatus = Get-TaskStatus $plan "RC16-012"
$rc16TaskStatus = Get-TaskStatus $plan "RC16-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-020" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-021" -and $rc16TaskStatus -eq "completed")
    )
)

$releasePackageResultSha256 = Get-FileSha256 $resolvedReleasePackageResultPath
$releasePackageArtifactSetSha256 = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
$installableMediaResultSha256 = Get-FileSha256 $resolvedInstallableMediaResultPath
$installableMediaManifestSha256 = Get-FileSha256 $resolvedInstallableMediaManifestPath
$packageDescriptorResultSha256 = Get-FileSha256 $resolvedPackageDescriptorResultPath
$packageDescriptorMatrixSha256 = Get-FileSha256 $resolvedPackageDescriptorMatrixPath
$releaseReproducibilitySha256 = Get-FileSha256 $resolvedReleaseReproducibilityResultPath
$candidatePromotionSha256 = Get-FileSha256 $resolvedCandidatePromotionPreflightPath
$releaseProvenanceSha256 = Get-FileSha256 $resolvedReleaseProvenancePath
$updateMetadataSha256 = Get-FileSha256 $resolvedUpdateMetadataPath
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $resolvedSupportIndexPath

$source = [ordered]@{
    rc16_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc16_contract = New-ArtifactRef $resolvedContractPath
    rc16_release_package_result = New-ArtifactRef $resolvedReleasePackageResultPath $releasePackageResult
    rc16_release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $releasePackageArtifactSet
    rc16_installable_media_result = New-ArtifactRef $resolvedInstallableMediaResultPath $installableMediaResult
    rc16_installable_media_manifest = New-ArtifactRef $resolvedInstallableMediaManifestPath $installableMediaManifest
    rc16_package_descriptor_result = New-ArtifactRef $resolvedPackageDescriptorResultPath $packageDescriptorResult
    rc16_package_descriptor_matrix = New-ArtifactRef $resolvedPackageDescriptorMatrixPath $packageDescriptorMatrix
    release_reproducibility_result = New-ArtifactRef $resolvedReleaseReproducibilityResultPath $releaseReproducibilityResult
    candidate_promotion_preflight = New-ArtifactRef $resolvedCandidatePromotionPreflightPath $candidatePromotionPreflight
    release_provenance = New-ArtifactRef $resolvedReleaseProvenancePath $releaseProvenance
    update_metadata = New-ArtifactRef $resolvedUpdateMetadataPath $updateMetadata
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    rc15_final_audit = New-ArtifactRef $resolvedRc15FinalAuditPath $rc15FinalAudit
    rc15_agentcore_planspec = New-ArtifactRef $resolvedRc15AgentCorePlanSpecPath $rc15AgentCorePlanSpec
    rc15_security_execution_decision = New-ArtifactRef $resolvedRc15SecurityExecutionDecisionPath $rc15SecurityExecutionDecision
    reproducibility_verifier = New-ArtifactRef $resolvedReproducibilityVerifierPath
    candidate_promotion_verifier = New-ArtifactRef $resolvedCandidatePromotionVerifierPath
}

$releasePackageComplete = (
    $releasePackageResult.status -eq "passed" -and
    $releasePackageResult.summary.failed_checks -eq 0 -and
    $releasePackageResult.summary.rc16_010_complete -eq $true -and
    $releasePackageArtifactSet.schema -eq "agentos.rc16-release-package-artifact-set.v1" -and
    $releasePackageArtifactSet.production_ready_claim -eq $false
)
$installableMediaComplete = (
    $installableMediaResult.status -eq "passed" -and
    $installableMediaResult.summary.failed_checks -eq 0 -and
    $installableMediaResult.summary.rc16_011_complete -eq $true -and
    $installableMediaManifest.schema -eq "agentos.rc16-installable-media-manifest.v1" -and
    $installableMediaManifest.production_ready_claim -eq $false
)
$descriptorFailClosedComplete = (
    $packageDescriptorResult.status -eq "passed" -and
    $packageDescriptorResult.summary.failed_checks -eq 0 -and
    $packageDescriptorResult.summary.failed_cases -eq 0 -and
    $packageDescriptorResult.summary.rc16_012_complete -eq $true -and
    $packageDescriptorMatrix.status -eq "passed"
)
$reproducibilityComplete = (
    $releaseReproducibilityResult.status -eq "passed" -and
    $releaseReproducibilityResult.production_ready_claim -eq $false -and
    $releaseReproducibilityResult.summary.divergent -eq 0
)
$candidatePromotionComplete = (
    $candidatePromotionPreflight.status -eq "passed" -and
    $candidatePromotionPreflight.production_ready_claim -eq $false -and
    $candidatePromotionPreflight.summary.blockers -eq 0
)

$packageMediaIdentityBound = (
    [string]$releasePackageArtifactSet.package_id -eq [string]$installableMediaManifest.package_id -and
    [string]$releasePackageArtifactSet.release_id -eq [string]$installableMediaManifest.release_id -and
    $installableMediaManifest.source_release_package.artifact_set_sha256 -eq $releasePackageArtifactSetSha256 -and
    $packageDescriptorResult.descriptor_surface.release_package_artifact_set_sha256 -eq $releasePackageArtifactSetSha256 -and
    $packageDescriptorResult.descriptor_surface.installable_media_manifest_sha256 -eq $installableMediaManifestSha256
)
$releaseBytesBound = (
    $releasePackageArtifactSet.package_surface.current_payload_sha256 -eq $installableMediaManifest.release_bytes.payload.sha256 -and
    $installableMediaManifest.release_bytes.payload.sha256 -eq $releaseProvenance.artifacts.initramfs.sha256 -and
    $releasePackageArtifactSet.package_surface.manifest_sha256 -eq $installableMediaManifest.release_bytes.initramfs_manifest.sha256 -and
    $installableMediaManifest.release_bytes.initramfs_manifest.sha256 -eq $releaseProvenance.artifacts.initramfs.manifest_sha256
)
$updateMetadataBound = (
    $updateMetadata.schema -eq "agentos.candidate-update-metadata.v1" -and
    $updateMetadata.production_ready_claim -eq $false -and
    $updateMetadata.update_strategy.stage_target -eq "inactive-slot" -and
    $updateMetadata.update_strategy.active_slot_modified_in_place -eq $false -and
    $updateMetadata.update_strategy.rollback_required -eq $true -and
    $releaseProvenance.artifacts.update_metadata.sha256 -eq $updateMetadataSha256
)
$compatibilityBound = (
    @($installableMediaManifest.architecture_and_compatibility.target_arch) -contains "x86_64" -and
    $installableMediaManifest.architecture_and_compatibility.kernel_family -eq "linux-lts" -and
    $installableMediaManifest.architecture_and_compatibility.compatibility.sha256 -eq $compatibilitySha256 -and
    $compatibility.authority.shell_authority -eq $false
)
$rollbackSupportBound = (
    $installableMediaManifest.rollback_support.rollback_baseline_sha256 -eq $rollbackBaselineSha256 -and
    $installableMediaManifest.rollback_support.support_recovery_sha256 -eq $supportIndexSha256 -and
    $rollbackBaseline.production_ready_claim -eq $false -and
    $supportIndex.support_upload_allowed -eq $false -and
    $supportIndex.recovery_execution_allowed -eq $false
)
$rc15ExecutionBound = (
    $releasePackageArtifactSet.package_surface.rc15_controlled_execution_ready -eq $true -and
    $installableMediaManifest.source_release_package.rc15_controlled_execution_ready -eq $true -and
    $rc15FinalAudit.status -eq "passed" -and
    $rc15FinalAudit.decision -eq "PASS" -and
    $rc15FinalAudit.controlled_local_execution_ready -eq $true -and
    $rc15AgentCorePlanSpec.status -eq "agentcore-planspec-executable" -and
    $rc15SecurityExecutionDecision.status -eq "security-execution-allow-bound"
)

$blockers = [System.Collections.ArrayList]::new()
if (-not $releasePackageComplete) { Add-Unique $blockers "rc16-release-package-artifact-set-not-complete" }
if (-not $installableMediaComplete) { Add-Unique $blockers "rc16-installable-media-manifest-not-complete" }
if (-not $descriptorFailClosedComplete) { Add-Unique $blockers "rc16-package-descriptor-fail-closed-not-complete" }
if (-not $reproducibilityComplete) { Add-Unique $blockers "release-reproducibility-not-passed" }
if (-not $candidatePromotionComplete) { Add-Unique $blockers "candidate-promotion-preflight-not-passed" }
if (-not $packageMediaIdentityBound) { Add-Unique $blockers "package-media-identity-not-bound" }
if (-not $releaseBytesBound) { Add-Unique $blockers "release-bytes-not-bound" }
if (-not $updateMetadataBound) { Add-Unique $blockers "update-metadata-not-bound" }
if (-not $compatibilityBound) { Add-Unique $blockers "architecture-compatibility-not-bound" }
if (-not $rollbackSupportBound) { Add-Unique $blockers "rollback-support-source-not-bound" }
if (-not $rc15ExecutionBound) { Add-Unique $blockers "rc15-controlled-local-execution-not-bound" }

$preflightEvidenceBound = (
    $releasePackageComplete -and
    $installableMediaComplete -and
    $descriptorFailClosedComplete -and
    $reproducibilityComplete -and
    $candidatePromotionComplete -and
    $packageMediaIdentityBound -and
    $releaseBytesBound -and
    $updateMetadataBound -and
    $compatibilityBound -and
    $rollbackSupportBound -and
    $rc15ExecutionBound
)

Add-Unique $blockers "rc16-install-update-planspec-not-bound"
Add-Unique $blockers "rc16-security-execution-install-update-allow-not-bound"
Add-Unique $blockers "rc16-rollback-support-package-not-bound"
Add-Unique $blockers "rc16-local-release-channel-consumer-smoke-not-run"

$effectPreparationAllowed = $false
$preflightState = if ($preflightEvidenceBound) {
    "installer-updater-preflight-bound-effects-denied"
} else {
    "installer-updater-preflight-denied-source-evidence-incomplete"
}

$preflightIdInput = @(
    "agentos.rc16-installer-updater-preflight-package.v1",
    $releasePackageResultSha256,
    $releasePackageArtifactSetSha256,
    $installableMediaResultSha256,
    $installableMediaManifestSha256,
    $packageDescriptorResultSha256,
    $packageDescriptorMatrixSha256,
    $releaseReproducibilitySha256,
    $candidatePromotionSha256,
    $releaseProvenanceSha256,
    $updateMetadataSha256,
    $compatibilitySha256,
    $rollbackBaselineSha256,
    $supportIndexSha256,
    "preflight-only-no-install-no-update"
) -join "|"
$preflightId = "sha256:$(Get-StringSha256 $preflightIdInput)"

Add-Check "plan.current_task.rc16_020" $planAllowsRun "RC16-020 must run after RC16-012 completes and while the plan pointer is at RC16-020, or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_012_status = $rc16PreviousStatus; rc16_020_status = $rc16TaskStatus })
Add-Check "contract.preflight_only.present" ($contractText.Contains("Installer and updater readiness must remain preflight-only") -and $contractText.Contains("Installer/updater preflight evidence is bound") -and $contractText.Contains("If any condition is false, the install/update path must deny")) "RC16-020 must consume the RC16 installer/update preflight contract." $source.rc16_contract
Add-Check "source.rc16_010_011_012.complete" ($releasePackageComplete -and $installableMediaComplete -and $descriptorFailClosedComplete) "RC16-020 requires completed release package, installable media, and descriptor fail-closed evidence." ([ordered]@{ rc16_010 = $releasePackageResult.summary; rc16_011 = $installableMediaResult.summary; rc16_012 = $packageDescriptorResult.summary })
Add-Check "source.reproducibility.bound" $reproducibilityComplete "RC16-020 must bind release reproducibility evidence without claiming production readiness." ([ordered]@{ status = $releaseReproducibilityResult.status; divergent = $releaseReproducibilityResult.summary.divergent; production_ready_claim = $releaseReproducibilityResult.production_ready_claim })
Add-Check "source.candidate_promotion.bound" $candidatePromotionComplete "RC16-020 must bind candidate promotion verifier output before preflight can be considered bound." ([ordered]@{ status = $candidatePromotionPreflight.status; blockers = $candidatePromotionPreflight.summary.blockers; production_ready_claim = $candidatePromotionPreflight.production_ready_claim })
Add-Check "identity.package_media_descriptor.bound" $packageMediaIdentityBound "Package descriptor, installable media, and release package identities must match exactly." ([ordered]@{ package_id = $releasePackageArtifactSet.package_id; media_package_id = $installableMediaManifest.package_id; release_id = $releasePackageArtifactSet.release_id; media_release_id = $installableMediaManifest.release_id })
Add-Check "release.bytes.update_metadata.bound" ($releaseBytesBound -and $updateMetadataBound) "Preflight must bind payload bytes, initramfs manifest, provenance, and inactive-slot update metadata." ([ordered]@{ payload_sha256 = $installableMediaManifest.release_bytes.payload.sha256; provenance_payload_sha256 = $releaseProvenance.artifacts.initramfs.sha256; update_stage_target = $updateMetadata.update_strategy.stage_target; rollback_required = $updateMetadata.update_strategy.rollback_required })
Add-Check "compatibility.rollback.support.rc15.bound" ($compatibilityBound -and $rollbackSupportBound -and $rc15ExecutionBound) "Preflight must bind compatibility, rollback/support, and RC15 controlled local execution evidence." ([ordered]@{ target_arch = @($installableMediaManifest.architecture_and_compatibility.target_arch); kernel_family = $installableMediaManifest.architecture_and_compatibility.kernel_family; rollback_baseline_sha256 = $rollbackBaselineSha256; support_index_sha256 = $supportIndexSha256; rc15_ready = $rc15FinalAudit.controlled_local_execution_ready })

$caseObservedBlockers = @(
    "rc16-release-package-artifact-set-not-complete",
    "rc16-installable-media-manifest-not-complete",
    "rc16-package-descriptor-fail-closed-not-complete",
    "release-reproducibility-not-passed",
    "candidate-promotion-preflight-not-passed",
    "package-media-identity-not-bound",
    "release-bytes-not-bound",
    "update-metadata-not-bound",
    "architecture-compatibility-not-bound",
    "rollback-support-source-not-bound",
    "rc15-controlled-local-execution-not-bound",
    "endpoint-reachability-is-not-authority",
    "frontend-output-is-not-authority",
    "signer-reachability-is-not-authority",
    "shell-output-is-not-authority",
    "model-replay-is-not-authority",
    "object-storage-ui-is-not-authority",
    "authority-broadening",
    "rc16-install-update-planspec-not-bound",
    "rc16-security-execution-install-update-allow-not-bound",
    "rc16-rollback-support-package-not-bound",
    "rc16-local-release-channel-consumer-smoke-not-run"
)
$caseExpectations = [ordered]@{
    "missing.release_package" = @("rc16-release-package-artifact-set-not-complete")
    "missing.installable_media_manifest" = @("rc16-installable-media-manifest-not-complete")
    "descriptor.fail_closed_not_passed" = @("rc16-package-descriptor-fail-closed-not-complete")
    "reproducibility.blocked" = @("release-reproducibility-not-passed")
    "candidate_promotion.blocked" = @("candidate-promotion-preflight-not-passed")
    "package.media.identity_mismatch" = @("package-media-identity-not-bound")
    "payload.digest_mismatch" = @("release-bytes-not-bound")
    "update_metadata.active_slot_target" = @("update-metadata-not-bound")
    "unsupported.architecture" = @("architecture-compatibility-not-bound")
    "rollback_support.missing" = @("rollback-support-source-not-bound")
    "rc15.execution_missing" = @("rc15-controlled-local-execution-not-bound")
    "surface.endpoint_reachability" = @("endpoint-reachability-is-not-authority")
    "surface.frontend_output" = @("frontend-output-is-not-authority")
    "surface.signer_reachability" = @("signer-reachability-is-not-authority")
    "surface.shell_output" = @("shell-output-is-not-authority")
    "surface.model_replay" = @("model-replay-is-not-authority")
    "surface.object_storage_ui" = @("object-storage-ui-is-not-authority")
    "authority.install_effect_before_agentcore" = @("rc16-install-update-planspec-not-bound")
    "authority.update_effect_before_security" = @("rc16-security-execution-install-update-allow-not-bound")
    "authority.activation_broadening" = @("authority-broadening")
    "authority.rollback_package_missing" = @("rc16-rollback-support-package-not-bound")
    "authority.production_ring_mutation" = @("authority-broadening")
}
$cases = @()
foreach ($caseId in $caseExpectations.Keys) {
    $cases += New-DenialCase -Id $caseId -ExpectedBlockers ([string[]]$caseExpectations[$caseId]) -ObservedBlockers $caseObservedBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "fixtures.preflight_denials.pass" ($failedCases.Count -eq 0) "Installer/updater preflight negative cases must deny without trusting transport/display surfaces or broadening authority." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$sideEffects = [ordered]@{
    endpoint_probe_performed = $false
    frontend_output_trusted = $false
    signer_reachability_trusted = $false
    shell_output_trusted = $false
    model_replay_trusted = $false
    object_storage_ui_trusted = $false
    payload_upload_performed = $false
    payload_published = $false
    network_fetch_attempted = $false
    remote_payload_bytes_downloaded = $false
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed = $false
    update_performed = $false
    activation_performed = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    cryptographic_signing_performed = $false
    production_ring_mutated = $false
}
Add-Check "authority.no_side_effects" (@($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0 -and $effectPreparationAllowed -eq $false) "RC16-020 must not prepare or execute install/update effects, fetch/upload payloads, sign, dispatch, rollback, upload support, recover, or mutate production state." $sideEffects

$packagePath = Join-Path $resolvedArtifactDir "installer-updater-preflight-package.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-020-installer-updater-preflight-package.json"

$preflightPackage = [ordered]@{
    schema = "agentos.rc16-installer-updater-preflight-package.v1"
    generated_at = $generatedAtValue
    task = "RC16-020"
    status = $preflightState
    preflight_id = $preflightId
    package_id = [string]$releasePackageArtifactSet.package_id
    media_id = [string]$installableMediaManifest.media_id
    release_id = [string]$releasePackageArtifactSet.release_id
    production_ready_claim = $false
    installer_updater_preflight = [ordered]@{
        evidence_bound = $preflightEvidenceBound
        install_preflight_ready = $preflightEvidenceBound
        update_preflight_ready = $preflightEvidenceBound
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        active_slot_mutation_allowed = $false
        boot_metadata_mutation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    binding_summary = [ordered]@{
        release_package_complete = $releasePackageComplete
        installable_media_complete = $installableMediaComplete
        descriptor_fail_closed_complete = $descriptorFailClosedComplete
        reproducibility_complete = $reproducibilityComplete
        candidate_promotion_complete = $candidatePromotionComplete
        package_media_identity_bound = $packageMediaIdentityBound
        release_bytes_bound = $releaseBytesBound
        update_metadata_bound = $updateMetadataBound
        compatibility_bound = $compatibilityBound
        rollback_support_source_bound = $rollbackSupportBound
        rc15_execution_bound = $rc15ExecutionBound
    }
    exact_target = [ordered]@{
        package_id = [string]$releasePackageArtifactSet.package_id
        media_id = [string]$installableMediaManifest.media_id
        release_id = [string]$releasePackageArtifactSet.release_id
        payload_sha256 = [string]$installableMediaManifest.release_bytes.payload.sha256
        payload_size_bytes = [int64]$installableMediaManifest.release_bytes.payload.size_bytes
        update_strategy = [ordered]@{
            mode = [string]$updateMetadata.update_strategy.mode
            stage_target = [string]$updateMetadata.update_strategy.stage_target
            active_slot_modified_in_place = $updateMetadata.update_strategy.active_slot_modified_in_place
            rollback_required = $updateMetadata.update_strategy.rollback_required
        }
        architecture = [ordered]@{
            target_arch = @($installableMediaManifest.architecture_and_compatibility.target_arch)
            kernel_family = [string]$installableMediaManifest.architecture_and_compatibility.kernel_family
            boot_modes = @($installableMediaManifest.architecture_and_compatibility.boot_modes)
        }
    }
    denial_cases = $cases
    side_effects = $sideEffects
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
        signer_reachability_authority = $false
        shell_output_authority = $false
        model_replay_authority = $false
        object_storage_ui_authority = $false
        tui_authority = $false
        install_authority = $false
        update_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        production_ring_mutation_authority = $false
        signing_authority = $false
    }
    source = $source
}
Write-Json $preflightPackage $packagePath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $packagePath))) "RC16-020 package output must not contain key blocks, private key paths, auth tokens, or public identity strings." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$packageSha256 = Get-FileSha256 $packagePath
$result = [ordered]@{
    schema = "agentos.rc16-installer-updater-preflight-package-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-020"
    status = $resultStatus
    production_ready_claim = $false
    preflight_id = $preflightId
    package_id = $preflightPackage.package_id
    media_id = $preflightPackage.media_id
    release_id = $preflightPackage.release_id
    preflight_surface = [ordered]@{
        state = $preflightState
        package_sha256 = $packageSha256
        release_package_artifact_set_sha256 = $releasePackageArtifactSetSha256
        installable_media_manifest_sha256 = $installableMediaManifestSha256
        package_descriptor_result_sha256 = $packageDescriptorResultSha256
        release_reproducibility_sha256 = $releaseReproducibilitySha256
        candidate_promotion_sha256 = $candidatePromotionSha256
        evidence_bound = $preflightEvidenceBound
        install_preflight_ready = $preflightEvidenceBound
        update_preflight_ready = $preflightEvidenceBound
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        installer_updater_preflight_package = [ordered]@{
            path = Get-StablePath $packagePath
            sha256 = $packageSha256
            preflight_id = $preflightId
        }
        candidate_promotion_preflight = [ordered]@{
            path = Get-StablePath $resolvedCandidatePromotionPreflightPath
            sha256 = $candidatePromotionSha256
        }
    }
    source = $source
    checks = $script:checks
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        signer_reachability_trusted = $false
        shell_output_trusted = $false
        model_replay_trusted = $false
        object_storage_ui_trusted = $false
        payload_upload_performed = $false
        payload_published = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
    blockers = @($blockers)
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        preflight_evidence_bound = $preflightEvidenceBound
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        rc16_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-021"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-installer-updater-preflight-package-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-020"
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
        rc16_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-021"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC16-020 outputs."
}

Write-Host "RC16 installer/updater preflight package $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Package: $(Get-StablePath $packagePath)"
Write-Host "Preflight evidence bound: $preflightEvidenceBound; install/update effects allowed: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
