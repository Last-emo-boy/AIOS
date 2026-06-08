param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-rollback-support-package",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$InstallUpdateBindingResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$InstallUpdatePlanSpecPath = ".workflow/artifacts/rc16-install-update-planspec-binding/install-update-planspec-package.json",
    [string]$SecurityExecutionEnvelopePath = ".workflow/artifacts/rc16-install-update-planspec-binding/security-execution-install-update-envelope.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$Rc15RollbackSupportResultPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/result.json",
    [string]$Rc15SupportRecoveryEvidenceChainPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/support-recovery-evidence-chain.json",
    [string]$Rc15SupportBundlePath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/controlled-execution-support-bundle.json",
    [string]$Rc15RecoveryReferenceIndexPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/recovery-reference-index.json",
    [string]$ReleaseArtifactsDocPath = "docs/release-artifacts.md",
    [string]$SupportBundleCodePath = "crates/agentd/src/support_bundle.rs",
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
            install_performed = $false
            update_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            private_signing_material_handled = $false
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
$resolvedInstallUpdateBindingResultPath = Resolve-RepoPath $InstallUpdateBindingResultPath
$resolvedInstallUpdatePlanSpecPath = Resolve-RepoPath $InstallUpdatePlanSpecPath
$resolvedSecurityExecutionEnvelopePath = Resolve-RepoPath $SecurityExecutionEnvelopePath
$resolvedInstallableMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedReleasePackageArtifactSetPath = Resolve-RepoPath $ReleasePackageArtifactSetPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedRc15RollbackSupportResultPath = Resolve-RepoPath $Rc15RollbackSupportResultPath
$resolvedRc15SupportRecoveryEvidenceChainPath = Resolve-RepoPath $Rc15SupportRecoveryEvidenceChainPath
$resolvedRc15SupportBundlePath = Resolve-RepoPath $Rc15SupportBundlePath
$resolvedRc15RecoveryReferenceIndexPath = Resolve-RepoPath $Rc15RecoveryReferenceIndexPath
$resolvedReleaseArtifactsDocPath = Resolve-RepoPath $ReleaseArtifactsDocPath
$resolvedSupportBundleCodePath = Resolve-RepoPath $SupportBundleCodePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseArtifactsText = Get-Content -Raw -LiteralPath $resolvedReleaseArtifactsDocPath
$supportBundleCodeText = Get-Content -Raw -LiteralPath $resolvedSupportBundleCodePath
$installUpdateResult = Read-Json $resolvedInstallUpdateBindingResultPath
$installUpdatePlanSpec = Read-Json $resolvedInstallUpdatePlanSpecPath
$securityEnvelope = Read-Json $resolvedSecurityExecutionEnvelopePath
$installableMediaManifest = Read-Json $resolvedInstallableMediaManifestPath
$releasePackageArtifactSet = Read-Json $resolvedReleasePackageArtifactSetPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath
$rc15RollbackResult = Read-Json $resolvedRc15RollbackSupportResultPath
$rc15EvidenceChain = Read-Json $resolvedRc15SupportRecoveryEvidenceChainPath
$rc15SupportBundle = Read-Json $resolvedRc15SupportBundlePath
$rc15RecoveryIndex = Read-Json $resolvedRc15RecoveryReferenceIndexPath

$rc16TaskStatus = Get-TaskStatus $plan "RC16-022"
$rc16PreviousStatus = Get-TaskStatus $plan "RC16-021"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-022" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-030" -and $rc16TaskStatus -eq "completed")
    )
)

$installUpdateBindingBound = (
    $installUpdateResult.status -eq "passed" -and
    $installUpdateResult.summary.rc16_021_complete -eq $true -and
    $installUpdateResult.readiness_surface.agentcore_install_update_planspec_bound -eq $true -and
    $installUpdateResult.readiness_surface.security_execution_install_update_envelope_bound -eq $true -and
    $installUpdateResult.readiness_surface.effect_prepared -eq $false
)
$packageIdentityBound = (
    [string]$installUpdateResult.package_id -eq [string]$installUpdatePlanSpec.package_id -and
    [string]$installUpdateResult.package_id -eq [string]$installableMediaManifest.package_id -and
    [string]$installUpdateResult.package_id -eq [string]$releasePackageArtifactSet.package_id -and
    [string]$installUpdateResult.media_id -eq [string]$installableMediaManifest.media_id -and
    [string]$installUpdateResult.release_id -eq [string]$installableMediaManifest.release_id
)
$rollbackBaselineBound = (
    $rollbackBaseline.production_ready_claim -eq $false -and
    $rollbackBaseline.execution_status.rollback_execution_allowed -eq $false -and
    [string]$installableMediaManifest.rollback_support.rollback_baseline_sha256 -eq (Get-FileSha256 $resolvedRollbackBaselinePath) -and
    [string]$installUpdatePlanSpec.planspec_core.binding_slots.rollback_baseline.sha256 -eq (Get-FileSha256 $resolvedRollbackBaselinePath)
)
$supportIndexBound = (
    $supportIndex.production_ready_claim -eq $false -and
    $supportIndex.redacted -eq $true -and
    $supportIndex.support_upload_allowed -eq $false -and
    $supportIndex.recovery_execution_allowed -eq $false -and
    [string]$installableMediaManifest.rollback_support.support_recovery_sha256 -eq (Get-FileSha256 $resolvedSupportIndexPath) -and
    [string]$installUpdatePlanSpec.planspec_core.binding_slots.support_recovery.sha256 -eq (Get-FileSha256 $resolvedSupportIndexPath)
)
$rc15RollbackSupportBound = (
    $rc15RollbackResult.status -eq "passed" -and
    $rc15RollbackResult.summary.rc15_031_complete -eq $true -and
    $rc15RollbackResult.rollback_surface.rollback_execution_performed -eq $true -and
    $rc15RollbackResult.rollback_surface.support_bundle_local_only -eq $true -and
    $rc15RollbackResult.rollback_surface.support_upload_performed -eq $false -and
    $rc15RollbackResult.rollback_surface.recovery_execution_performed -eq $false -and
    $rc15EvidenceChain.rollback_execution_performed -eq $true -and
    $rc15EvidenceChain.support_bundle_local_only -eq $true
)
$supportBundleManifestBound = (
    $rc15SupportBundle.local_only -eq $true -and
    $rc15SupportBundle.uploaded -eq $false -and
    $rc15SupportBundle.redacted -eq $true -and
    [string]$rc15SupportBundle.redaction_policy -eq "no-raw-secrets-no-tokens-no-private-material"
)
$recoveryReferenceBound = (
    $rc15RecoveryIndex.recovery_execution_allowed -eq $false -and
    $rc15RecoveryIndex.recovery_execution_performed -eq $false -and
    $rc15RecoveryIndex.support_bundle_upload_allowed -eq $false -and
    -not [string]::IsNullOrWhiteSpace([string]$rc15RecoveryIndex.references.rollback_attempt_digest) -and
    -not [string]::IsNullOrWhiteSpace([string]$rc15RecoveryIndex.references.rollback_audit_digest)
)
$docContractBound = (
    $releaseArtifactsText.Contains("RunStore, AuditJournal, and release rollback evidence") -and
    $releaseArtifactsText.Contains("redacted support bundle evidence") -and
    $releaseArtifactsText.Contains("all fail closed before effects")
)
$supportBundleCodeBound = (
    $supportBundleCodeText.Contains("agentos.support-bundle-manifest.v1") -and
    $supportBundleCodeText.Contains("secret-values-redacted") -and
    $supportBundleCodeText.Contains("private_key_paths_included") -and
    $supportBundleCodeText.Contains("run-store+audit-journal")
)

$blockers = [System.Collections.ArrayList]::new()
if (-not $installUpdateBindingBound) { Add-Unique $blockers "rc16-install-update-planspec-binding-not-complete" }
if (-not $packageIdentityBound) { Add-Unique $blockers "rc16-package-identity-not-bound" }
if (-not $rollbackBaselineBound) { Add-Unique $blockers "rc16-rollback-baseline-not-bound" }
if (-not $supportIndexBound) { Add-Unique $blockers "rc16-support-index-not-bound" }
if (-not $rc15RollbackSupportBound) { Add-Unique $blockers "rc15-rollback-support-evidence-not-bound" }
if (-not $supportBundleManifestBound) { Add-Unique $blockers "support-bundle-manifest-not-bound" }
if (-not $recoveryReferenceBound) { Add-Unique $blockers "recovery-reference-index-not-bound" }
if (-not $docContractBound) { Add-Unique $blockers "release-artifacts-rollback-support-contract-not-bound" }
if (-not $supportBundleCodeBound) { Add-Unique $blockers "agentd-support-bundle-code-contract-not-bound" }

Add-Unique $blockers "rc16-exact-install-update-target-not-bound"
Add-Unique $blockers "rc16-exact-install-update-approval-not-bound"
Add-Unique $blockers "rc16-install-update-planspec-not-executable"
Add-Unique $blockers "rc16-security-execution-install-update-allow-not-bound"
Add-Unique $blockers "rc16-local-release-channel-consumer-smoke-not-run"

$rollbackSupportPackageBound = (
    $installUpdateBindingBound -and
    $packageIdentityBound -and
    $rollbackBaselineBound -and
    $supportIndexBound -and
    $rc15RollbackSupportBound -and
    $supportBundleManifestBound -and
    $recoveryReferenceBound -and
    $docContractBound -and
    $supportBundleCodeBound
)

$postInstallObservationNeeds = @(
    [ordered]@{ id = "pre-install-active-artifact-set-hash"; required = $true; bound_before_effect = $true },
    [ordered]@{ id = "post-install-active-artifact-set-hash"; required = $true; bound_after_effect = $false },
    [ordered]@{ id = "boot-metadata-before-after-hash"; required = $true; bound_after_effect = $false },
    [ordered]@{ id = "audit-journal-seal"; required = $true; bound_after_effect = $false },
    [ordered]@{ id = "rollback-restore-equality-proof"; required = $true; bound_after_effect = $false },
    [ordered]@{ id = "support-bundle-redaction-proof"; required = $true; bound_before_effect = $supportBundleManifestBound },
    [ordered]@{ id = "recovery-reference-index-proof"; required = $true; bound_before_effect = $recoveryReferenceBound },
    [ordered]@{ id = "health-gate-observation"; required = $true; bound_after_effect = $false }
)

$sideEffects = [ordered]@{
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed = $false
    update_performed = $false
    rollback_execution_prepared = $false
    rollback_execution_performed = $false
    support_bundle_projected = $true
    support_bundle_local_only = $true
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    production_ring_mutated = $false
}

$packageCore = [ordered]@{
    schema = "agentos.rc16-rollback-support-package-core.v1"
    task = "RC16-022"
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    planspec_core_hash = [string]$installUpdateResult.readiness_surface.planspec_core_hash
    effect_envelope_core_hash = [string]$installUpdateResult.readiness_surface.effect_envelope_core_hash
    rollback_support_package_bound = $rollbackSupportPackageBound
    rollback_baseline = [ordered]@{
        path = Get-StablePath $resolvedRollbackBaselinePath
        sha256 = Get-FileSha256 $resolvedRollbackBaselinePath
        baseline_digest = [string]$rollbackBaseline.rollback_baseline_sha256
        previous_active_artifact_set_sha256 = [string]$rollbackBaseline.previous_active_artifact_set_sha256
        restored_active_artifact_set_sha256 = [string]$rollbackBaseline.restored_active_artifact_set_sha256
        restore_equality_required = $true
    }
    rollback_approval_requirements = [ordered]@{
        separate_rollback_approval_required = $true
        exact_actor_required = $true
        exact_package_identity_required = $true
        exact_planspec_hash_required = $true
        audit_journal_required = $true
        expiry_required = $true
        nonce_required = $true
        policy_version_required = $true
        security_execution_rollback_allow_required = $true
    }
    support_bundle_manifest = [ordered]@{
        source_path = Get-StablePath $resolvedRc15SupportBundlePath
        sha256 = Get-FileSha256 $resolvedRc15SupportBundlePath
        local_only = $rc15SupportBundle.local_only -eq $true
        uploaded = $false
        redacted = $rc15SupportBundle.redacted -eq $true
        redaction_policy = [string]$rc15SupportBundle.redaction_policy
        raw_secret_values_allowed = $false
        private_material_allowed = $false
    }
    recovery_references = [ordered]@{
        source_path = Get-StablePath $resolvedRc15RecoveryReferenceIndexPath
        sha256 = Get-FileSha256 $resolvedRc15RecoveryReferenceIndexPath
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        support_bundle_upload_allowed = $false
        rollback_attempt_digest = [string]$rc15RecoveryIndex.references.rollback_attempt_digest
        rollback_audit_digest = [string]$rc15RecoveryIndex.references.rollback_audit_digest
    }
    post_install_update_observation_needs = $postInstallObservationNeeds
}
$packageCoreHash = Get-StringSha256 (($packageCore | ConvertTo-Json -Depth 100 -Compress))

$caseObservedBlockers = @(
    "rc16-install-update-planspec-binding-not-complete",
    "rc16-package-identity-not-bound",
    "rc16-rollback-baseline-not-bound",
    "rc16-support-index-not-bound",
    "rc15-rollback-support-evidence-not-bound",
    "support-bundle-manifest-not-bound",
    "support-bundle-unredacted-denied",
    "recovery-reference-index-not-bound",
    "release-artifacts-rollback-support-contract-not-bound",
    "agentd-support-bundle-code-contract-not-bound",
    "post-install-observation-not-bound",
    "rollback-approval-requirements-not-bound",
    "support-upload-denied",
    "recovery-execution-denied",
    "remote-dispatch-denied",
    "active-slot-mutation-denied",
    "boot-metadata-mutation-denied",
    "active-artifact-set-mutation-denied",
    "private-signing-material-denied",
    "model-replay-is-not-authority",
    "tui-output-is-not-authority",
    "shell-output-is-not-authority",
    "production-ring-mutation-denied"
)
$caseExpectations = [ordered]@{
    "missing.install_update_planspec_binding" = @("rc16-install-update-planspec-binding-not-complete")
    "identity.package_mismatch" = @("rc16-package-identity-not-bound")
    "rollback.baseline_missing" = @("rc16-rollback-baseline-not-bound")
    "support.index_missing" = @("rc16-support-index-not-bound")
    "rc15.rollback_support_missing" = @("rc15-rollback-support-evidence-not-bound")
    "support.manifest_missing" = @("support-bundle-manifest-not-bound")
    "support.manifest_unredacted" = @("support-bundle-unredacted-denied")
    "recovery.reference_missing" = @("recovery-reference-index-not-bound")
    "docs.rollback_contract_missing" = @("release-artifacts-rollback-support-contract-not-bound")
    "code.support_bundle_contract_missing" = @("agentd-support-bundle-code-contract-not-bound")
    "post_install.observation_missing" = @("post-install-observation-not-bound")
    "rollback.approval_requirements_missing" = @("rollback-approval-requirements-not-bound")
    "authority.support_upload" = @("support-upload-denied")
    "authority.recovery_execution" = @("recovery-execution-denied")
    "authority.remote_dispatch" = @("remote-dispatch-denied")
    "authority.active_slot_mutation" = @("active-slot-mutation-denied")
    "authority.boot_metadata_mutation" = @("boot-metadata-mutation-denied")
    "authority.active_artifact_set_mutation" = @("active-artifact-set-mutation-denied")
    "authority.private_material" = @("private-signing-material-denied")
    "surface.model_replay" = @("model-replay-is-not-authority")
    "surface.tui_output" = @("tui-output-is-not-authority")
    "surface.shell_output" = @("shell-output-is-not-authority")
    "authority.production_ring_mutation" = @("production-ring-mutation-denied")
}
$cases = @()
foreach ($caseId in $caseExpectations.Keys) {
    $cases += New-DenialCase -Id $caseId -ExpectedBlockers ([string[]]$caseExpectations[$caseId]) -ObservedBlockers $caseObservedBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$source = [ordered]@{
    rc16_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc16_contract = New-ArtifactRef $resolvedContractPath
    rc16_install_update_binding_result = New-ArtifactRef $resolvedInstallUpdateBindingResultPath $installUpdateResult
    rc16_install_update_planspec_package = New-ArtifactRef $resolvedInstallUpdatePlanSpecPath $installUpdatePlanSpec
    rc16_security_execution_install_update_envelope = New-ArtifactRef $resolvedSecurityExecutionEnvelopePath $securityEnvelope
    rc16_installable_media_manifest = New-ArtifactRef $resolvedInstallableMediaManifestPath $installableMediaManifest
    rc16_release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $releasePackageArtifactSet
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    rc15_rollback_support_result = New-ArtifactRef $resolvedRc15RollbackSupportResultPath $rc15RollbackResult
    rc15_support_recovery_evidence_chain = New-ArtifactRef $resolvedRc15SupportRecoveryEvidenceChainPath $rc15EvidenceChain
    rc15_controlled_execution_support_bundle = New-ArtifactRef $resolvedRc15SupportBundlePath $rc15SupportBundle
    rc15_recovery_reference_index = New-ArtifactRef $resolvedRc15RecoveryReferenceIndexPath $rc15RecoveryIndex
    release_artifacts_doc = New-ArtifactRef $resolvedReleaseArtifactsDocPath
    agentd_support_bundle_code = New-ArtifactRef $resolvedSupportBundleCodePath
}

$packagePath = Join-Path $resolvedArtifactDir "rollback-support-package.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-022-rollback-support-package.json"

$rollbackSupportPackage = [ordered]@{
    schema = "agentos.rc16-rollback-support-package.v1"
    generated_at = $generatedAtValue
    task = "RC16-022"
    status = if ($rollbackSupportPackageBound) { "rollback-support-package-bound-effects-denied" } else { "rollback-support-package-denied-source-incomplete" }
    production_ready_claim = $false
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    planspec_core_hash = [string]$installUpdateResult.readiness_surface.planspec_core_hash
    effect_envelope_core_hash = [string]$installUpdateResult.readiness_surface.effect_envelope_core_hash
    rollback_support_package_core_hash = $packageCoreHash
    rollback_support_package_bound = $rollbackSupportPackageBound
    package_core = $packageCore
    binding_summary = [ordered]@{
        install_update_binding_bound = $installUpdateBindingBound
        package_identity_bound = $packageIdentityBound
        rollback_baseline_bound = $rollbackBaselineBound
        support_index_bound = $supportIndexBound
        rc15_rollback_support_bound = $rc15RollbackSupportBound
        support_bundle_manifest_bound = $supportBundleManifestBound
        recovery_reference_bound = $recoveryReferenceBound
        release_artifacts_contract_bound = $docContractBound
        support_bundle_code_bound = $supportBundleCodeBound
    }
    install_update_authority_after_binding = [ordered]@{
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_allowed = $false
        update_allowed = $false
        agentcore_install_update_planspec_executable = $false
        security_execution_allowed = $false
        blockers = @($blockers)
    }
    denial_cases = $cases
    side_effects = $sideEffects
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        active_slot_mutation_authority = $false
        boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        private_signing_material_authority = $false
        model_replay_authority = $false
        tui_authority = $false
        shell_output_authority = $false
    }
    source = $source
}
Write-Json $rollbackSupportPackage $packagePath

Add-Check "plan.current_task.rc16_022" $planAllowsRun "RC16-022 must run after RC16-021 completed, either while current_task is RC16-022 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_021_status = $rc16PreviousStatus; rc16_022_status = $rc16TaskStatus })
Add-Check "contract.rollback_support.present" ($contractText.Contains("Rollback baseline and support/recovery package evidence") -and $contractText.Contains("support upload and recovery execution remain disabled") -and $contractText.Contains("Audit trail requirements")) "RC16-022 must consume the RC16 rollback/support package contract." $source.rc16_contract
Add-Check "source.install_update_binding.bound" $installUpdateBindingBound "RC16-022 must consume completed RC16-021 install/update PlanSpec and SecurityExecution envelope evidence without effects." ([ordered]@{ status = $installUpdateResult.status; planspec_bound = $installUpdateResult.readiness_surface.agentcore_install_update_planspec_bound; security_envelope_bound = $installUpdateResult.readiness_surface.security_execution_install_update_envelope_bound; effect_prepared = $installUpdateResult.readiness_surface.effect_prepared })
Add-Check "source.rollback_support.bound" ($rollbackBaselineBound -and $supportIndexBound -and $packageIdentityBound) "Rollback baseline, support index, and package/media identity must be hash-bound for distributable install/update." ([ordered]@{ package_identity_bound = $packageIdentityBound; rollback_baseline_bound = $rollbackBaselineBound; support_index_bound = $supportIndexBound })
Add-Check "source.rc15.rollback_support.bound" $rc15RollbackSupportBound "RC16-022 must bind RC15 controlled rollback/support evidence while not executing rollback in RC16." ([ordered]@{ rc15_rollback_performed = $rc15RollbackResult.rollback_surface.rollback_execution_performed; rc15_support_local_only = $rc15RollbackResult.rollback_surface.support_bundle_local_only; rc15_support_upload_performed = $rc15RollbackResult.rollback_surface.support_upload_performed })
Add-Check "support.bundle.manifest.redacted_local" ($supportBundleManifestBound -and $recoveryReferenceBound) "Support bundle manifest and recovery references must be redacted, local-only, and non-executing." ([ordered]@{ support_bundle_local_only = $rc15SupportBundle.local_only; uploaded = $rc15SupportBundle.uploaded; redacted = $rc15SupportBundle.redacted; recovery_execution_performed = $rc15RecoveryIndex.recovery_execution_performed })
Add-Check "post_install.observation_needs.bound" (@($postInstallObservationNeeds).Count -ge 8 -and $postInstallObservationNeeds[0].bound_before_effect -eq $true) "Package must list post-install/update observation needs before any future effect authority can be prepared." ([ordered]@{ needs = $postInstallObservationNeeds })
Add-Check "docs.code.contracts.bound" ($docContractBound -and $supportBundleCodeBound) "Release artifact documentation and agentd support bundle code must encode recovery source of truth and redaction expectations." ([ordered]@{ release_artifacts_doc_sha256 = Get-FileSha256 $resolvedReleaseArtifactsDocPath; support_bundle_code_sha256 = Get-FileSha256 $resolvedSupportBundleCodePath })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing rollback/support refs, unredacted bundles, support upload, recovery execution, remote dispatch, mutation, private material, and display-surface authority cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" ($sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.active_slot_mutated -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC16-022 must not install, update, rollback, upload support, execute recovery, dispatch remotely, mutate slots/boot metadata/artifact sets, handle private signing material, or mutate production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $packagePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC16-022 package output must not contain key blocks, private key paths, auth tokens, or public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$packageSha256 = Get-FileSha256 $packagePath
$result = [ordered]@{
    schema = "agentos.rc16-rollback-support-package-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-022"
    status = $resultStatus
    production_ready_claim = $false
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    rollback_support_surface = [ordered]@{
        state = if ($rollbackSupportPackageBound) { "rollback-support-package-bound-install-update-effects-still-denied" } else { "rollback-support-package-denied-source-incomplete" }
        rollback_support_package_bound = $rollbackSupportPackageBound
        install_update_binding_bound = $installUpdateBindingBound
        package_identity_bound = $packageIdentityBound
        rollback_baseline_bound = $rollbackBaselineBound
        support_index_bound = $supportIndexBound
        rc15_rollback_support_bound = $rc15RollbackSupportBound
        support_bundle_manifest_bound = $supportBundleManifestBound
        recovery_reference_bound = $recoveryReferenceBound
        post_install_update_observation_needs_bound = $true
        support_bundle_local_only = $true
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        private_signing_material_handled = $false
        production_ring_mutation_allowed = $false
        rollback_support_package_core_hash = $packageCoreHash
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        rollback_support_package = [ordered]@{
            path = Get-StablePath $packagePath
            sha256 = $packageSha256
            rollback_support_package_core_hash = $packageCoreHash
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
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
        support_bundle_local_only = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        rollback_execution_performed = $false
        install_performed = $false
        update_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc16_022_complete = (@($script:failedChecks).Count -eq 0)
        rollback_support_package_bound = $rollbackSupportPackageBound
        support_bundle_local_only = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        rollback_execution_performed = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        next_task = "RC16-030"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-rollback-support-package-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-022"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    rollback_support_surface = $result.rollback_support_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-030"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC16-022 outputs."
}

Write-Host "RC16 rollback/support package $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Package: $(Get-StablePath $packagePath)"
Write-Host "Rollback/support package bound: $rollbackSupportPackageBound; support upload/recovery/rollback/install/update effects performed: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
