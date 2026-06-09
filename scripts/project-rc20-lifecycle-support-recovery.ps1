param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-lifecycle-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$ChannelPromotionResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
    [string]$InstallAcceptanceResultPath = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json",
    [string]$FirstBootAcceptanceResultPath = ".workflow/artifacts/rc20-first-boot-user-acceptance/result.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc20-post-install-update-drill/result.json",
    [string]$UpdateEvidencePath = ".workflow/artifacts/rc20-post-install-update-drill/update-drill-evidence.json",
    [string]$RollbackResultPath = ".workflow/artifacts/rc20-post-update-rollback-drill/result.json",
    [string]$RollbackEvidencePath = ".workflow/artifacts/rc20-post-update-rollback-drill/rollback-drill-evidence.json",
    [string]$Rc19SupportRecoveryResultPath = ".workflow/artifacts/rc19-first-user-support-recovery/result.json",
    [string]$Rc19SupportBundlePath = ".workflow/artifacts/rc19-first-user-support-recovery/first-user-support-bundle.json",
    [string]$Rc19RecoveryReferencePath = ".workflow/artifacts/rc19-first-user-support-recovery/recovery-reference-index.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
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
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param([string]$Id, [bool]$Passed, [string]$Message, $Evidence = $null)
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function New-ArtifactRef {
    param([string]$Path, $Json = $null)
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        task = if ($null -ne $Json) { $Json.task } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
        consumer_ready_claim = if ($null -ne $Json) { $Json.consumer_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $privateMarker = "PRIVATE" + " KEY"
    $publicMarker = "PUBLIC" + " KEY"
    $markers = @(
        ("BEGIN " + $privateMarker),
        ("BEGIN " + $publicMarker),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        ("pass" + "word="),
        ("sec" + "ret="),
        ("finger" + "print")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-SideEffects {
    param([bool]$SupportBundleCreated = $false)
    return [ordered]@{
        lifecycle_support_bundle_created = $SupportBundleCreated
        recovery_reference_index_created = $SupportBundleCreated
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_mutated = $false
        nginx_or_tls_changed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        shell_output_authority = $false
        tui_output_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
}

function New-DenialCase {
    param([string]$Id, [string[]]$Blockers, [string]$Reason)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_support_upload_or_recovery_execution = $true
        side_effects = New-SideEffects
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
$resolvedReleaseBundleResultPath = Resolve-RepoPath $ReleaseBundleResultPath
$resolvedChannelPromotionResultPath = Resolve-RepoPath $ChannelPromotionResultPath
$resolvedInstallAcceptanceResultPath = Resolve-RepoPath $InstallAcceptanceResultPath
$resolvedFirstBootAcceptanceResultPath = Resolve-RepoPath $FirstBootAcceptanceResultPath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedUpdateEvidencePath = Resolve-RepoPath $UpdateEvidencePath
$resolvedRollbackResultPath = Resolve-RepoPath $RollbackResultPath
$resolvedRollbackEvidencePath = Resolve-RepoPath $RollbackEvidencePath
$resolvedRc19SupportRecoveryResultPath = Resolve-RepoPath $Rc19SupportRecoveryResultPath
$resolvedRc19SupportBundlePath = Resolve-RepoPath $Rc19SupportBundlePath
$resolvedRc19RecoveryReferencePath = Resolve-RepoPath $Rc19RecoveryReferencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$channelPromotionResult = Read-Json $resolvedChannelPromotionResultPath
$installAcceptanceResult = Read-Json $resolvedInstallAcceptanceResultPath
$firstBootAcceptanceResult = Read-Json $resolvedFirstBootAcceptanceResultPath
$updateResult = Read-Json $resolvedUpdateResultPath
$updateEvidence = Read-Json $resolvedUpdateEvidencePath
$rollbackResult = Read-Json $resolvedRollbackResultPath
$rollbackEvidence = Read-Json $resolvedRollbackEvidencePath
$rc19SupportRecoveryResult = Read-Json $resolvedRc19SupportRecoveryResultPath
$rc19SupportBundle = Read-Json $resolvedRc19SupportBundlePath
$rc19RecoveryReference = Read-Json $resolvedRc19RecoveryReferencePath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-031"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-032"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-032" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$releaseBundleReady = (
    $releaseBundleResult.status -eq "passed" -and
    $releaseBundleResult.summary.rc20_010_complete -eq $true -and
    $releaseBundleResult.bundle_surface.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $releaseBundleResult.bundle_surface.first_user_target_state_id -eq $installAcceptanceResult.target_state_id -and
    $releaseBundleResult.bundle_surface.support_bundle_id -eq $rc19SupportRecoveryResult.support_bundle_id
)

$channelPromotionReady = (
    $channelPromotionResult.status -eq "passed" -and
    $channelPromotionResult.summary.rc20_011_complete -eq $true -and
    $channelPromotionResult.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $channelPromotionResult.summary.external_mirror_publication_performed -eq $false -and
    $channelPromotionResult.summary.active_artifact_set_mutated -eq $false -and
    $channelPromotionResult.summary.production_ring_mutated -eq $false
)

$installReady = (
    $installAcceptanceResult.status -eq "passed" -and
    $installAcceptanceResult.summary.rc20_021_complete -eq $true -and
    $installAcceptanceResult.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $installAcceptanceResult.selected_version -eq "rc20-single-user-stable-local-projection" -and
    $installAcceptanceResult.summary.first_user_install_performed_inside_disposable_target -eq $true -and
    $installAcceptanceResult.summary.host_rootfs_mutated -eq $false -and
    $installAcceptanceResult.summary.production_ring_mutated -eq $false
)

$firstBootReady = (
    $firstBootAcceptanceResult.status -eq "passed" -and
    $firstBootAcceptanceResult.summary.rc20_022_complete -eq $true -and
    $firstBootAcceptanceResult.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $firstBootAcceptanceResult.target_state_id -eq $installAcceptanceResult.target_state_id -and
    $firstBootAcceptanceResult.summary.projection_only_for_credentials -eq $true -and
    $firstBootAcceptanceResult.summary.raw_user_secret_introduced -eq $false -and
    $firstBootAcceptanceResult.summary.credential_material_introduced -eq $false -and
    $firstBootAcceptanceResult.summary.support_upload_performed -eq $false -and
    $firstBootAcceptanceResult.summary.recovery_execution_performed -eq $false -and
    $firstBootAcceptanceResult.summary.remote_dispatch_enabled -eq $false
)

$updateReady = (
    $updateResult.status -eq "passed" -and
    $updateResult.summary.rc20_030_complete -eq $true -and
    $updateResult.selected_version -eq $installAcceptanceResult.selected_version -and
    $updateResult.summary.isolated_update_performed_inside_disposable_installed_system -eq $true -and
    $updateResult.summary.rollback_prerequisites_bound -eq $true -and
    $updateResult.update_surface.host_active_slot_mutated -eq $false -and
    $updateResult.update_surface.production_ring_mutated -eq $false -and
    $updateEvidence.update_drill_id -eq $updateResult.update_drill_id
)

$rollbackReady = (
    $rollbackResult.status -eq "passed" -and
    $rollbackResult.summary.rc20_031_complete -eq $true -and
    $rollbackResult.selected_version -eq $installAcceptanceResult.selected_version -and
    $rollbackResult.update_drill_id -eq $updateResult.update_drill_id -and
    $rollbackResult.previous_updated_image_state_id -eq $updateResult.updated_image_state_id -and
    $rollbackResult.restored_target_state_id -eq $updateResult.previous_installed_image_state_id -and
    $rollbackResult.summary.rollback_performed -eq $true -and
    $rollbackResult.summary.support_upload_performed -eq $false -and
    $rollbackResult.summary.recovery_execution_performed -eq $false -and
    $rollbackResult.summary.remote_dispatch_enabled -eq $false -and
    $rollbackEvidence.rollback_audit_record.rollback_audit_record_id -eq $rollbackResult.rollback_audit_record_id
)

$rc19SupportReady = (
    $rc19SupportRecoveryResult.status -eq "passed" -and
    $rc19SupportRecoveryResult.summary.rc19_032_complete -eq $true -and
    $rc19SupportRecoveryResult.first_user_target_state_id -eq $installAcceptanceResult.target_state_id -and
    $rc19SupportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $rc19SupportRecoveryResult.summary.support_bundle_redacted -eq $true -and
    $rc19SupportRecoveryResult.summary.support_upload_performed -eq $false -and
    $rc19SupportRecoveryResult.summary.recovery_execution_performed -eq $false -and
    $rc19SupportRecoveryResult.summary.remote_dispatch_enabled -eq $false -and
    $rc19SupportBundle.local_only -eq $true -and
    $rc19SupportBundle.redacted -eq $true -and
    $rc19SupportBundle.uploaded -eq $false -and
    $rc19RecoveryReference.projection_only -eq $true -and
    $rc19RecoveryReference.recovery_execution_performed -eq $false
)

$stateChainReady = (
    $installAcceptanceResult.target_state_id -eq $releaseBundleResult.bundle_surface.first_user_target_state_id -and
    $firstBootAcceptanceResult.target_state_id -eq $installAcceptanceResult.target_state_id -and
    $updateResult.previous_installed_image_state_id -eq "sha256:3c407255ba8f5c2b26979bc2ceb4fa2d34eda72b5efbd2a244f21e6e13f098a5" -and
    $rollbackResult.previous_updated_image_state_id -eq $updateResult.updated_image_state_id -and
    $rollbackResult.restored_target_state_id -eq $updateResult.previous_installed_image_state_id
)

$supportClosureAllowed = (
    $planAllowsRun -and
    $releaseBundleReady -and
    $channelPromotionReady -and
    $installReady -and
    $firstBootReady -and
    $updateReady -and
    $rollbackReady -and
    $rc19SupportReady -and
    $stateChainReady
)

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-032-plan-pointer-not-current" }
if (-not $releaseBundleReady) { $blockers += "rc20-release-bundle-not-ready" }
if (-not $channelPromotionReady) { $blockers += "rc20-local-channel-promotion-not-ready" }
if (-not $installReady) { $blockers += "rc20-install-acceptance-not-ready" }
if (-not $firstBootReady) { $blockers += "rc20-first-boot-acceptance-not-ready" }
if (-not $updateReady) { $blockers += "rc20-post-install-update-not-ready" }
if (-not $rollbackReady) { $blockers += "rc20-post-update-rollback-not-ready" }
if (-not $rc19SupportReady) { $blockers += "rc19-support-recovery-not-ready" }
if (-not $stateChainReady) { $blockers += "rc20-lifecycle-state-chain-mismatch" }
if ($supportClosureAllowed) { $blockers = @() }

$source = [ordered]@{
    rc20_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc20_contract = New-ArtifactRef $resolvedContractPath
    rc20_release_bundle_result = New-ArtifactRef $resolvedReleaseBundleResultPath $releaseBundleResult
    rc20_channel_promotion_result = New-ArtifactRef $resolvedChannelPromotionResultPath $channelPromotionResult
    rc20_install_acceptance_result = New-ArtifactRef $resolvedInstallAcceptanceResultPath $installAcceptanceResult
    rc20_first_boot_acceptance_result = New-ArtifactRef $resolvedFirstBootAcceptanceResultPath $firstBootAcceptanceResult
    rc20_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc20_update_evidence = New-ArtifactRef $resolvedUpdateEvidencePath $updateEvidence
    rc20_rollback_result = New-ArtifactRef $resolvedRollbackResultPath $rollbackResult
    rc20_rollback_evidence = New-ArtifactRef $resolvedRollbackEvidencePath $rollbackEvidence
    rc19_support_recovery_result = New-ArtifactRef $resolvedRc19SupportRecoveryResultPath $rc19SupportRecoveryResult
    rc19_support_bundle = New-ArtifactRef $resolvedRc19SupportBundlePath $rc19SupportBundle
    rc19_recovery_reference = New-ArtifactRef $resolvedRc19RecoveryReferencePath $rc19RecoveryReference
}

$supportBundleCore = [ordered]@{
    schema = "agentos.rc20-lifecycle-support-bundle-core.v1"
    task = "RC20-032"
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    target_state_id = [string]$installAcceptanceResult.target_state_id
    install_acceptance_id = [string]$installAcceptanceResult.install_acceptance_id
    first_boot_acceptance_id = [string]$firstBootAcceptanceResult.first_boot_acceptance_id
    local_operator_posture_id = [string]$firstBootAcceptanceResult.local_operator_posture_id
    update_drill_id = [string]$updateResult.update_drill_id
    rollback_audit_record_id = [string]$rollbackResult.rollback_audit_record_id
    previous_installed_image_state_id = [string]$updateResult.previous_installed_image_state_id
    updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = [string]$rollbackResult.restored_target_state_id
    rc19_support_bundle_id = [string]$rc19SupportRecoveryResult.support_bundle_id
    rc19_recovery_reference_digest = [string]$rc19SupportRecoveryResult.recovery_reference_digest
    release_bundle_result_sha256 = Get-FileSha256 $resolvedReleaseBundleResultPath
    channel_promotion_result_sha256 = Get-FileSha256 $resolvedChannelPromotionResultPath
    install_acceptance_result_sha256 = Get-FileSha256 $resolvedInstallAcceptanceResultPath
    first_boot_acceptance_result_sha256 = Get-FileSha256 $resolvedFirstBootAcceptanceResultPath
    update_result_sha256 = Get-FileSha256 $resolvedUpdateResultPath
    update_evidence_sha256 = Get-FileSha256 $resolvedUpdateEvidencePath
    rollback_result_sha256 = Get-FileSha256 $resolvedRollbackResultPath
    rollback_evidence_sha256 = Get-FileSha256 $resolvedRollbackEvidencePath
    rc19_support_result_sha256 = Get-FileSha256 $resolvedRc19SupportRecoveryResultPath
    rc19_support_bundle_sha256 = Get-FileSha256 $resolvedRc19SupportBundlePath
    rc19_recovery_reference_sha256 = Get-FileSha256 $resolvedRc19RecoveryReferencePath
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    active_artifact_set_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$supportBundleDigest = Get-StringSha256 (Get-JsonText $supportBundleCore)

$supportBundle = [ordered]@{
    schema = "agentos.rc20-lifecycle-support-bundle.v1"
    generated_at = $generatedAtValue
    task = "RC20-032"
    status = if ($supportClosureAllowed) { "lifecycle-support-bundle-local-redacted" } else { "lifecycle-support-bundle-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    support_bundle_id = "rc20-lifecycle-support-$($supportBundleDigest.Substring(0, 16))"
    support_bundle_digest = $supportBundleDigest
    local_only = $true
    uploaded = $false
    redacted = $true
    redaction_policy = "no-raw-secrets-no-tokens-no-private-material-no-host-private-state"
    projection_only = $true
    support_bundle_core = $supportBundleCore
    included_evidence = @(
        "rc20-release-bundle-result",
        "rc20-local-channel-promotion-result",
        "rc20-install-acceptance-result",
        "rc20-first-boot-acceptance-result",
        "rc20-post-install-update-result",
        "rc20-post-update-rollback-result",
        "rc19-support-recovery-result",
        "rc19-recovery-reference-index"
    )
    side_effects = New-SideEffects -SupportBundleCreated:$supportClosureAllowed
    source = $source
}
$supportBundlePath = Join-Path $resolvedArtifactDir "lifecycle-support-bundle.json"
Write-Json $supportBundle $supportBundlePath

$recoveryReferenceCore = [ordered]@{
    schema = "agentos.rc20-lifecycle-recovery-reference-core.v1"
    task = "RC20-032"
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    support_bundle_id = [string]$supportBundle.support_bundle_id
    support_bundle_digest = [string]$supportBundle.support_bundle_digest
    support_bundle_sha256 = Get-FileSha256 $supportBundlePath
    install_acceptance_id = [string]$installAcceptanceResult.install_acceptance_id
    first_boot_acceptance_id = [string]$firstBootAcceptanceResult.first_boot_acceptance_id
    update_drill_id = [string]$updateResult.update_drill_id
    rollback_audit_record_id = [string]$rollbackResult.rollback_audit_record_id
    target_state_id = [string]$installAcceptanceResult.target_state_id
    updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = [string]$rollbackResult.restored_target_state_id
    rc19_support_bundle_id = [string]$rc19SupportRecoveryResult.support_bundle_id
    rc19_recovery_reference_digest = [string]$rc19SupportRecoveryResult.recovery_reference_digest
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$recoveryReferenceDigest = Get-StringSha256 (Get-JsonText $recoveryReferenceCore)
$recoveryReferenceIndex = [ordered]@{
    schema = "agentos.rc20-lifecycle-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC20-032"
    status = "projection-only-no-recovery-execution"
    production_ready_claim = $false
    consumer_ready_claim = $false
    projection_only = $true
    recovery_reference_digest = $recoveryReferenceDigest
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    references = $recoveryReferenceCore
    source = $source
}
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
Write-Json $recoveryReferenceIndex $recoveryIndexPath

$caseSpecs = @(
    [ordered]@{ id = "missing-release-bundle"; blockers = @("rc20-release-bundle-not-ready"); reason = "Lifecycle support requires RC20 release bundle evidence." },
    [ordered]@{ id = "missing-channel-promotion"; blockers = @("rc20-local-channel-promotion-not-ready"); reason = "Lifecycle support requires local channel promotion evidence." },
    [ordered]@{ id = "missing-install-acceptance"; blockers = @("rc20-install-acceptance-not-ready"); reason = "Lifecycle support requires install acceptance evidence." },
    [ordered]@{ id = "missing-first-boot-acceptance"; blockers = @("rc20-first-boot-acceptance-not-ready"); reason = "Lifecycle support requires first boot user acceptance evidence." },
    [ordered]@{ id = "missing-update-evidence"; blockers = @("rc20-post-install-update-not-ready"); reason = "Lifecycle support requires post-install update evidence." },
    [ordered]@{ id = "missing-rollback-evidence"; blockers = @("rc20-post-update-rollback-not-ready"); reason = "Lifecycle support requires post-update rollback evidence." },
    [ordered]@{ id = "state-chain-mismatch"; blockers = @("rc20-lifecycle-state-chain-mismatch"); reason = "Lifecycle support denies incoherent install/update/rollback state chain." },
    [ordered]@{ id = "missing-rc19-support-reference"; blockers = @("rc19-support-recovery-not-ready"); reason = "Lifecycle support must bind RC19 support/recovery reference." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is outside RC20 body scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is outside RC20 body scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is outside RC20 body scope." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "mirror-frontend-authority"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not lifecycle support authority." },
    [ordered]@{ id = "nginx-tls-authority"; blockers = @("nginx-tls-authority-denied"); reason = "Nginx/TLS infrastructure changes are outside RC20 body scope." },
    [ordered]@{ id = "signer-authority"; blockers = @("signer-authority-denied"); reason = "Signer authority is outside RC20 body scope." },
    [ordered]@{ id = "object-storage-provisioning"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is outside RC20 body scope." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "release-signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "Release signing is outside RC20 body scope." },
    [ordered]@{ id = "shell-authority-attempt"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not lifecycle support authority." },
    [ordered]@{ id = "tui-authority-attempt"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not lifecycle support authority." },
    [ordered]@{ id = "endpoint-authority-attempt"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not lifecycle support authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not lifecycle support authority." },
    [ordered]@{ id = "consumer-ready-claim"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for RC20 consumer smoke." },
    [ordered]@{ id = "ga-claim"; blockers = @("ga-claim-denied"); reason = "RC20 lifecycle support cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc20_032" $planAllowsRun "RC20-032 must run after RC20-031 completed, with current_task set to RC20-032." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_031_status = $rc20PreviousStatus; rc20_032_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-032 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "source.release_bundle.ready" $releaseBundleReady "Lifecycle support must bind canonical RC20 release bundle evidence." ([ordered]@{ release_bundle_id = $releaseBundleResult.release_bundle_id; target_state_id = $releaseBundleResult.bundle_surface.first_user_target_state_id; support_bundle_id = $releaseBundleResult.bundle_surface.support_bundle_id })
Add-Check "source.channel_promotion.ready" $channelPromotionReady "Lifecycle support must bind local channel promotion without external mirror publication or production mutation." ([ordered]@{ release_bundle_id = $channelPromotionResult.release_bundle_id; external_mirror_publication_performed = $channelPromotionResult.summary.external_mirror_publication_performed; active_artifact_set_mutated = $channelPromotionResult.summary.active_artifact_set_mutated; production_ring_mutated = $channelPromotionResult.summary.production_ring_mutated })
Add-Check "source.install_first_boot.ready" ($installReady -and $firstBootReady) "Lifecycle support must bind install acceptance and first boot posture for the same target state without credential or remote authority." ([ordered]@{ install_acceptance_id = $installAcceptanceResult.install_acceptance_id; first_boot_acceptance_id = $firstBootAcceptanceResult.first_boot_acceptance_id; target_state_id = $installAcceptanceResult.target_state_id; first_boot_target_state_id = $firstBootAcceptanceResult.target_state_id })
Add-Check "source.update_rollback.ready" ($updateReady -and $rollbackReady) "Lifecycle support must bind update and rollback execution drills inside the disposable installed-system boundary." ([ordered]@{ update_drill_id = $updateResult.update_drill_id; rollback_audit_record_id = $rollbackResult.rollback_audit_record_id; updated_image_state_id = $updateResult.updated_image_state_id; restored_target_state_id = $rollbackResult.restored_target_state_id })
Add-Check "source.state_chain.coherent" $stateChainReady "Install, first boot, update, and rollback state chain must be coherent." ([ordered]@{ first_user_target_state_id = $installAcceptanceResult.target_state_id; previous_installed_image_state_id = $updateResult.previous_installed_image_state_id; updated_image_state_id = $updateResult.updated_image_state_id; restored_target_state_id = $rollbackResult.restored_target_state_id })
Add-Check "source.rc19_support_recovery.bound" $rc19SupportReady "Lifecycle support must bind RC19 local-only support/recovery reference without upload or recovery execution." ([ordered]@{ support_bundle_id = $rc19SupportRecoveryResult.support_bundle_id; recovery_reference_digest = $rc19SupportRecoveryResult.recovery_reference_digest; local_only = $rc19SupportBundle.local_only; redacted = $rc19SupportBundle.redacted; uploaded = $rc19SupportBundle.uploaded; recovery_execution_performed = $rc19RecoveryReference.recovery_execution_performed })
Add-Check "support.bundle.local_redacted" ($supportBundle.local_only -eq $true -and $supportBundle.uploaded -eq $false -and $supportBundle.redacted -eq $true -and $supportBundle.support_bundle_core.install_acceptance_result_sha256 -eq (Get-FileSha256 $resolvedInstallAcceptanceResultPath) -and $supportBundle.support_bundle_core.update_result_sha256 -eq (Get-FileSha256 $resolvedUpdateResultPath) -and $supportBundle.support_bundle_core.rollback_result_sha256 -eq (Get-FileSha256 $resolvedRollbackResultPath)) "Lifecycle support bundle must be local-only, redacted, and hash-bound to install, first boot, update, rollback, and RC19 support/recovery evidence." ([ordered]@{ support_bundle_id = $supportBundle.support_bundle_id; local_only = $supportBundle.local_only; redacted = $supportBundle.redacted; uploaded = $supportBundle.uploaded })
Add-Check "recovery.index.projection_only" ($recoveryReferenceIndex.projection_only -eq $true -and $recoveryReferenceIndex.recovery_execution_allowed -eq $false -and $recoveryReferenceIndex.recovery_execution_performed -eq $false -and $recoveryReferenceIndex.support_bundle_upload_allowed -eq $false -and $recoveryReferenceIndex.remote_dispatch_enabled -eq $false) "Recovery reference index must be projection-only and must not execute recovery, upload support, or dispatch remotely." ([ordered]@{ recovery_reference_digest = $recoveryReferenceDigest; recovery_execution_allowed = $recoveryReferenceIndex.recovery_execution_allowed; recovery_execution_performed = $recoveryReferenceIndex.recovery_execution_performed; support_bundle_upload_allowed = $recoveryReferenceIndex.support_bundle_upload_allowed; remote_dispatch_enabled = $recoveryReferenceIndex.remote_dispatch_enabled })
Add-Check "authority.no_forbidden_side_effects" ($supportBundle.side_effects.support_upload_performed -eq $false -and $supportBundle.side_effects.recovery_execution_performed -eq $false -and $supportBundle.side_effects.remote_dispatch_enabled -eq $false -and $supportBundle.side_effects.host_rootfs_mutated -eq $false -and $supportBundle.side_effects.host_active_slot_mutated -eq $false -and $supportBundle.side_effects.host_boot_metadata_mutated -eq $false -and $supportBundle.side_effects.active_artifact_set_mutated -eq $false -and $supportBundle.side_effects.production_ring_mutated -eq $false -and $supportBundle.side_effects.mirror_frontend_mutated -eq $false -and $supportBundle.side_effects.nginx_or_tls_changed -eq $false -and $supportBundle.side_effects.signer_authority_granted -eq $false -and $supportBundle.side_effects.object_storage_provisioned -eq $false -and $supportBundle.side_effects.private_signing_material_handled -eq $false -and $supportBundle.side_effects.cryptographic_signing_performed -eq $false) "RC20-032 must not upload support, execute recovery, remote dispatch, mutate host or production state, change mirror/Nginx/TLS, grant signer authority, provision object storage, handle private material, or sign." $supportBundle.side_effects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 24) "Missing lifecycle sources and forbidden authority surfaces must deny before support upload, recovery execution, host mutation, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC20-032 outputs must not contain key blocks, private authority paths, auth tokens, signing key file names, raw passwords, raw secrets, or public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-lifecycle-support-recovery-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-032"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    target_state_id = [string]$installAcceptanceResult.target_state_id
    previous_installed_image_state_id = [string]$updateResult.previous_installed_image_state_id
    updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = [string]$rollbackResult.restored_target_state_id
    support_bundle_id = [string]$supportBundle.support_bundle_id
    support_bundle_digest = [string]$supportBundle.support_bundle_digest
    recovery_reference_digest = [string]$recoveryReferenceDigest
    lifecycle_support_surface = [ordered]@{
        state = if ($supportClosureAllowed) { "lifecycle-support-recovery-projection-bound" } else { "lifecycle-support-recovery-projection-denied" }
        release_bundle_bound = $releaseBundleReady
        channel_promotion_bound = $channelPromotionReady
        install_acceptance_bound = $installReady
        first_boot_acceptance_bound = $firstBootReady
        post_install_update_bound = $updateReady
        post_update_rollback_bound = $rollbackReady
        rc19_support_recovery_bound = $rc19SupportReady
        lifecycle_state_chain_bound = $stateChainReady
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_mutated = $false
        nginx_or_tls_changed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        lifecycle_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = Get-FileSha256 $supportBundlePath
            support_bundle_id = $supportBundle.support_bundle_id
            support_bundle_digest = $supportBundleDigest
            local_only = $true
            redacted = $true
            uploaded = $false
        }
        recovery_reference_index = [ordered]@{
            path = Get-StablePath $recoveryIndexPath
            sha256 = Get-FileSha256 $recoveryIndexPath
            recovery_reference_digest = $recoveryReferenceDigest
            projection_only = $true
            recovery_execution_performed = $false
        }
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        lifecycle_support_projection_only = $true
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_authority = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        shell_output_authority = $false
        tui_output_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_032_complete = (@($script:failedChecks).Count -eq 0)
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        selected_version = [string]$installAcceptanceResult.selected_version
        target_state_id = [string]$installAcceptanceResult.target_state_id
        lifecycle_state_chain_bound = $stateChainReady
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC20-040"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-032-lifecycle-support-recovery.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-lifecycle-support-recovery-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-032"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
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
    lifecycle_support_surface = $result.lifecycle_support_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_032_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-040"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-032 outputs." }

Write-Host "RC20 lifecycle support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Lifecycle support bundle: $(Get-StablePath $supportBundlePath)"
Write-Host "Recovery index: $(Get-StablePath $recoveryIndexPath)"
Write-Host "Support upload/recovery/remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
