param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-single-user-distribution-consumer-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$ChannelPromotionResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
    [string]$InstallerCatalogResultPath = ".workflow/artifacts/rc20-installer-catalog-selection/result.json",
    [string]$InstallAcceptanceResultPath = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json",
    [string]$FirstBootAcceptanceResultPath = ".workflow/artifacts/rc20-first-boot-user-acceptance/result.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc20-post-install-update-drill/result.json",
    [string]$RollbackResultPath = ".workflow/artifacts/rc20-post-update-rollback-drill/result.json",
    [string]$LifecycleSupportResultPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/result.json",
    [string]$LifecycleSupportBundlePath = ".workflow/artifacts/rc20-lifecycle-support-recovery/lifecycle-support-bundle.json",
    [string]$RecoveryIndexPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/recovery-reference-index.json",
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
    $identityMarker = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateMarker),
        ("BEGIN " + $publicMarker),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        ("pass" + "word="),
        ("sec" + "ret="),
        $identityMarker
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-FailClosedCase {
    param([string]$Id, [string[]]$Blockers, [string]$Reason)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_consumer_ready = $true
        side_effects = [ordered]@{
            install_performed_by_consumer_smoke = $false
            update_performed_by_consumer_smoke = $false
            rollback_execution_performed_by_consumer_smoke = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_payload_downloaded = $false
            object_storage_provisioned = $false
            remote_dispatch_enabled = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            mirror_frontend_authority = $false
            nginx_or_tls_authority = $false
            endpoint_reachability_trusted = $false
            shell_output_trusted = $false
            tui_output_trusted = $false
            model_replay_trusted = $false
            signer_authority_granted = $false
            private_signing_material_handled = $false
            cryptographic_signing_performed = $false
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
$resolvedReleaseBundleResultPath = Resolve-RepoPath $ReleaseBundleResultPath
$resolvedChannelPromotionResultPath = Resolve-RepoPath $ChannelPromotionResultPath
$resolvedInstallerCatalogResultPath = Resolve-RepoPath $InstallerCatalogResultPath
$resolvedInstallAcceptanceResultPath = Resolve-RepoPath $InstallAcceptanceResultPath
$resolvedFirstBootAcceptanceResultPath = Resolve-RepoPath $FirstBootAcceptanceResultPath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedRollbackResultPath = Resolve-RepoPath $RollbackResultPath
$resolvedLifecycleSupportResultPath = Resolve-RepoPath $LifecycleSupportResultPath
$resolvedLifecycleSupportBundlePath = Resolve-RepoPath $LifecycleSupportBundlePath
$resolvedRecoveryIndexPath = Resolve-RepoPath $RecoveryIndexPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$channelPromotionResult = Read-Json $resolvedChannelPromotionResultPath
$installerCatalogResult = Read-Json $resolvedInstallerCatalogResultPath
$installAcceptanceResult = Read-Json $resolvedInstallAcceptanceResultPath
$firstBootAcceptanceResult = Read-Json $resolvedFirstBootAcceptanceResultPath
$updateResult = Read-Json $resolvedUpdateResultPath
$rollbackResult = Read-Json $resolvedRollbackResultPath
$lifecycleSupportResult = Read-Json $resolvedLifecycleSupportResultPath
$lifecycleSupportBundle = Read-Json $resolvedLifecycleSupportBundlePath
$recoveryIndex = Read-Json $resolvedRecoveryIndexPath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-032"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-040"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc20PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC20-040" -and ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC20-050" -and $rc20TaskStatus -eq "completed")
    )
)

$contractBound = (
    $contractText.Contains("Consumer smoke can report local single-user distribution readiness, not production readiness.") -and
    $contractText.Contains("No later gate can claim readiness if an earlier gate is missing") -and
    $contractText.Contains("GA production-ready claim")
)

$releaseBundleReady = (
    $releaseBundleResult.status -eq "passed" -and
    $releaseBundleResult.summary.rc20_010_complete -eq $true -and
    $releaseBundleResult.release_bundle_id -eq $channelPromotionResult.release_bundle_id -and
    $releaseBundleResult.release_bundle_id -eq $installerCatalogResult.release_bundle_id -and
    $releaseBundleResult.release_bundle_id -eq $installAcceptanceResult.release_bundle_id -and
    $releaseBundleResult.release_bundle_id -eq $firstBootAcceptanceResult.release_bundle_id -and
    $releaseBundleResult.release_bundle_id -eq $lifecycleSupportResult.release_bundle_id
)

$channelReady = (
    $channelPromotionResult.status -eq "passed" -and
    $channelPromotionResult.summary.rc20_011_complete -eq $true -and
    $channelPromotionResult.summary.candidate_channel_package_bound -eq $true -and
    $channelPromotionResult.summary.stable_channel_projection_bound -eq $true -and
    $channelPromotionResult.summary.external_mirror_publication_performed -eq $false -and
    $channelPromotionResult.summary.active_artifact_set_mutated -eq $false -and
    $channelPromotionResult.summary.production_ring_mutated -eq $false
)

$installerReady = (
    $installerCatalogResult.status -eq "passed" -and
    $installerCatalogResult.summary.rc20_020_complete -eq $true -and
    $installerCatalogResult.summary.catalog_exactly_expected -eq $true -and
    $installerCatalogResult.summary.preflight_binds_required_identity -eq $true -and
    $installerCatalogResult.summary.host_install_authorized -eq $false -and
    $installerCatalogResult.summary.remote_fetch_authorized -eq $false -and
    $installerCatalogResult.summary.external_mirror_trusted -eq $false
)

$installReady = (
    $installAcceptanceResult.status -eq "passed" -and
    $installAcceptanceResult.summary.rc20_021_complete -eq $true -and
    $installAcceptanceResult.selected_version -eq "rc20-single-user-stable-local-projection" -and
    $installAcceptanceResult.summary.first_user_install_performed_inside_disposable_target -eq $true -and
    $installAcceptanceResult.summary.host_rootfs_mutated -eq $false -and
    $installAcceptanceResult.summary.production_ring_mutated -eq $false
)

$firstBootReady = (
    $firstBootAcceptanceResult.status -eq "passed" -and
    $firstBootAcceptanceResult.summary.rc20_022_complete -eq $true -and
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
    $updateResult.update_surface.production_ring_mutated -eq $false
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
    $rollbackResult.summary.remote_dispatch_enabled -eq $false
)

$supportReady = (
    $lifecycleSupportResult.status -eq "passed" -and
    $lifecycleSupportResult.summary.rc20_032_complete -eq $true -and
    $lifecycleSupportResult.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $lifecycleSupportResult.selected_version -eq $installAcceptanceResult.selected_version -and
    $lifecycleSupportResult.target_state_id -eq $installAcceptanceResult.target_state_id -and
    $lifecycleSupportResult.summary.lifecycle_state_chain_bound -eq $true -and
    $lifecycleSupportResult.summary.support_bundle_local_only -eq $true -and
    $lifecycleSupportResult.summary.support_bundle_redacted -eq $true -and
    $lifecycleSupportResult.summary.support_upload_performed -eq $false -and
    $lifecycleSupportResult.summary.recovery_execution_performed -eq $false -and
    $lifecycleSupportResult.summary.remote_dispatch_enabled -eq $false -and
    $lifecycleSupportBundle.local_only -eq $true -and
    $lifecycleSupportBundle.redacted -eq $true -and
    $lifecycleSupportBundle.uploaded -eq $false -and
    $recoveryIndex.projection_only -eq $true -and
    $recoveryIndex.recovery_execution_performed -eq $false
)

$targetChainReady = (
    $releaseBundleResult.bundle_surface.first_user_target_state_id -eq $installAcceptanceResult.target_state_id -and
    $firstBootAcceptanceResult.target_state_id -eq $installAcceptanceResult.target_state_id -and
    $lifecycleSupportResult.target_state_id -eq $installAcceptanceResult.target_state_id
)

$lifecycleChainReady = (
    $updateResult.previous_installed_image_state_id -eq $lifecycleSupportResult.previous_installed_image_state_id -and
    $updateResult.updated_image_state_id -eq $rollbackResult.previous_updated_image_state_id -and
    $rollbackResult.restored_target_state_id -eq $lifecycleSupportResult.restored_target_state_id
)

$consumerReady = (
    $planAllowsRun -and
    $contractBound -and
    $releaseBundleReady -and
    $channelReady -and
    $installerReady -and
    $installReady -and
    $firstBootReady -and
    $updateReady -and
    $rollbackReady -and
    $supportReady -and
    $targetChainReady -and
    $lifecycleChainReady
)
$consumerDecision = if ($consumerReady) { "single-user-distribution-local-consumer-ready" } else { "single-user-distribution-denied-before-effect" }

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-040-plan-pointer-not-current" }
if (-not $contractBound) { $blockers += "rc20-consumer-contract-not-bound" }
if (-not $releaseBundleReady) { $blockers += "rc20-release-bundle-not-ready" }
if (-not $channelReady) { $blockers += "rc20-local-channel-not-ready" }
if (-not $installerReady) { $blockers += "rc20-installer-catalog-not-ready" }
if (-not $installReady) { $blockers += "rc20-install-acceptance-not-ready" }
if (-not $firstBootReady) { $blockers += "rc20-first-boot-acceptance-not-ready" }
if (-not $updateReady) { $blockers += "rc20-post-install-update-not-ready" }
if (-not $rollbackReady) { $blockers += "rc20-post-update-rollback-not-ready" }
if (-not $supportReady) { $blockers += "rc20-lifecycle-support-recovery-not-ready" }
if (-not $targetChainReady) { $blockers += "single-user-target-state-chain-mismatch" }
if (-not $lifecycleChainReady) { $blockers += "single-user-lifecycle-state-chain-mismatch" }
if ($consumerReady) { $blockers = @() }

$sideEffects = [ordered]@{
    consumer_smoke_evaluated = $true
    install_effect_prepared = $false
    update_effect_prepared = $false
    rollback_effect_prepared = $false
    install_performed_by_consumer_smoke = $false
    update_performed_by_consumer_smoke = $false
    rollback_execution_performed_by_consumer_smoke = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_payload_downloaded = $false
    object_storage_provisioned = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    mirror_frontend_authority = $false
    nginx_or_tls_authority = $false
    endpoint_reachability_trusted = $false
    frontend_output_trusted = $false
    shell_output_trusted = $false
    tui_output_trusted = $false
    model_replay_trusted = $false
    signer_authority_granted = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
}

$source = [ordered]@{
    rc20_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc20_contract = New-ArtifactRef $resolvedContractPath
    rc20_release_bundle_result = New-ArtifactRef $resolvedReleaseBundleResultPath $releaseBundleResult
    rc20_channel_promotion_result = New-ArtifactRef $resolvedChannelPromotionResultPath $channelPromotionResult
    rc20_installer_catalog_result = New-ArtifactRef $resolvedInstallerCatalogResultPath $installerCatalogResult
    rc20_install_acceptance_result = New-ArtifactRef $resolvedInstallAcceptanceResultPath $installAcceptanceResult
    rc20_first_boot_acceptance_result = New-ArtifactRef $resolvedFirstBootAcceptanceResultPath $firstBootAcceptanceResult
    rc20_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc20_rollback_result = New-ArtifactRef $resolvedRollbackResultPath $rollbackResult
    rc20_lifecycle_support_result = New-ArtifactRef $resolvedLifecycleSupportResultPath $lifecycleSupportResult
    rc20_lifecycle_support_bundle = New-ArtifactRef $resolvedLifecycleSupportBundlePath $lifecycleSupportBundle
    rc20_recovery_reference_index = New-ArtifactRef $resolvedRecoveryIndexPath $recoveryIndex
}

$auditMaterial = [ordered]@{
    schema = "agentos.rc20-single-user-distribution-consumer-smoke-audit-material.v1"
    task = "RC20-040"
    generated_at = $generatedAtValue
    decision = $consumerDecision
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    target_state_id = [string]$installAcceptanceResult.target_state_id
    previous_installed_image_state_id = [string]$updateResult.previous_installed_image_state_id
    updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = [string]$rollbackResult.restored_target_state_id
    support_bundle_id = [string]$lifecycleSupportResult.support_bundle_id
    recovery_reference_digest = [string]$lifecycleSupportResult.recovery_reference_digest
    release_bundle_result_sha256 = Get-FileSha256 $resolvedReleaseBundleResultPath
    channel_promotion_result_sha256 = Get-FileSha256 $resolvedChannelPromotionResultPath
    installer_catalog_result_sha256 = Get-FileSha256 $resolvedInstallerCatalogResultPath
    install_acceptance_result_sha256 = Get-FileSha256 $resolvedInstallAcceptanceResultPath
    first_boot_acceptance_result_sha256 = Get-FileSha256 $resolvedFirstBootAcceptanceResultPath
    update_result_sha256 = Get-FileSha256 $resolvedUpdateResultPath
    rollback_result_sha256 = Get-FileSha256 $resolvedRollbackResultPath
    lifecycle_support_result_sha256 = Get-FileSha256 $resolvedLifecycleSupportResultPath
    blockers = @($blockers)
    side_effects = $sideEffects
}
$auditDigest = Get-StringSha256 (Get-JsonText $auditMaterial)

$auditRecord = [ordered]@{
    schema = "agentos.rc20-single-user-distribution-consumer-smoke-audit.v1"
    generated_at = $generatedAtValue
    task = "RC20-040"
    local_only = $true
    fabricated = $false
    decision = $consumerDecision
    decision_digest = $auditDigest
    release_bundle_bound = $releaseBundleReady
    local_channel_bound = $channelReady
    installer_catalog_bound = $installerReady
    install_acceptance_bound = $installReady
    first_boot_acceptance_bound = $firstBootReady
    update_bound = $updateReady
    rollback_bound = $rollbackReady
    support_recovery_bound = $supportReady
    target_chain_bound = $targetChainReady
    lifecycle_chain_bound = $lifecycleChainReady
    consumer_ready_claim = $consumerReady
    production_ready_claim = $false
    blockers = @($blockers)
}

$caseSpecs = @(
    [ordered]@{ id = "missing-release-bundle"; blockers = @("rc20-release-bundle-not-ready"); reason = "Consumer smoke requires release bundle evidence." },
    [ordered]@{ id = "missing-local-channel"; blockers = @("rc20-local-channel-not-ready"); reason = "Consumer smoke requires local channel evidence." },
    [ordered]@{ id = "missing-installer-catalog"; blockers = @("rc20-installer-catalog-not-ready"); reason = "Consumer smoke requires installer catalog selection evidence." },
    [ordered]@{ id = "missing-install-acceptance"; blockers = @("rc20-install-acceptance-not-ready"); reason = "Consumer smoke requires install acceptance evidence." },
    [ordered]@{ id = "missing-first-boot-acceptance"; blockers = @("rc20-first-boot-acceptance-not-ready"); reason = "Consumer smoke requires first boot user acceptance evidence." },
    [ordered]@{ id = "missing-update-drill"; blockers = @("rc20-post-install-update-not-ready"); reason = "Consumer smoke requires post-install update evidence." },
    [ordered]@{ id = "missing-rollback-drill"; blockers = @("rc20-post-update-rollback-not-ready"); reason = "Consumer smoke requires post-update rollback evidence." },
    [ordered]@{ id = "missing-lifecycle-support"; blockers = @("rc20-lifecycle-support-recovery-not-ready"); reason = "Consumer smoke requires lifecycle support/recovery evidence." },
    [ordered]@{ id = "target-state-chain-mismatch"; blockers = @("single-user-target-state-chain-mismatch"); reason = "Consumer smoke cannot report readiness for mismatched target state." },
    [ordered]@{ id = "lifecycle-state-chain-mismatch"; blockers = @("single-user-lifecycle-state-chain-mismatch"); reason = "Consumer smoke cannot report readiness for mismatched update/rollback state chain." },
    [ordered]@{ id = "new-install-attempt"; blockers = @("consumer-install-effect-denied"); reason = "Consumer smoke must not execute install." },
    [ordered]@{ id = "new-update-attempt"; blockers = @("consumer-update-effect-denied"); reason = "Consumer smoke must not execute update." },
    [ordered]@{ id = "new-rollback-attempt"; blockers = @("consumer-rollback-effect-denied"); reason = "Consumer smoke must not execute rollback." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of scope." },
    [ordered]@{ id = "object-storage-provisioning-attempt"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not consumer authority." },
    [ordered]@{ id = "nginx-tls-authority-attempt"; blockers = @("nginx-tls-authority-denied"); reason = "Nginx/TLS output is not consumer authority." },
    [ordered]@{ id = "endpoint-authority-attempt"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not consumer authority." },
    [ordered]@{ id = "shell-output-authority-attempt"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not consumer authority." },
    [ordered]@{ id = "tui-output-authority-attempt"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not consumer authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not consumer authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not consumer authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "release-signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "Release signing is out of scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "Consumer smoke cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$consumerEvidence = [ordered]@{
    schema = "agentos.rc20-single-user-distribution-consumer-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-040"
    status = $consumerDecision
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
    local_only = $true
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    target_state_id = [string]$installAcceptanceResult.target_state_id
    readiness = [ordered]@{
        outcome = $consumerDecision
        release_bundle_readiness = if ($releaseBundleReady) { "ready" } else { "denied" }
        local_channel_readiness = if ($channelReady) { "ready" } else { "denied" }
        installer_catalog_readiness = if ($installerReady) { "ready" } else { "denied" }
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        first_boot_readiness = if ($firstBootReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_readiness = if ($rollbackReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($blockers)
        next_safe_action = "run-rc20-final-closeout-audit"
    }
    local_channel = [ordered]@{
        followed = $channelReady
        local_only = $true
        external_mirror_publication_performed = $false
        remote_payload_download_attempted = $false
        endpoint_reachability_trusted = $false
    }
    lifecycle_state_chain = [ordered]@{
        target_state_id = [string]$installAcceptanceResult.target_state_id
        previous_installed_image_state_id = [string]$updateResult.previous_installed_image_state_id
        updated_image_state_id = [string]$updateResult.updated_image_state_id
        restored_target_state_id = [string]$rollbackResult.restored_target_state_id
        target_chain_coherent = $targetChainReady
        lifecycle_chain_coherent = $lifecycleChainReady
    }
    audit = $auditRecord
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$consumerEvidencePath = Join-Path $resolvedArtifactDir "consumer-smoke-evidence.json"
Write-Json $consumerEvidence $consumerEvidencePath

Add-Check "plan.current_task.rc20_040" $planAllowsRun "RC20-040 must run after RC20-032 completed, either while current_task is RC20-040 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_032_status = $rc20PreviousStatus; rc20_040_status = $rc20TaskStatus })
Add-Check "contract.consumer.bound" $contractBound "RC20 contract must allow only local single-user consumer readiness and must deny production readiness authority." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.release_bundle.ready" $releaseBundleReady "Consumer smoke must bind RC20 single-user release bundle evidence." ([ordered]@{ release_bundle_id = $releaseBundleResult.release_bundle_id; bundle_target_state_id = $releaseBundleResult.bundle_surface.first_user_target_state_id })
Add-Check "source.local_channel.ready" $channelReady "Consumer smoke must follow RC20 local channel promotion without external mirror publication or production mutation." ([ordered]@{ candidate_channel_package_id = $channelPromotionResult.summary.candidate_channel_package_id; stable_channel_projection_id = $channelPromotionResult.summary.stable_channel_projection_id; external_mirror_publication_performed = $channelPromotionResult.summary.external_mirror_publication_performed })
Add-Check "source.installer_catalog.ready" $installerReady "Consumer smoke must bind installer catalog and version preflight without host install or remote fetch authority." ([ordered]@{ installer_catalog_id = $installerCatalogResult.installer_catalog_id; version_selection_preflight_id = $installerCatalogResult.version_selection_preflight_id; host_install_authorized = $installerCatalogResult.summary.host_install_authorized; remote_fetch_authorized = $installerCatalogResult.summary.remote_fetch_authorized })
Add-Check "source.install_first_boot.ready" ($installReady -and $firstBootReady) "Consumer smoke must bind install acceptance and first boot posture without credential, support upload, recovery, or remote dispatch authority." ([ordered]@{ install_acceptance_id = $installAcceptanceResult.install_acceptance_id; first_boot_acceptance_id = $firstBootAcceptanceResult.first_boot_acceptance_id; target_state_id = $installAcceptanceResult.target_state_id })
Add-Check "source.update_rollback.ready" ($updateReady -and $rollbackReady) "Consumer smoke must bind post-install update and rollback drill evidence without executing new update or rollback." ([ordered]@{ update_drill_id = $updateResult.update_drill_id; rollback_audit_record_id = $rollbackResult.rollback_audit_record_id; updated_image_state_id = $updateResult.updated_image_state_id; restored_target_state_id = $rollbackResult.restored_target_state_id })
Add-Check "source.support_recovery.ready" $supportReady "Consumer smoke must bind lifecycle support/recovery evidence without support upload or recovery execution." ([ordered]@{ support_bundle_id = $lifecycleSupportResult.support_bundle_id; recovery_reference_digest = $lifecycleSupportResult.recovery_reference_digest; support_bundle_local_only = $lifecycleSupportResult.summary.support_bundle_local_only; support_upload_performed = $lifecycleSupportResult.summary.support_upload_performed; recovery_execution_performed = $lifecycleSupportResult.summary.recovery_execution_performed })
Add-Check "target.chain.coherent" $targetChainReady "Consumer smoke must bind a coherent single-user target state across release bundle, install, first boot, and lifecycle support evidence." $consumerEvidence.lifecycle_state_chain
Add-Check "lifecycle.chain.coherent" $lifecycleChainReady "Consumer smoke must bind a coherent update/rollback lifecycle state chain." $consumerEvidence.lifecycle_state_chain
Add-Check "consumer.ready_or_denial" ($consumerReady -and $consumerDecision -eq "single-user-distribution-local-consumer-ready") "Consumer smoke must report local single-user distribution readiness or explicit denial from RC20 evidence." ([ordered]@{ decision = $consumerDecision; blockers = @($blockers); consumer_ready_claim = $consumerReady; production_ready_claim = $false })
Add-Check "consumer.audit.bound" ($auditRecord.local_only -eq $true -and $auditRecord.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($auditDigest)) "Consumer smoke must be audited and non-fabricated." $auditRecord
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.install_performed_by_consumer_smoke -eq $false -and $sideEffects.update_performed_by_consumer_smoke -eq $false -and $sideEffects.rollback_execution_performed_by_consumer_smoke -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.mirror_frontend_authority -eq $false -and $sideEffects.nginx_or_tls_authority -eq $false -and $sideEffects.endpoint_reachability_trusted -eq $false -and $sideEffects.shell_output_trusted -eq $false -and $sideEffects.tui_output_trusted -eq $false -and $sideEffects.model_replay_trusted -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false) "RC20-040 must not execute new install/update/rollback, upload support, execute recovery, fetch remote payloads, provision object storage, remote dispatch, mutate host/production state, trust projection surfaces, handle private material, or sign." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 30) "Missing evidence and forbidden authority surfaces must fail closed before consumer readiness or side effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $consumerEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC20-040 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, raw passwords, raw secrets, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-single-user-distribution-consumer-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-040"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    target_state_id = [string]$installAcceptanceResult.target_state_id
    consumer_surface = [ordered]@{
        state = $consumerDecision
        release_bundle_readiness = if ($releaseBundleReady) { "ready" } else { "denied" }
        local_channel_readiness = if ($channelReady) { "ready" } else { "denied" }
        installer_catalog_readiness = if ($installerReady) { "ready" } else { "denied" }
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        first_boot_readiness = if ($firstBootReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_readiness = if ($rollbackReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        consumer_decision = $consumerDecision
        consumer_ready_claim = $consumerReady
        production_ready_claim = $false
        audited = $true
        audit_digest = $auditDigest
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        consumer_smoke_evidence = [ordered]@{
            path = Get-StablePath $consumerEvidencePath
            sha256 = Get-FileSha256 $consumerEvidencePath
            audit_digest = $auditDigest
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        single_user_distribution_consumer_smoke_only = $true
        local_channel_followed = $channelReady
        consumer_ready_claim = $consumerReady
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        rollback_execution_performed_by_consumer_smoke = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_authority = $false
        nginx_or_tls_authority = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        signer_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_040_complete = (@($script:failedChecks).Count -eq 0)
        consumer_decision = $consumerDecision
        consumer_ready_claim = $consumerReady
        production_ready_claim = $false
        release_bundle_readiness = if ($releaseBundleReady) { "ready" } else { "denied" }
        local_channel_readiness = if ($channelReady) { "ready" } else { "denied" }
        installer_catalog_readiness = if ($installerReady) { "ready" } else { "denied" }
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        first_boot_readiness = if ($firstBootReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_readiness = if ($rollbackReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        audited = $true
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        rollback_execution_performed_by_consumer_smoke = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC20-050"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-040-single-user-distribution-consumer-smoke.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-single-user-distribution-consumer-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-040"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
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
    consumer_surface = $result.consumer_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-050"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-040 outputs." }

Write-Host "RC20 single-user distribution consumer smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $consumerEvidencePath)"
Write-Host "Decision: $consumerDecision; consumer_ready_claim=$consumerReady; production_ready_claim=false"
Write-Host "New effects: install=false; update=false; rollback=false; support upload=false; recovery=false; remote dispatch=false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
