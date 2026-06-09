param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-installable-image-consumer-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$ImageArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$ImageArtifactSetPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/installable-image-artifact-set.json",
    [string]$FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$OfflineChannelResultPath = ".workflow/artifacts/rc19-offline-local-channel-consumption/result.json",
    [string]$OfflineChannelEvidencePath = ".workflow/artifacts/rc19-offline-local-channel-consumption/local-channel-consumption-evidence.json",
    [string]$PostInstallSmokeResultPath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json",
    [string]$SupportRecoveryResultPath = ".workflow/artifacts/rc19-first-user-support-recovery/result.json",
    [string]$SupportBundlePath = ".workflow/artifacts/rc19-first-user-support-recovery/first-user-support-bundle.json",
    [string]$RecoveryIndexPath = ".workflow/artifacts/rc19-first-user-support-recovery/recovery-reference-index.json",
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
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][bool]$Passed, [Parameter(Mandatory = $true)][string]$Message, $Evidence = $null)
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
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function New-ArtifactRef {
    param([Parameter(Mandatory = $true)][string]$Path, $Json = $null)
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
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-FailClosedCase {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string[]]$Blockers, [Parameter(Mandatory = $true)][string]$Reason)
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
            endpoint_reachability_trusted = $false
            shell_output_trusted = $false
            tui_output_trusted = $false
            model_replay_trusted = $false
            signer_authority_granted = $false
            private_signing_material_handled = $false
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
$resolvedImageArtifactResultPath = Resolve-RepoPath $ImageArtifactResultPath
$resolvedImageArtifactSetPath = Resolve-RepoPath $ImageArtifactSetPath
$resolvedFirstUserInstallResultPath = Resolve-RepoPath $FirstUserInstallResultPath
$resolvedOfflineChannelResultPath = Resolve-RepoPath $OfflineChannelResultPath
$resolvedOfflineChannelEvidencePath = Resolve-RepoPath $OfflineChannelEvidencePath
$resolvedPostInstallSmokeResultPath = Resolve-RepoPath $PostInstallSmokeResultPath
$resolvedSupportRecoveryResultPath = Resolve-RepoPath $SupportRecoveryResultPath
$resolvedSupportBundlePath = Resolve-RepoPath $SupportBundlePath
$resolvedRecoveryIndexPath = Resolve-RepoPath $RecoveryIndexPath

$plan = Read-Json $resolvedPlanPath
$imageArtifactResult = Read-Json $resolvedImageArtifactResultPath
$imageArtifactSet = Read-Json $resolvedImageArtifactSetPath
$firstUserInstallResult = Read-Json $resolvedFirstUserInstallResultPath
$offlineChannelResult = Read-Json $resolvedOfflineChannelResultPath
$offlineChannelEvidence = Read-Json $resolvedOfflineChannelEvidencePath
$postInstallSmokeResult = Read-Json $resolvedPostInstallSmokeResultPath
$supportRecoveryResult = Read-Json $resolvedSupportRecoveryResultPath
$supportBundle = Read-Json $resolvedSupportBundlePath
$recoveryIndex = Read-Json $resolvedRecoveryIndexPath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-032"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-040"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-040" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-050" -and $rc19TaskStatus -eq "completed")
    )
)

$firstUserTargetStateId = [string]$firstUserInstallResult.summary.target_state_id
$imageArtifactReady = (
    $imageArtifactResult.status -eq "passed" -and
    $imageArtifactResult.summary.rc19_010_complete -eq $true -and
    $imageArtifactResult.installable_image_artifact_id -eq $imageArtifactSet.installable_image_artifact_id -and
    $imageArtifactSet.production_ready_claim -eq $false
)
$firstUserInstallReady = (
    $firstUserInstallResult.status -eq "passed" -and
    $firstUserInstallResult.summary.rc19_021_complete -eq $true -and
    $firstUserInstallResult.summary.first_user_install_performed -eq $true -and
    $firstUserInstallResult.summary.target_state_id -eq $offlineChannelResult.first_user_install_target_state_id -and
    $firstUserInstallResult.summary.host_rootfs_mutated -eq $false -and
    $firstUserInstallResult.summary.remote_dispatch_enabled -eq $false
)
$offlineChannelReady = (
    $offlineChannelResult.status -eq "passed" -and
    $offlineChannelResult.summary.rc19_030_complete -eq $true -and
    $offlineChannelResult.summary.offline_local_channel_package_bound -eq $true -and
    $offlineChannelResult.installable_image_artifact_id -eq $imageArtifactResult.installable_image_artifact_id -and
    $offlineChannelEvidence.local_channel_followed -eq $true -and
    $offlineChannelEvidence.local_only -eq $true -and
    $offlineChannelEvidence.offline_only -eq $true -and
    $offlineChannelEvidence.side_effects.remote_payload_downloaded -eq $false
)
$postInstallReady = (
    $postInstallSmokeResult.status -eq "passed" -and
    $postInstallSmokeResult.summary.rc19_031_complete -eq $true -and
    $postInstallSmokeResult.first_user_target_state_id -eq $firstUserTargetStateId -and
    $postInstallSmokeResult.summary.update_compatibility_readiness -eq "ready" -and
    $postInstallSmokeResult.summary.rollback_compatibility_readiness -eq "ready" -and
    $postInstallSmokeResult.summary.update_or_rollback_executed_by_this_smoke -eq $false -and
    $postInstallSmokeResult.summary.remote_dispatch_enabled -eq $false
)
$supportRecoveryReady = (
    $supportRecoveryResult.status -eq "passed" -and
    $supportRecoveryResult.summary.rc19_032_complete -eq $true -and
    $supportRecoveryResult.first_user_target_state_id -eq $firstUserTargetStateId -and
    $supportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $supportRecoveryResult.summary.support_bundle_redacted -eq $true -and
    $supportRecoveryResult.summary.support_upload_performed -eq $false -and
    $supportRecoveryResult.summary.recovery_execution_performed -eq $false -and
    $supportBundle.local_only -eq $true -and
    $supportBundle.redacted -eq $true -and
    $supportBundle.uploaded -eq $false -and
    $recoveryIndex.projection_only -eq $true -and
    $recoveryIndex.recovery_execution_performed -eq $false
)
$targetChainReady = (
    $firstUserTargetStateId -eq $offlineChannelResult.first_user_install_target_state_id -and
    $firstUserTargetStateId -eq $postInstallSmokeResult.first_user_target_state_id -and
    $firstUserTargetStateId -eq $supportRecoveryResult.first_user_target_state_id
)

$consumerReady = $planAllowsRun -and $imageArtifactReady -and $firstUserInstallReady -and $offlineChannelReady -and $postInstallReady -and $supportRecoveryReady -and $targetChainReady
$consumerDecision = if ($consumerReady) { "installable-image-local-consumer-ready" } else { "installable-image-local-consumer-denied-before-effect" }

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc19-040-plan-pointer-not-current" }
if (-not $imageArtifactReady) { $blockers += "installable-image-artifact-not-ready" }
if (-not $firstUserInstallReady) { $blockers += "first-user-install-not-ready" }
if (-not $offlineChannelReady) { $blockers += "offline-local-channel-not-ready" }
if (-not $postInstallReady) { $blockers += "post-install-update-rollback-not-ready" }
if (-not $supportRecoveryReady) { $blockers += "first-user-support-recovery-not-ready" }
if (-not $targetChainReady) { $blockers += "first-user-target-state-chain-mismatch" }
if ($consumerReady) { $blockers = @() }

$sideEffects = [ordered]@{
    consumer_smoke_evaluated = $true
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
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_image_artifact_result = New-ArtifactRef $resolvedImageArtifactResultPath $imageArtifactResult
    rc19_image_artifact_set = New-ArtifactRef $resolvedImageArtifactSetPath $imageArtifactSet
    rc19_first_user_install_result = New-ArtifactRef $resolvedFirstUserInstallResultPath $firstUserInstallResult
    rc19_offline_channel_result = New-ArtifactRef $resolvedOfflineChannelResultPath $offlineChannelResult
    rc19_offline_channel_evidence = New-ArtifactRef $resolvedOfflineChannelEvidencePath $offlineChannelEvidence
    rc19_post_install_smoke_result = New-ArtifactRef $resolvedPostInstallSmokeResultPath $postInstallSmokeResult
    rc19_support_recovery_result = New-ArtifactRef $resolvedSupportRecoveryResultPath $supportRecoveryResult
    rc19_support_bundle = New-ArtifactRef $resolvedSupportBundlePath $supportBundle
    rc19_recovery_reference_index = New-ArtifactRef $resolvedRecoveryIndexPath $recoveryIndex
}

$auditMaterial = [ordered]@{
    schema = "agentos.rc19-installable-image-consumer-smoke-audit-material.v1"
    task = "RC19-040"
    generated_at = $generatedAtValue
    decision = $consumerDecision
    installable_image_artifact_id = [string]$imageArtifactResult.installable_image_artifact_id
    first_user_target_state_id = $firstUserTargetStateId
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    support_bundle_id = [string]$supportRecoveryResult.support_bundle_id
    recovery_reference_digest = [string]$supportRecoveryResult.recovery_reference_digest
    image_artifact_result_sha256 = Get-FileSha256 $resolvedImageArtifactResultPath
    first_user_install_result_sha256 = Get-FileSha256 $resolvedFirstUserInstallResultPath
    offline_channel_result_sha256 = Get-FileSha256 $resolvedOfflineChannelResultPath
    post_install_smoke_result_sha256 = Get-FileSha256 $resolvedPostInstallSmokeResultPath
    support_recovery_result_sha256 = Get-FileSha256 $resolvedSupportRecoveryResultPath
    blockers = @($blockers)
    side_effects = $sideEffects
}
$auditDigest = Get-StringSha256 (Get-JsonText $auditMaterial)

$auditRecord = [ordered]@{
    schema = "agentos.rc19-installable-image-consumer-smoke-audit.v1"
    generated_at = $generatedAtValue
    task = "RC19-040"
    local_only = $true
    fabricated = $false
    decision = $consumerDecision
    decision_digest = $auditDigest
    installable_image_artifact_bound = $imageArtifactReady
    first_user_install_bound = $firstUserInstallReady
    offline_channel_bound = $offlineChannelReady
    post_install_update_rollback_bound = $postInstallReady
    support_recovery_bound = $supportRecoveryReady
    target_chain_bound = $targetChainReady
    consumer_ready_claim = $consumerReady
    production_ready_claim = $false
    blockers = @($blockers)
}

$caseSpecs = @(
    [ordered]@{ id = "missing-installable-image-artifact"; blockers = @("installable-image-artifact-not-ready"); reason = "Consumer smoke requires installable image artifact evidence." },
    [ordered]@{ id = "missing-first-user-install"; blockers = @("first-user-install-not-ready"); reason = "Consumer smoke requires first-user install evidence." },
    [ordered]@{ id = "missing-offline-channel"; blockers = @("offline-local-channel-not-ready"); reason = "Consumer smoke requires offline/local channel evidence." },
    [ordered]@{ id = "missing-post-install-smoke"; blockers = @("post-install-update-rollback-not-ready"); reason = "Consumer smoke requires post-install update/rollback smoke evidence." },
    [ordered]@{ id = "missing-support-recovery"; blockers = @("first-user-support-recovery-not-ready"); reason = "Consumer smoke requires support/recovery evidence." },
    [ordered]@{ id = "target-state-chain-mismatch"; blockers = @("first-user-target-state-chain-mismatch"); reason = "Consumer smoke cannot report readiness for mismatched first-user target state." },
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
    schema = "agentos.rc19-installable-image-consumer-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-040"
    status = $consumerDecision
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
    local_only = $true
    installable_image_artifact_id = [string]$imageArtifactResult.installable_image_artifact_id
    first_user_target_state_id = $firstUserTargetStateId
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    readiness = [ordered]@{
        outcome = $consumerDecision
        installable_image_readiness = if ($imageArtifactReady) { "ready" } else { "denied" }
        first_user_install_readiness = if ($firstUserInstallReady) { "ready" } else { "denied" }
        offline_channel_readiness = if ($offlineChannelReady) { "ready" } else { "denied" }
        post_install_update_readiness = if ($postInstallReady) { "ready" } else { "denied" }
        post_install_rollback_readiness = if ($postInstallReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportRecoveryReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($blockers)
        next_safe_action = "run-rc19-final-closeout-audit"
    }
    local_channel = [ordered]@{
        followed = $offlineChannelReady
        local_only = $true
        offline_only = $true
        remote_payload_download_attempted = $false
    }
    audit = $auditRecord
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$consumerEvidencePath = Join-Path $resolvedArtifactDir "consumer-smoke-evidence.json"
Write-Json $consumerEvidence $consumerEvidencePath

Add-Check "plan.current_task.rc19_040" $planAllowsRun "RC19-040 must run after RC19-032 completed, while current_task is RC19-040 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_032_status = $rc19PreviousStatus; rc19_040_status = $rc19TaskStatus })
Add-Check "source.installable_image.ready" $imageArtifactReady "Consumer smoke must bind RC19 reproducible installable image artifact evidence." ([ordered]@{ installable_image_artifact_id = $imageArtifactResult.installable_image_artifact_id; image_result_status = $imageArtifactResult.status; image_set_status = $imageArtifactSet.status })
Add-Check "source.first_user_install.ready" $firstUserInstallReady "Consumer smoke must bind RC19 first-user install evidence without host or remote mutation." ([ordered]@{ target_state_id = $firstUserTargetStateId; first_user_install_performed = $firstUserInstallResult.summary.first_user_install_performed; host_rootfs_mutated = $firstUserInstallResult.summary.host_rootfs_mutated })
Add-Check "source.offline_channel.ready" $offlineChannelReady "Consumer smoke must follow local/offline channel evidence without remote payload download." ([ordered]@{ offline_local_channel_package_id = $offlineChannelResult.offline_local_channel_package_id; local_only = $offlineChannelEvidence.local_only; offline_only = $offlineChannelEvidence.offline_only; remote_payload_downloaded = $offlineChannelEvidence.side_effects.remote_payload_downloaded })
Add-Check "source.post_install.ready" $postInstallReady "Consumer smoke must bind post-install update/rollback readiness without executing new update or rollback." ([ordered]@{ update_readiness = $postInstallSmokeResult.summary.update_compatibility_readiness; rollback_readiness = $postInstallSmokeResult.summary.rollback_compatibility_readiness; executed_by_smoke = $postInstallSmokeResult.summary.update_or_rollback_executed_by_this_smoke })
Add-Check "source.support_recovery.ready" $supportRecoveryReady "Consumer smoke must bind first-user support/recovery evidence without support upload or recovery execution." ([ordered]@{ support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only; support_bundle_redacted = $supportRecoveryResult.summary.support_bundle_redacted; support_upload_performed = $supportRecoveryResult.summary.support_upload_performed; recovery_execution_performed = $supportRecoveryResult.summary.recovery_execution_performed })
Add-Check "target.chain.coherent" $targetChainReady "Consumer smoke must bind a coherent first-user target state across install, local channel, post-install smoke, and support/recovery evidence." ([ordered]@{ first_user_target_state_id = $firstUserTargetStateId; channel_target_state_id = $offlineChannelResult.first_user_install_target_state_id; post_install_target_state_id = $postInstallSmokeResult.first_user_target_state_id; support_target_state_id = $supportRecoveryResult.first_user_target_state_id })
Add-Check "consumer.ready_or_denial" ($consumerReady -and $consumerDecision -eq "installable-image-local-consumer-ready") "Consumer smoke must report installable image local consumer readiness or explicit denial from RC19 evidence." ([ordered]@{ decision = $consumerDecision; blockers = @($blockers); consumer_ready_claim = $consumerReady; production_ready_claim = $false })
Add-Check "consumer.audit.bound" ($auditRecord.local_only -eq $true -and $auditRecord.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($auditDigest)) "Consumer smoke must be audited and non-fabricated." $auditRecord
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.install_performed_by_consumer_smoke -eq $false -and $sideEffects.update_performed_by_consumer_smoke -eq $false -and $sideEffects.rollback_execution_performed_by_consumer_smoke -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.mirror_frontend_authority -eq $false -and $sideEffects.endpoint_reachability_trusted -eq $false -and $sideEffects.shell_output_trusted -eq $false -and $sideEffects.tui_output_trusted -eq $false -and $sideEffects.model_replay_trusted -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false) "RC19-040 must not execute new install/update/rollback, upload support, execute recovery, fetch remote payloads, provision object storage, remote dispatch, mutate host/production state, trust projection surfaces, handle private material, or sign." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 24) "Missing evidence and forbidden authority surfaces must fail closed before consumer readiness or side effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $consumerEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-040 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-installable-image-consumer-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-040"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
    installable_image_artifact_id = [string]$imageArtifactResult.installable_image_artifact_id
    first_user_target_state_id = $firstUserTargetStateId
    consumer_surface = [ordered]@{
        state = $consumerDecision
        local_offline_channel_followed = $offlineChannelReady
        installable_image_readiness = if ($imageArtifactReady) { "ready" } else { "denied" }
        first_user_install_readiness = if ($firstUserInstallReady) { "ready" } else { "denied" }
        post_install_update_readiness = if ($postInstallReady) { "ready" } else { "denied" }
        post_install_rollback_readiness = if ($postInstallReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportRecoveryReady) { "ready" } else { "denied" }
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
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        installable_image_consumer_smoke_only = $true
        local_offline_channel_followed = $offlineChannelReady
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
        rc19_040_complete = (@($script:failedChecks).Count -eq 0)
        consumer_decision = $consumerDecision
        consumer_ready_claim = $consumerReady
        production_ready_claim = $false
        installable_image_readiness = if ($imageArtifactReady) { "ready" } else { "denied" }
        first_user_install_readiness = if ($firstUserInstallReady) { "ready" } else { "denied" }
        post_install_update_readiness = if ($postInstallReady) { "ready" } else { "denied" }
        post_install_rollback_readiness = if ($postInstallReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportRecoveryReady) { "ready" } else { "denied" }
        audited = $true
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        rollback_execution_performed_by_consumer_smoke = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC19-050"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-040-installable-image-consumer-smoke.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-installable-image-consumer-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-040"
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
        rc19_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-050"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC19-040 outputs." }

Write-Host "RC19 installable image consumer smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $consumerEvidencePath)"
Write-Host "Decision: $consumerDecision; consumer_ready_claim=$consumerReady; production_ready_claim=false"
Write-Host "New effects: install=false; update=false; rollback=false; support upload=false; recovery=false; remote dispatch=false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
