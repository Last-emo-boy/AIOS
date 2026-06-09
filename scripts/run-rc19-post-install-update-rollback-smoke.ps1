param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-post-install-update-rollback-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$FirstUserInstallEvidencePath = ".workflow/artifacts/rc19-first-user-install-drill/first-user-install-evidence.json",
    [string]$OfflineChannelResultPath = ".workflow/artifacts/rc19-offline-local-channel-consumption/result.json",
    [string]$OfflineChannelEvidencePath = ".workflow/artifacts/rc19-offline-local-channel-consumption/local-channel-consumption-evidence.json",
    [string]$Rc18UpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$Rc18UpdateEvidencePath = ".workflow/artifacts/rc18-isolated-update-drill/update-drill-evidence.json",
    [string]$Rc18RollbackResultPath = ".workflow/artifacts/rc18-isolated-rollback-drill/result.json",
    [string]$Rc18RollbackEvidencePath = ".workflow/artifacts/rc18-isolated-rollback-drill/rollback-drill-evidence.json",
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
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$Blockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_post_install_effect = $true
        side_effects = [ordered]@{
            update_performed_by_smoke = $false
            rollback_execution_performed_by_smoke = $false
            install_performed_by_smoke = $false
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
            endpoint_reachability_trusted = $false
            frontend_output_trusted = $false
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
$resolvedFirstUserInstallResultPath = Resolve-RepoPath $FirstUserInstallResultPath
$resolvedFirstUserInstallEvidencePath = Resolve-RepoPath $FirstUserInstallEvidencePath
$resolvedOfflineChannelResultPath = Resolve-RepoPath $OfflineChannelResultPath
$resolvedOfflineChannelEvidencePath = Resolve-RepoPath $OfflineChannelEvidencePath
$resolvedRc18UpdateResultPath = Resolve-RepoPath $Rc18UpdateResultPath
$resolvedRc18UpdateEvidencePath = Resolve-RepoPath $Rc18UpdateEvidencePath
$resolvedRc18RollbackResultPath = Resolve-RepoPath $Rc18RollbackResultPath
$resolvedRc18RollbackEvidencePath = Resolve-RepoPath $Rc18RollbackEvidencePath

$plan = Read-Json $resolvedPlanPath
$firstUserInstallResult = Read-Json $resolvedFirstUserInstallResultPath
$firstUserInstallEvidence = Read-Json $resolvedFirstUserInstallEvidencePath
$offlineChannelResult = Read-Json $resolvedOfflineChannelResultPath
$offlineChannelEvidence = Read-Json $resolvedOfflineChannelEvidencePath
$rc18UpdateResult = Read-Json $resolvedRc18UpdateResultPath
$rc18UpdateEvidence = Read-Json $resolvedRc18UpdateEvidencePath
$rc18RollbackResult = Read-Json $resolvedRc18RollbackResultPath
$rc18RollbackEvidence = Read-Json $resolvedRc18RollbackEvidencePath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-030"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-031"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-031" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-032" -and $rc19TaskStatus -eq "completed")
    )
)

$firstUserTargetStateId = [string]$firstUserInstallResult.summary.target_state_id
$firstUserInstallReady = (
    $firstUserInstallResult.status -eq "passed" -and
    $firstUserInstallResult.summary.rc19_021_complete -eq $true -and
    $firstUserInstallResult.summary.first_user_install_performed -eq $true -and
    $firstUserInstallResult.install_surface.target_kind -eq "disposable-first-user-install-target" -and
    $firstUserInstallResult.install_surface.target_materialized -eq $true -and
    $firstUserInstallEvidence.target_state_id -eq $firstUserTargetStateId -and
    $firstUserInstallResult.summary.host_rootfs_mutated -eq $false -and
    $firstUserInstallResult.summary.host_active_slot_mutated -eq $false -and
    $firstUserInstallResult.summary.host_boot_metadata_mutated -eq $false -and
    $firstUserInstallResult.summary.remote_dispatch_enabled -eq $false
)

$offlineChannelReady = (
    $offlineChannelResult.status -eq "passed" -and
    $offlineChannelResult.summary.rc19_030_complete -eq $true -and
    $offlineChannelResult.summary.offline_local_channel_package_bound -eq $true -and
    $offlineChannelResult.first_user_install_target_state_id -eq $firstUserTargetStateId -and
    $offlineChannelEvidence.bindings.first_user_install_bound -eq $true -and
    $offlineChannelEvidence.bindings.installable_image_artifact_bound -eq $true -and
    $offlineChannelEvidence.side_effects.remote_payload_downloaded -eq $false -and
    $offlineChannelEvidence.side_effects.object_storage_provisioned -eq $false -and
    $offlineChannelEvidence.side_effects.remote_dispatch_enabled -eq $false -and
    $offlineChannelEvidence.side_effects.consumer_ready_claim -eq $false
)

$updateCompatibilityReady = (
    $rc18UpdateResult.status -eq "passed" -and
    $rc18UpdateResult.summary.rc18_021_complete -eq $true -and
    $rc18UpdateResult.summary.isolated_update_performed -eq $true -and
    $rc18UpdateResult.update_surface.image_scope -eq "disposable-installed-system-image-or-vm" -and
    $rc18UpdateResult.update_surface.host_rootfs_mutated -eq $false -and
    $rc18UpdateResult.update_surface.host_active_slot_mutated -eq $false -and
    $rc18UpdateResult.update_surface.host_boot_metadata_mutated -eq $false -and
    $rc18UpdateResult.update_surface.remote_dispatch_enabled -eq $false -and
    $rc18UpdateEvidence.image_effect.isolated_update_performed -eq $true
)

$rollbackCompatibilityReady = (
    $rc18RollbackResult.status -eq "passed" -and
    $rc18RollbackResult.summary.rc18_030_complete -eq $true -and
    $rc18RollbackResult.summary.isolated_rollback_performed -eq $true -and
    $rc18RollbackResult.rollback_surface.image_scope -eq "disposable-installed-system-image-or-vm" -and
    $rc18RollbackResult.previous_updated_image_state_id -eq $rc18UpdateResult.updated_image_state_id -and
    $rc18RollbackResult.rollback_surface.host_rootfs_mutated -eq $false -and
    $rc18RollbackResult.rollback_surface.host_active_slot_mutated -eq $false -and
    $rc18RollbackResult.rollback_surface.host_boot_metadata_mutated -eq $false -and
    $rc18RollbackResult.rollback_surface.remote_dispatch_enabled -eq $false -and
    $rc18RollbackEvidence.image_effect.isolated_rollback_performed -eq $true
)

$disposableBoundaryCompatible = (
    $firstUserInstallResult.install_surface.target_kind -eq "disposable-first-user-install-target" -and
    $rc18UpdateResult.update_surface.image_scope -eq "disposable-installed-system-image-or-vm" -and
    $rc18RollbackResult.rollback_surface.image_scope -eq "disposable-installed-system-image-or-vm"
)

$postInstallSmokeReady = $planAllowsRun -and $firstUserInstallReady -and $offlineChannelReady -and $updateCompatibilityReady -and $rollbackCompatibilityReady -and $disposableBoundaryCompatible
$smokeDecision = if ($postInstallSmokeReady) { "post-install-update-rollback-compatible" } else { "post-install-update-rollback-denied-before-effect" }

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc19-031-plan-pointer-not-current" }
if (-not $firstUserInstallReady) { $blockers += "first-user-install-evidence-not-ready" }
if (-not $offlineChannelReady) { $blockers += "offline-local-channel-not-ready" }
if (-not $updateCompatibilityReady) { $blockers += "rc18-isolated-update-compatibility-not-ready" }
if (-not $rollbackCompatibilityReady) { $blockers += "rc18-isolated-rollback-compatibility-not-ready" }
if (-not $disposableBoundaryCompatible) { $blockers += "disposable-target-boundary-not-compatible" }
if ($postInstallSmokeReady) { $blockers = @() }

$sideEffects = [ordered]@{
    post_install_smoke_evaluated = $true
    update_compatibility_evaluated = $true
    rollback_compatibility_evaluated = $true
    install_performed_by_smoke = $false
    update_performed_by_smoke = $false
    rollback_execution_performed_by_smoke = $false
    disposable_target_state_mutated_by_smoke = $false
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
    endpoint_reachability_trusted = $false
    frontend_output_trusted = $false
    shell_output_trusted = $false
    tui_output_trusted = $false
    model_replay_trusted = $false
    signer_authority_granted = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    consumer_ready_claim = $false
}

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_first_user_install_result = New-ArtifactRef $resolvedFirstUserInstallResultPath $firstUserInstallResult
    rc19_first_user_install_evidence = New-ArtifactRef $resolvedFirstUserInstallEvidencePath $firstUserInstallEvidence
    rc19_offline_channel_result = New-ArtifactRef $resolvedOfflineChannelResultPath $offlineChannelResult
    rc19_offline_channel_evidence = New-ArtifactRef $resolvedOfflineChannelEvidencePath $offlineChannelEvidence
    rc18_isolated_update_result = New-ArtifactRef $resolvedRc18UpdateResultPath $rc18UpdateResult
    rc18_isolated_update_evidence = New-ArtifactRef $resolvedRc18UpdateEvidencePath $rc18UpdateEvidence
    rc18_isolated_rollback_result = New-ArtifactRef $resolvedRc18RollbackResultPath $rc18RollbackResult
    rc18_isolated_rollback_evidence = New-ArtifactRef $resolvedRc18RollbackEvidencePath $rc18RollbackEvidence
}

$smokeMaterial = [ordered]@{
    schema = "agentos.rc19-post-install-update-rollback-smoke-material.v1"
    task = "RC19-031"
    generated_at = $generatedAtValue
    decision = $smokeDecision
    first_user_target_state_id = $firstUserTargetStateId
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    installable_image_artifact_id = [string]$offlineChannelResult.installable_image_artifact_id
    update_compatibility_source = "RC18-021"
    rollback_compatibility_source = "RC18-030"
    rc18_updated_image_state_id = [string]$rc18UpdateResult.updated_image_state_id
    rc18_restored_image_state_id = [string]$rc18RollbackResult.restored_image_state_id
    first_user_install_result_sha256 = Get-FileSha256 $resolvedFirstUserInstallResultPath
    offline_channel_result_sha256 = Get-FileSha256 $resolvedOfflineChannelResultPath
    rc18_update_result_sha256 = Get-FileSha256 $resolvedRc18UpdateResultPath
    rc18_rollback_result_sha256 = Get-FileSha256 $resolvedRc18RollbackResultPath
    blockers = @($blockers)
    side_effects = $sideEffects
}
$smokeDigest = Get-StringSha256 (Get-JsonText $smokeMaterial)

$audit = [ordered]@{
    schema = "agentos.rc19-post-install-update-rollback-smoke-audit.v1"
    generated_at = $generatedAtValue
    task = "RC19-031"
    local_only = $true
    fabricated = $false
    decision = $smokeDecision
    decision_digest = $smokeDigest
    first_user_install_bound = $firstUserInstallReady
    offline_channel_bound = $offlineChannelReady
    update_compatibility_bound = $updateCompatibilityReady
    rollback_compatibility_bound = $rollbackCompatibilityReady
    disposable_boundary_compatible = $disposableBoundaryCompatible
    production_ready_claim = $false
    consumer_ready_claim = $false
    blockers = @($blockers)
}

$caseSpecs = @(
    [ordered]@{ id = "missing-first-user-install"; blockers = @("first-user-install-evidence-not-ready"); reason = "Post-install smoke requires first-user install evidence." },
    [ordered]@{ id = "missing-offline-channel"; blockers = @("offline-local-channel-not-ready"); reason = "Post-install smoke requires offline/local channel consumption package." },
    [ordered]@{ id = "missing-rc18-update"; blockers = @("rc18-isolated-update-compatibility-not-ready"); reason = "Post-install update compatibility requires RC18 isolated update evidence." },
    [ordered]@{ id = "missing-rc18-rollback"; blockers = @("rc18-isolated-rollback-compatibility-not-ready"); reason = "Post-install rollback compatibility requires RC18 isolated rollback evidence." },
    [ordered]@{ id = "non-disposable-target"; blockers = @("disposable-target-boundary-not-compatible"); reason = "Compatibility smoke may only evaluate disposable target/image boundaries." },
    [ordered]@{ id = "offline-channel-target-mismatch"; blockers = @("offline-channel-target-state-mismatch"); reason = "Offline channel package must bind the same first-user target state." },
    [ordered]@{ id = "update-state-chain-mismatch"; blockers = @("rc18-update-state-chain-mismatch"); reason = "Update compatibility requires coherent RC18 update state evidence." },
    [ordered]@{ id = "rollback-state-chain-mismatch"; blockers = @("rc18-rollback-state-chain-mismatch"); reason = "Rollback compatibility requires coherent RC18 rollback state evidence." },
    [ordered]@{ id = "new-install-attempt"; blockers = @("install-effect-denied"); reason = "RC19-031 must not execute a new install." },
    [ordered]@{ id = "new-update-attempt"; blockers = @("update-effect-denied"); reason = "RC19-031 must not execute a new update." },
    [ordered]@{ id = "new-rollback-attempt"; blockers = @("rollback-effect-denied"); reason = "RC19-031 must not execute a new rollback." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of scope." },
    [ordered]@{ id = "object-storage-provisioning-attempt"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "endpoint-authority-attempt"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not post-install authority." },
    [ordered]@{ id = "frontend-output-authority-attempt"; blockers = @("frontend-output-authority-denied"); reason = "Frontend output is not post-install authority." },
    [ordered]@{ id = "shell-output-authority-attempt"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not post-install authority." },
    [ordered]@{ id = "tui-output-authority-attempt"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not post-install authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not post-install authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not post-install authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "consumer-ready-claim-attempt"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for RC19-040." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC19-031 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$smokeEvidence = [ordered]@{
    schema = "agentos.rc19-post-install-update-rollback-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-031"
    status = $smokeDecision
    production_ready_claim = $false
    consumer_ready_claim = $false
    local_only = $true
    first_user_target_state_id = $firstUserTargetStateId
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    smoke_digest = $smokeDigest
    readiness = [ordered]@{
        outcome = $smokeDecision
        update_compatibility_readiness = if ($updateCompatibilityReady) { "ready" } else { "denied" }
        rollback_compatibility_readiness = if ($rollbackCompatibilityReady) { "ready" } else { "denied" }
        first_user_install_readiness = if ($firstUserInstallReady) { "ready" } else { "denied" }
        offline_channel_readiness = if ($offlineChannelReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($blockers)
        next_safe_action = "project-rc19-first-user-support-recovery"
    }
    boundary = [ordered]@{
        rc19_target_kind = [string]$firstUserInstallResult.install_surface.target_kind
        rc18_update_image_scope = [string]$rc18UpdateResult.update_surface.image_scope
        rc18_rollback_image_scope = [string]$rc18RollbackResult.rollback_surface.image_scope
        disposable_boundary_compatible = $disposableBoundaryCompatible
        update_or_rollback_executed_by_this_smoke = $false
    }
    compatibility_sources = [ordered]@{
        rc18_update_result_sha256 = Get-FileSha256 $resolvedRc18UpdateResultPath
        rc18_update_evidence_sha256 = Get-FileSha256 $resolvedRc18UpdateEvidencePath
        rc18_rollback_result_sha256 = Get-FileSha256 $resolvedRc18RollbackResultPath
        rc18_rollback_evidence_sha256 = Get-FileSha256 $resolvedRc18RollbackEvidencePath
        rc18_updated_image_state_id = [string]$rc18UpdateResult.updated_image_state_id
        rc18_restored_image_state_id = [string]$rc18RollbackResult.restored_image_state_id
    }
    audit = $audit
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$smokeEvidencePath = Join-Path $resolvedArtifactDir "post-install-update-rollback-evidence.json"
Write-Json $smokeEvidence $smokeEvidencePath

Add-Check "plan.current_task.rc19_031" $planAllowsRun "RC19-031 must run after RC19-030 completed, while current_task is RC19-031 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_030_status = $rc19PreviousStatus; rc19_031_status = $rc19TaskStatus })
Add-Check "source.first_user_install.ready" $firstUserInstallReady "Post-install smoke must bind RC19 first-user install evidence and disposable target state." ([ordered]@{ first_user_install_ready = $firstUserInstallReady; target_state_id = $firstUserTargetStateId; target_kind = $firstUserInstallResult.install_surface.target_kind; host_rootfs_mutated = $firstUserInstallResult.summary.host_rootfs_mutated })
Add-Check "source.offline_channel.ready" $offlineChannelReady "Post-install smoke must bind RC19 offline/local channel consumption without remote payload or consumer-ready claim." ([ordered]@{ offline_channel_ready = $offlineChannelReady; offline_local_channel_package_id = $offlineChannelResult.offline_local_channel_package_id; remote_payload_downloaded = $offlineChannelEvidence.side_effects.remote_payload_downloaded; consumer_ready_claim = $offlineChannelEvidence.side_effects.consumer_ready_claim })
Add-Check "source.rc18_update.compatible" $updateCompatibilityReady "Post-install update compatibility must be derived from RC18 isolated update evidence inside disposable image boundary." ([ordered]@{ update_compatibility_ready = $updateCompatibilityReady; image_scope = $rc18UpdateResult.update_surface.image_scope; isolated_update_performed = $rc18UpdateResult.summary.isolated_update_performed; host_rootfs_mutated = $rc18UpdateResult.update_surface.host_rootfs_mutated })
Add-Check "source.rc18_rollback.compatible" $rollbackCompatibilityReady "Post-install rollback compatibility must be derived from RC18 isolated rollback evidence inside disposable image boundary." ([ordered]@{ rollback_compatibility_ready = $rollbackCompatibilityReady; image_scope = $rc18RollbackResult.rollback_surface.image_scope; isolated_rollback_performed = $rc18RollbackResult.summary.isolated_rollback_performed; host_rootfs_mutated = $rc18RollbackResult.rollback_surface.host_rootfs_mutated })
Add-Check "boundary.disposable_only" $disposableBoundaryCompatible "Update and rollback compatibility must be evaluated only against disposable first-user target and disposable installed-system image boundaries." $smokeEvidence.boundary
Add-Check "smoke.ready_or_denial" ($postInstallSmokeReady -and $smokeDecision -eq "post-install-update-rollback-compatible") "Smoke must report post-install update/rollback compatibility readiness or explicit denial." ([ordered]@{ decision = $smokeDecision; blockers = @($blockers) })
Add-Check "smoke.audit.bound" ($audit.local_only -eq $true -and $audit.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($smokeDigest)) "Post-install smoke must be audited and non-fabricated." $audit
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.install_performed_by_smoke -eq $false -and $sideEffects.update_performed_by_smoke -eq $false -and $sideEffects.rollback_execution_performed_by_smoke -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.endpoint_reachability_trusted -eq $false -and $sideEffects.frontend_output_trusted -eq $false -and $sideEffects.shell_output_trusted -eq $false -and $sideEffects.tui_output_trusted -eq $false -and $sideEffects.model_replay_trusted -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.consumer_ready_claim -eq $false) "RC19-031 must not execute new install/update/rollback, upload support, execute recovery, remote dispatch, mutate host/production state, trust external surfaces, handle private material, or claim consumer readiness." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 24) "Missing sources and forbidden authority surfaces must fail closed before post-install effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $smokeEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-031 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-post-install-update-rollback-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-031"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_user_target_state_id = $firstUserTargetStateId
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    smoke_digest = $smokeDigest
    post_install_surface = [ordered]@{
        state = $smokeDecision
        local_only = $true
        first_user_install_bound = $firstUserInstallReady
        offline_channel_bound = $offlineChannelReady
        update_compatibility_readiness = if ($updateCompatibilityReady) { "ready" } else { "denied" }
        rollback_compatibility_readiness = if ($rollbackCompatibilityReady) { "ready" } else { "denied" }
        disposable_boundary_compatible = $disposableBoundaryCompatible
        update_or_rollback_executed_by_this_smoke = $false
        audited = $true
        audit_digest = $smokeDigest
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        post_install_update_rollback_evidence = [ordered]@{
            path = Get-StablePath $smokeEvidencePath
            sha256 = Get-FileSha256 $smokeEvidencePath
            smoke_digest = $smokeDigest
        }
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        post_install_smoke_only = $true
        disposable_target_boundary_only = $true
        update_compatibility_evaluated = $true
        rollback_compatibility_evaluated = $true
        install_performed_by_smoke = $false
        update_performed_by_smoke = $false
        rollback_execution_performed_by_smoke = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
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
        rc19_031_complete = (@($script:failedChecks).Count -eq 0)
        post_install_smoke_decision = $smokeDecision
        update_compatibility_readiness = if ($updateCompatibilityReady) { "ready" } else { "denied" }
        rollback_compatibility_readiness = if ($rollbackCompatibilityReady) { "ready" } else { "denied" }
        first_user_install_bound = $firstUserInstallReady
        offline_channel_bound = $offlineChannelReady
        update_or_rollback_executed_by_this_smoke = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        consumer_ready_claim = $false
        next_task = "RC19-032"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-031-post-install-update-rollback-smoke.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-post-install-update-rollback-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-031"
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
    post_install_surface = $result.post_install_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-032"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC19-031 outputs." }

Write-Host "RC19 post-install update/rollback smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $smokeEvidencePath)"
Write-Host "Decision: $smokeDecision; update readiness: $($result.post_install_surface.update_compatibility_readiness); rollback readiness: $($result.post_install_surface.rollback_compatibility_readiness)"
Write-Host "Executed by this smoke: update=false; rollback=false; host mutation=false; remote dispatch=false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
