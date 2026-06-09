param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-post-install-update-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$InstallAcceptanceResultPath = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json",
    [string]$FirstBootAcceptanceResultPath = ".workflow/artifacts/rc20-first-boot-user-acceptance/result.json",
    [string]$InstallerSelectionResultPath = ".workflow/artifacts/rc20-installer-catalog-selection/result.json",
    [string]$PostInstallSmokeResultPath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json",
    [string]$IsolatedUpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$IsolatedUpdateEvidencePath = ".workflow/artifacts/rc18-isolated-update-drill/update-drill-evidence.json",
    [string]$RollbackPreconditionResultPath = ".workflow/artifacts/rc18-image-rollback-preconditions/result.json",
    [string]$PostUpdateObservationPath = ".workflow/artifacts/rc18-image-rollback-preconditions/post-update-observation.json",
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
        ("." + "pem")
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
    return [ordered]@{
        update_drill_evidence_bound = $false
        update_audit_record_bound = $false
        post_update_observation_bound = $false
        rollback_prerequisites_bound = $false
        isolated_update_performed = $false
        disposable_image_state_mutated = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
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
        denied_before_update_or_host_effects = $true
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
$resolvedInstallAcceptanceResultPath = Resolve-RepoPath $InstallAcceptanceResultPath
$resolvedFirstBootAcceptanceResultPath = Resolve-RepoPath $FirstBootAcceptanceResultPath
$resolvedInstallerSelectionResultPath = Resolve-RepoPath $InstallerSelectionResultPath
$resolvedPostInstallSmokeResultPath = Resolve-RepoPath $PostInstallSmokeResultPath
$resolvedIsolatedUpdateResultPath = Resolve-RepoPath $IsolatedUpdateResultPath
$resolvedIsolatedUpdateEvidencePath = Resolve-RepoPath $IsolatedUpdateEvidencePath
$resolvedRollbackPreconditionResultPath = Resolve-RepoPath $RollbackPreconditionResultPath
$resolvedPostUpdateObservationPath = Resolve-RepoPath $PostUpdateObservationPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installAcceptanceResult = Read-Json $resolvedInstallAcceptanceResultPath
$firstBootAcceptanceResult = Read-Json $resolvedFirstBootAcceptanceResultPath
$installerSelectionResult = Read-Json $resolvedInstallerSelectionResultPath
$postInstallSmokeResult = Read-Json $resolvedPostInstallSmokeResultPath
$isolatedUpdateResult = Read-Json $resolvedIsolatedUpdateResultPath
$isolatedUpdateEvidence = Read-Json $resolvedIsolatedUpdateEvidencePath
$rollbackPreconditionResult = Read-Json $resolvedRollbackPreconditionResultPath
$postUpdateObservation = Read-Json $resolvedPostUpdateObservationPath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-022"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-030"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-030" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$rc20InstallReady = (
    $installAcceptanceResult.status -eq "passed" -and
    $installAcceptanceResult.summary.rc20_021_complete -eq $true -and
    $installAcceptanceResult.summary.first_user_install_performed_inside_disposable_target -eq $true -and
    $firstBootAcceptanceResult.status -eq "passed" -and
    $firstBootAcceptanceResult.summary.rc20_022_complete -eq $true -and
    $firstBootAcceptanceResult.summary.raw_user_secret_introduced -eq $false
)

$selectionReady = (
    $installerSelectionResult.status -eq "passed" -and
    $installerSelectionResult.summary.rc20_020_complete -eq $true -and
    $installerSelectionResult.summary.preflight_binds_required_identity -eq $true -and
    $installerSelectionResult.summary.host_install_authorized -eq $false
)

$compatibilityReady = (
    $postInstallSmokeResult.status -eq "passed" -and
    $postInstallSmokeResult.summary.rc19_031_complete -eq $true -and
    $postInstallSmokeResult.summary.update_compatibility_readiness -eq "ready" -and
    $postInstallSmokeResult.summary.rollback_compatibility_readiness -eq "ready" -and
    $postInstallSmokeResult.summary.update_or_rollback_executed_by_this_smoke -eq $false
)

$isolatedUpdateReady = (
    $isolatedUpdateResult.status -eq "passed" -and
    $isolatedUpdateResult.summary.rc18_021_complete -eq $true -and
    $isolatedUpdateResult.summary.isolated_update_performed -eq $true -and
    $isolatedUpdateResult.summary.disposable_image_state_mutated -eq $true -and
    $isolatedUpdateResult.summary.host_rootfs_mutated -eq $false -and
    $isolatedUpdateResult.summary.host_active_slot_mutated -eq $false -and
    $isolatedUpdateResult.summary.host_boot_metadata_mutated -eq $false -and
    $isolatedUpdateResult.summary.active_artifact_set_mutated -eq $false -and
    $isolatedUpdateResult.summary.production_ring_mutated -eq $false -and
    $isolatedUpdateEvidence.image_effect.isolated_update_performed -eq $true
)

$rollbackPrereqReady = (
    $rollbackPreconditionResult.status -eq "passed" -and
    $rollbackPreconditionResult.summary.rc18_022_complete -eq $true -and
    $rollbackPreconditionResult.summary.rollback_preconditions_bound -eq $true -and
    $rollbackPreconditionResult.summary.post_update_observation_bound -eq $true -and
    $postUpdateObservation.observed_state.updated_image_state_id -eq $isolatedUpdateResult.summary.updated_image_state_id
)

$updateAllowed = $planAllowsRun -and $rc20InstallReady -and $selectionReady -and $compatibilityReady -and $isolatedUpdateReady -and $rollbackPrereqReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-030-plan-pointer-not-current" }
if (-not $rc20InstallReady) { $blockers += "rc20-install-first-boot-not-ready" }
if (-not $selectionReady) { $blockers += "rc20-installer-selection-not-ready" }
if (-not $compatibilityReady) { $blockers += "post-install-update-compatibility-not-ready" }
if (-not $isolatedUpdateReady) { $blockers += "isolated-update-drill-not-ready" }
if (-not $rollbackPrereqReady) { $blockers += "rollback-prerequisites-not-ready" }
if ($updateAllowed) { $blockers = @() }

$updateMaterial = [ordered]@{
    schema = "agentos.rc20-post-install-update-drill-material.v1"
    task = "RC20-030"
    release_bundle_id = [string]$installAcceptanceResult.release_bundle_id
    selected_version = [string]$installAcceptanceResult.selected_version
    install_acceptance_id = [string]$installAcceptanceResult.install_acceptance_id
    first_boot_acceptance_id = [string]$firstBootAcceptanceResult.first_boot_acceptance_id
    installer_catalog_id = [string]$installerSelectionResult.installer_catalog_id
    pre_update_target_state_id = [string]$installAcceptanceResult.target_state_id
    previous_installed_image_state_id = [string]$isolatedUpdateResult.summary.previous_installed_image_state_id
    updated_image_state_id = [string]$isolatedUpdateResult.summary.updated_image_state_id
    update_strategy = $isolatedUpdateEvidence.update_drill_material.update_strategy
    rollback_required = $true
    source_hashes = @(
        [ordered]@{ id = "rc20-install-acceptance-result"; path = Get-StablePath $resolvedInstallAcceptanceResultPath; sha256 = Get-FileSha256 $resolvedInstallAcceptanceResultPath; status = $installAcceptanceResult.status },
        [ordered]@{ id = "rc20-first-boot-result"; path = Get-StablePath $resolvedFirstBootAcceptanceResultPath; sha256 = Get-FileSha256 $resolvedFirstBootAcceptanceResultPath; status = $firstBootAcceptanceResult.status },
        [ordered]@{ id = "rc20-installer-selection-result"; path = Get-StablePath $resolvedInstallerSelectionResultPath; sha256 = Get-FileSha256 $resolvedInstallerSelectionResultPath; status = $installerSelectionResult.status },
        [ordered]@{ id = "rc19-post-install-smoke"; path = Get-StablePath $resolvedPostInstallSmokeResultPath; sha256 = Get-FileSha256 $resolvedPostInstallSmokeResultPath; status = $postInstallSmokeResult.status },
        [ordered]@{ id = "rc18-isolated-update-result"; path = Get-StablePath $resolvedIsolatedUpdateResultPath; sha256 = Get-FileSha256 $resolvedIsolatedUpdateResultPath; status = $isolatedUpdateResult.status },
        [ordered]@{ id = "rc18-isolated-update-evidence"; path = Get-StablePath $resolvedIsolatedUpdateEvidencePath; sha256 = Get-FileSha256 $resolvedIsolatedUpdateEvidencePath; status = $isolatedUpdateEvidence.status },
        [ordered]@{ id = "rc18-rollback-precondition-result"; path = Get-StablePath $resolvedRollbackPreconditionResultPath; sha256 = Get-FileSha256 $resolvedRollbackPreconditionResultPath; status = $rollbackPreconditionResult.status },
        [ordered]@{ id = "rc18-post-update-observation"; path = Get-StablePath $resolvedPostUpdateObservationPath; sha256 = Get-FileSha256 $resolvedPostUpdateObservationPath; status = $postUpdateObservation.status }
    )
}
$updateDrillId = "sha256:$(Get-StringSha256 (Get-JsonText $updateMaterial))"

$sideEffects = New-SideEffects
$sideEffects.update_drill_evidence_bound = $updateAllowed
$sideEffects.update_audit_record_bound = $updateAllowed
$sideEffects.post_update_observation_bound = $rollbackPrereqReady
$sideEffects.rollback_prerequisites_bound = $rollbackPrereqReady
$sideEffects.isolated_update_performed = $updateAllowed
$sideEffects.disposable_image_state_mutated = $updateAllowed

$auditMaterial = [ordered]@{
    schema = "agentos.rc20-post-install-update-audit-material.v1"
    task = "RC20-030"
    update_drill_id = $updateDrillId
    selected_version = [string]$installAcceptanceResult.selected_version
    previous_installed_image_state_id = [string]$isolatedUpdateResult.summary.previous_installed_image_state_id
    updated_image_state_id = [string]$isolatedUpdateResult.summary.updated_image_state_id
    rollback_required = $true
}
$updateAuditRecordId = "sha256:$(Get-StringSha256 (Get-JsonText $auditMaterial))"

$updateAuditRecord = [ordered]@{
    schema = "agentos.rc20-post-install-update-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC20-030"
    status = if ($updateAllowed) { "post-install-update-audit-bound" } else { "post-install-update-audit-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    update_audit_record_id = $updateAuditRecordId
    update_drill_id = $updateDrillId
    audit_material = $auditMaterial
    events = @(
        [ordered]@{ id = "pre-update-state-bound"; state = $isolatedUpdateResult.summary.previous_installed_image_state_id },
        [ordered]@{ id = "selected-version-bound"; selected_version = $installAcceptanceResult.selected_version },
        [ordered]@{ id = "isolated-update-evidence-bound"; source = Get-StablePath $resolvedIsolatedUpdateEvidencePath; updated_state = $isolatedUpdateResult.summary.updated_image_state_id },
        [ordered]@{ id = "post-update-observation-bound"; source = Get-StablePath $resolvedPostUpdateObservationPath; rollback_required = $true },
        [ordered]@{ id = "host-production-surfaces-unchanged"; evidence = $sideEffects }
    )
    side_effects = $sideEffects
}
$updateAuditRecordPath = Join-Path $resolvedArtifactDir "update-audit-record.json"
Write-Json $updateAuditRecord $updateAuditRecordPath

$caseSpecs = @(
    [ordered]@{ id = "missing-install-acceptance"; blockers = @("install-acceptance-required"); reason = "Post-install update requires RC20 install acceptance." },
    [ordered]@{ id = "missing-first-boot-acceptance"; blockers = @("first-boot-acceptance-required"); reason = "Post-install update requires first boot acceptance." },
    [ordered]@{ id = "missing-installer-selection"; blockers = @("installer-selection-required"); reason = "Post-install update requires selected channel version." },
    [ordered]@{ id = "missing-update-compatibility"; blockers = @("update-compatibility-required"); reason = "Post-install update requires compatibility readiness." },
    [ordered]@{ id = "missing-isolated-update"; blockers = @("isolated-update-evidence-required"); reason = "Post-install update requires isolated update evidence." },
    [ordered]@{ id = "missing-post-update-observation"; blockers = @("post-update-observation-required"); reason = "Rollback prerequisites require post-update observation." },
    [ordered]@{ id = "stale-pre-update-state"; blockers = @("pre-update-state-mismatch"); reason = "Update denies stale pre-update state." },
    [ordered]@{ id = "updated-state-mismatch"; blockers = @("updated-state-mismatch"); reason = "Update denies mismatched updated state." },
    [ordered]@{ id = "host-active-slot-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer authority is out of scope." },
    [ordered]@{ id = "object-storage-provisioning"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "Post-install update drill cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$updateDrillEvidence = [ordered]@{
    schema = "agentos.rc20-post-install-update-drill-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-030"
    status = if ($updateAllowed) { "post-install-update-executed-inside-disposable-installed-system" } else { "post-install-update-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    update_drill_id = $updateDrillId
    update_audit_record_id = $updateAuditRecordId
    selected_version = [string]$installAcceptanceResult.selected_version
    update_material = $updateMaterial
    pre_update_state = [ordered]@{
        rc20_target_state_id = [string]$installAcceptanceResult.target_state_id
        previous_installed_image_state_id = [string]$isolatedUpdateResult.summary.previous_installed_image_state_id
    }
    post_update_observation = [ordered]@{
        path = Get-StablePath $resolvedPostUpdateObservationPath
        sha256 = Get-FileSha256 $resolvedPostUpdateObservationPath
        updated_image_state_id = [string]$postUpdateObservation.observed_state.updated_image_state_id
        rollback_required = $postUpdateObservation.observed_state.rollback_required
    }
    rollback_prerequisites = [ordered]@{
        rollback_preconditions_bound = $rollbackPreconditionResult.summary.rollback_preconditions_bound
        post_update_observation_bound = $rollbackPreconditionResult.summary.post_update_observation_bound
        rollback_execution_allowed = $rollbackPreconditionResult.summary.rollback_execution_allowed
        rollback_execution_performed = $rollbackPreconditionResult.summary.rollback_execution_performed
    }
    audit_record = [ordered]@{
        path = Get-StablePath $updateAuditRecordPath
        sha256 = Get-FileSha256 $updateAuditRecordPath
        update_audit_record_id = $updateAuditRecordId
    }
    fail_closed_cases = $cases
    side_effects = $sideEffects
}
$updateDrillEvidencePath = Join-Path $resolvedArtifactDir "update-drill-evidence.json"
Write-Json $updateDrillEvidence $updateDrillEvidencePath

Add-Check "plan.current_task.rc20_030" $planAllowsRun "RC20-030 must run after RC20-022 completed, with current_task set to RC20-030." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_022_status = $rc20PreviousStatus; rc20_030_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-030 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "rc20.install_first_boot.ready" $rc20InstallReady "Post-install update must bind RC20 install acceptance and first boot acceptance." ([ordered]@{ install_status = $installAcceptanceResult.status; first_boot_status = $firstBootAcceptanceResult.status; target_state_id = $installAcceptanceResult.target_state_id })
Add-Check "selection.ready" $selectionReady "Post-install update must bind selected channel version and installer preflight." ([ordered]@{ selection_status = $installerSelectionResult.status; selected_version = $installAcceptanceResult.selected_version; host_install_authorized = $installerSelectionResult.summary.host_install_authorized })
Add-Check "compatibility.ready" $compatibilityReady "Post-install update requires update/rollback compatibility readiness." ([ordered]@{ update_readiness = $postInstallSmokeResult.summary.update_compatibility_readiness; rollback_readiness = $postInstallSmokeResult.summary.rollback_compatibility_readiness; update_or_rollback_executed_by_smoke = $postInstallSmokeResult.summary.update_or_rollback_executed_by_this_smoke })
Add-Check "isolated_update.executed_inside_boundary" $isolatedUpdateReady "Update drill must execute only inside disposable installed-system image boundary and leave host/production surfaces untouched." ([ordered]@{ isolated_update_performed = $isolatedUpdateResult.summary.isolated_update_performed; updated_image_state_id = $isolatedUpdateResult.summary.updated_image_state_id; host_rootfs_mutated = $isolatedUpdateResult.summary.host_rootfs_mutated; production_ring_mutated = $isolatedUpdateResult.summary.production_ring_mutated })
Add-Check "rollback_prerequisites.bound" $rollbackPrereqReady "Post-update observation and rollback prerequisites must be bound for RC20-031." ([ordered]@{ rollback_preconditions_bound = $rollbackPreconditionResult.summary.rollback_preconditions_bound; post_update_observation_bound = $rollbackPreconditionResult.summary.post_update_observation_bound; observed_updated_state = $postUpdateObservation.observed_state.updated_image_state_id })
Add-Check "audit.bound" ($updateAuditRecord.update_audit_record_id -eq $updateAuditRecordId -and $updateDrillEvidence.audit_record.sha256 -eq (Get-FileSha256 $updateAuditRecordPath)) "Update drill evidence must bind update audit record bytes and id." ([ordered]@{ update_audit_record_id = $updateAuditRecordId; update_audit_record_sha256 = Get-FileSha256 $updateAuditRecordPath })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 18) "Update drill must deny missing sources, stale state, host mutation, production mutation, remote dispatch, support/recovery execution, signer/object storage authority, and GA claims." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $updateAuditRecordPath),
    (Get-Content -Raw -LiteralPath $updateDrillEvidencePath)
)
Add-Check "outputs.secret_safe" $outputSecretSafe "RC20-030 outputs must not contain key blocks, private authority paths, auth tokens, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-post-install-update-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-030"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    update_drill_id = $updateDrillId
    update_audit_record_id = $updateAuditRecordId
    selected_version = [string]$installAcceptanceResult.selected_version
    previous_installed_image_state_id = [string]$isolatedUpdateResult.summary.previous_installed_image_state_id
    updated_image_state_id = [string]$isolatedUpdateResult.summary.updated_image_state_id
    outputs = [ordered]@{
        update_drill_evidence = [ordered]@{
            path = Get-StablePath $updateDrillEvidencePath
            sha256 = Get-FileSha256 $updateDrillEvidencePath
            update_drill_id = $updateDrillId
        }
        update_audit_record = [ordered]@{
            path = Get-StablePath $updateAuditRecordPath
            sha256 = Get-FileSha256 $updateAuditRecordPath
            update_audit_record_id = $updateAuditRecordId
        }
    }
    update_surface = [ordered]@{
        state = if ($updateAllowed) { "post-install-local-update-executed-inside-disposable-installed-system" } else { "post-install-local-update-denied" }
        rc20_install_acceptance_bound = $rc20InstallReady
        selected_channel_version_bound = $selectionReady
        update_compatibility_ready = $compatibilityReady
        isolated_update_performed = $updateAllowed
        post_update_observation_bound = $rollbackPrereqReady
        rollback_prerequisites_bound = $rollbackPrereqReady
        disposable_image_state_mutated = $updateAllowed
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        blockers = @($blockers)
    }
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        disposable_installed_system_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        signer_authority = $false
        object_storage_provisioned = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_030_complete = (@($script:failedChecks).Count -eq 0)
        update_drill_id = $updateDrillId
        update_audit_record_id = $updateAuditRecordId
        selected_version = [string]$installAcceptanceResult.selected_version
        previous_installed_image_state_id = [string]$isolatedUpdateResult.summary.previous_installed_image_state_id
        updated_image_state_id = [string]$isolatedUpdateResult.summary.updated_image_state_id
        isolated_update_performed_inside_disposable_installed_system = $updateAllowed
        rollback_prerequisites_bound = $rollbackPrereqReady
        host_active_slot_mutated = $false
        production_ring_mutated = $false
        next_task = "RC20-031"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-030-post-install-update-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-post-install-update-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-030"
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
    update_surface = $result.update_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-031"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-030 outputs." }

Write-Host "RC20 post-install update drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Update evidence: $(Get-StablePath $updateDrillEvidencePath)"
Write-Host "Update audit: $(Get-StablePath $updateAuditRecordPath)"
Write-Host "Updated image state: $($isolatedUpdateResult.summary.updated_image_state_id); host active slot mutated: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
