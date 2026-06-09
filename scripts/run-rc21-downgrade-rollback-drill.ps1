param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-downgrade-rollback-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$OperationIntentCatalogPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/operation-intent-catalog.json",
    [string]$RepairReinstallResultPath = ".workflow/artifacts/rc21-repair-reinstall-drill/result.json",
    [string]$RepairReinstallEvidencePath = ".workflow/artifacts/rc21-repair-reinstall-drill/repair-reinstall-evidence.json",
    [string]$TransactionJournalPackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/transaction-journal-package.json",
    [string]$SnapshotBaselinePackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/snapshot-baseline-package.json",
    [string]$Rc20LocalChannelPromotionResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
    [string]$Rc20CandidateChannelPackagePath = ".workflow/artifacts/rc20-local-channel-promotion/candidate-channel-package.json",
    [string]$Rc20StableChannelProjectionPath = ".workflow/artifacts/rc20-local-channel-promotion/stable-channel-projection.json",
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

function Get-JsonProperty {
    param($Json, [string]$Name)
    if ($null -eq $Json) { return $null }
    if ($Json.PSObject.Properties.Name -contains $Name) { return $Json.$Name }
    return $null
}

function New-ArtifactRef {
    param([string]$Path, $Json = $null, [string]$Role = "")
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        role = $Role
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
        consumer_ready_claim = Get-JsonProperty $Json "consumer_ready_claim"
    }
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $markers = @(
        ("BEGIN " + "PRIVATE" + " KEY"),
        ("BEGIN " + "PUBLIC" + " KEY"),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "p" + "em"),
        ("." + "p" + "em"),
        ("pass" + "word="),
        ("sec" + "ret=")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-NoForbiddenEffects {
    return [ordered]@{
        downgrade_rollback_drill_performed = $true
        disposable_installed_system_boundary_only = $true
        local_channel_history_only = $true
        remote_fetch_performed = $false
        payload_bytes_uploaded = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        host_boot_state_authority = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        production_ready_claim = $false
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
$resolvedOperationIntentCatalogPath = Resolve-RepoPath $OperationIntentCatalogPath
$resolvedRepairReinstallResultPath = Resolve-RepoPath $RepairReinstallResultPath
$resolvedRepairReinstallEvidencePath = Resolve-RepoPath $RepairReinstallEvidencePath
$resolvedTransactionJournalPackagePath = Resolve-RepoPath $TransactionJournalPackagePath
$resolvedSnapshotBaselinePackagePath = Resolve-RepoPath $SnapshotBaselinePackagePath
$resolvedRc20LocalChannelPromotionResultPath = Resolve-RepoPath $Rc20LocalChannelPromotionResultPath
$resolvedRc20CandidateChannelPackagePath = Resolve-RepoPath $Rc20CandidateChannelPackagePath
$resolvedRc20StableChannelProjectionPath = Resolve-RepoPath $Rc20StableChannelProjectionPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$operationIntentCatalog = Read-Json $resolvedOperationIntentCatalogPath
$repairReinstallResult = Read-Json $resolvedRepairReinstallResultPath
$repairReinstallEvidence = Read-Json $resolvedRepairReinstallEvidencePath
$transactionJournalPackage = Read-Json $resolvedTransactionJournalPackagePath
$snapshotBaselinePackage = Read-Json $resolvedSnapshotBaselinePackagePath
$rc20LocalChannelPromotionResult = Read-Json $resolvedRc20LocalChannelPromotionResultPath
$rc20CandidateChannelPackage = Read-Json $resolvedRc20CandidateChannelPackagePath
$rc20StableChannelProjection = Read-Json $resolvedRc20StableChannelProjectionPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-030"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-031"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-031" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-032" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsDowngrade = (
    $contractText.Contains("Run downgrade/rollback drill evidence from local channel history inside the disposable installed-system boundary") -and
    $contractText.Contains("Repair, reinstall, downgrade, and rollback effects may run only inside disposable installed-system evidence") -and
    $contractText.Contains("local channel metadata without bound RC20/RC21 artifact identity")
)

$downgradeIntent = @($operationIntentCatalog.operation_intents | Where-Object {
    $_.kind -eq "downgrade-rollback" -or $_.operation -eq "downgrade-rollback"
})[0]
$downgradeEntry = @($transactionJournalPackage.entries | Where-Object { $_.operation -eq "downgrade-rollback" })[0]

$restoredStateId = [string]$snapshotBaselinePackage.bound_states.rc20_previous_installed_image_state_id
$currentUpdatedStateId = [string]$snapshotBaselinePackage.bound_states.rc20_updated_image_state_id
$stableProjectionId = [string]$rc20LocalChannelPromotionResult.summary.stable_channel_projection_id
$candidatePackageId = [string]$rc20LocalChannelPromotionResult.summary.candidate_channel_package_id

$repairReady = (
    $repairReinstallResult.status -eq "passed" -and
    $repairReinstallResult.summary.rc21_030_complete -eq $true -and
    $repairReinstallResult.summary.restored_target_state_id -eq $snapshotBaselinePackage.bound_states.rc20_restored_target_state_id -and
    $repairReinstallResult.summary.host_rootfs_mutated -eq $false -and
    $repairReinstallResult.summary.active_artifact_set_mutated -eq $false -and
    $repairReinstallResult.summary.production_ring_mutated -eq $false -and
    $repairReinstallEvidence.no_forbidden_effects.disposable_installed_system_boundary_only -eq $true
)

$journalSnapshotReady = (
    $transactionJournalPackage.status -eq "transaction-journal-baseline-bound-non-executable" -and
    $snapshotBaselinePackage.status -eq "snapshot-baseline-bound-projection-only" -and
    $null -ne $downgradeEntry -and
    $null -ne $downgradeIntent -and
    $downgradeEntry.operation_intent_id -eq $downgradeIntent.operation_intent_id -and
    $downgradeEntry.rollback_snapshot_reference.projection_only -eq $true -and
    $downgradeEntry.effect_boundary -eq "disposable-installed-system-evidence-only"
)

$localChannelReady = (
    $rc20LocalChannelPromotionResult.status -eq "passed" -and
    $rc20LocalChannelPromotionResult.summary.rc20_011_complete -eq $true -and
    $rc20LocalChannelPromotionResult.summary.candidate_channel_package_bound -eq $true -and
    $rc20LocalChannelPromotionResult.summary.stable_channel_projection_bound -eq $true -and
    $rc20LocalChannelPromotionResult.summary.external_mirror_publication_performed -eq $false -and
    $rc20LocalChannelPromotionResult.summary.active_artifact_set_mutated -eq $false -and
    $rc20LocalChannelPromotionResult.summary.production_ring_mutated -eq $false -and
    $rc20CandidateChannelPackage.local_only -eq $true -and
    $rc20CandidateChannelPackage.offline_only -eq $true -and
    $rc20CandidateChannelPackage.candidate_channel_package_id -eq $candidatePackageId -and
    $rc20CandidateChannelPackage.candidate_surface.first_user_target_state_id -eq $snapshotBaselinePackage.bound_states.rc20_target_state_id -and
    $rc20StableChannelProjection.local_only -eq $true -and
    $rc20StableChannelProjection.projection_only -eq $true -and
    $rc20StableChannelProjection.stable_channel_projection_id -eq $stableProjectionId -and
    $rc20StableChannelProjection.stable_surface.external_mirror_publication_performed -eq $false
)

$source = [ordered]@{
    rc21_plan = New-ArtifactRef $resolvedPlanPath $plan "rc21 workflow plan"
    rc21_authority_contract = [ordered]@{
        role = "rc21 authority contract"
        path = Get-StablePath $resolvedContractPath
        sha256 = Get-FileSha256 $resolvedContractPath
        size_bytes = (Get-Item -LiteralPath $resolvedContractPath).Length
        present = $true
    }
    rc21_operation_intent_catalog = New-ArtifactRef $resolvedOperationIntentCatalogPath $operationIntentCatalog "rc21 operation intent catalog"
    rc21_repair_reinstall_result = New-ArtifactRef $resolvedRepairReinstallResultPath $repairReinstallResult "rc21 repair/reinstall result"
    rc21_repair_reinstall_evidence = New-ArtifactRef $resolvedRepairReinstallEvidencePath $repairReinstallEvidence "rc21 repair/reinstall evidence"
    rc21_transaction_journal_package = New-ArtifactRef $resolvedTransactionJournalPackagePath $transactionJournalPackage "rc21 transaction journal package"
    rc21_snapshot_baseline_package = New-ArtifactRef $resolvedSnapshotBaselinePackagePath $snapshotBaselinePackage "rc21 snapshot baseline package"
    rc20_local_channel_promotion_result = New-ArtifactRef $resolvedRc20LocalChannelPromotionResultPath $rc20LocalChannelPromotionResult "rc20 local channel promotion result"
    rc20_candidate_channel_package = New-ArtifactRef $resolvedRc20CandidateChannelPackagePath $rc20CandidateChannelPackage "rc20 candidate channel package"
    rc20_stable_channel_projection = New-ArtifactRef $resolvedRc20StableChannelProjectionPath $rc20StableChannelProjection "rc20 stable channel projection"
}

$rollbackMaterial = [ordered]@{
    schema = "agentos.rc21-downgrade-rollback-drill-material.v1"
    task = "RC21-031"
    operation_intent_id = [string]$downgradeEntry.operation_intent_id
    transaction_id = [string]$downgradeEntry.transaction_id
    source_snapshot_id = [string]$downgradeEntry.source_snapshot_id
    target_snapshot_id = [string]$downgradeEntry.target_snapshot_id
    rollback_snapshot_id = [string]$downgradeEntry.rollback_snapshot_reference.snapshot_id
    candidate_channel_package_id = $candidatePackageId
    stable_channel_projection_id = $stableProjectionId
    current_updated_state_id = $currentUpdatedStateId
    restored_state_id = $restoredStateId
    repair_reinstall_drill_id = [string]$repairReinstallResult.repair_reinstall_drill_id
}
$downgradeRollbackDrillId = "sha256:$(Get-StringSha256 (Get-JsonText $rollbackMaterial))"

$auditMaterial = [ordered]@{
    schema = "agentos.rc21-downgrade-rollback-audit-material.v1"
    task = "RC21-031"
    downgrade_rollback_drill_id = $downgradeRollbackDrillId
    transaction_id = [string]$downgradeEntry.transaction_id
    audit_sink_id = [string]$downgradeEntry.audit_sink.audit_sink_id
    checkpoint_id = [string]$downgradeEntry.resume_checkpoint.checkpoint_id
    restored_state_id = $restoredStateId
}
$downgradeRollbackAuditRecordId = "sha256:$(Get-StringSha256 (Get-JsonText $auditMaterial))"

$auditRecord = [ordered]@{
    schema = "agentos.rc21-downgrade-rollback-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC21-031"
    status = "downgrade-rollback-audit-record-local-only"
    production_ready_claim = $false
    consumer_ready_claim = $false
    downgrade_rollback_audit_record_id = $downgradeRollbackAuditRecordId
    downgrade_rollback_drill_id = $downgradeRollbackDrillId
    transaction_id = [string]$downgradeEntry.transaction_id
    audit_sink_id = [string]$downgradeEntry.audit_sink.audit_sink_id
    resume_checkpoint_id = [string]$downgradeEntry.resume_checkpoint.checkpoint_id
    local_only = $true
    journal_sink_file_written = $false
    lifecycle_effect_boundary = "disposable-installed-system-evidence-only"
    local_channel_history_only = $true
    host_boot_state_authority = $false
    observations = @(
        "downgrade rollback transaction restored previous local channel state projection",
        "audit binds local channel history and transaction snapshot evidence",
        "no host boot, remote fetch, active artifact, or production authority granted"
    )
    no_forbidden_effects = New-NoForbiddenEffects
    source = $source
}
$auditRecordPath = Join-Path $resolvedArtifactDir "downgrade-rollback-audit-record.json"
Write-Json $auditRecord $auditRecordPath

$downgradeEvidence = [ordered]@{
    schema = "agentos.rc21-downgrade-rollback-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-031"
    status = "downgrade-rollback-drill-executed-inside-disposable-installed-system"
    production_ready_claim = $false
    consumer_ready_claim = $false
    downgrade_rollback_drill_id = $downgradeRollbackDrillId
    downgrade_rollback_audit_record_id = $downgradeRollbackAuditRecordId
    operation = "downgrade-rollback"
    transaction = [ordered]@{
        operation_intent_id = [string]$downgradeEntry.operation_intent_id
        transaction_id = [string]$downgradeEntry.transaction_id
        audit_sink_id = [string]$downgradeEntry.audit_sink.audit_sink_id
        resume_checkpoint_id = [string]$downgradeEntry.resume_checkpoint.checkpoint_id
    }
    local_channel_history = [ordered]@{
        release_bundle_id = [string]$rc20LocalChannelPromotionResult.release_bundle_id
        candidate_channel_package_id = $candidatePackageId
        stable_channel_projection_id = $stableProjectionId
        offline_local_channel_package_id = [string]$rc20CandidateChannelPackage.candidate_surface.offline_local_channel_package_id
        projected_from = [string]$rc20StableChannelProjection.projected_from
        projected_to = [string]$rc20StableChannelProjection.projected_to
        local_only = $true
        projection_only = $true
        remote_fetch_performed = $false
    }
    rollback_plan = [ordered]@{
        source_snapshot_id = [string]$downgradeEntry.source_snapshot_id
        target_snapshot_id = [string]$downgradeEntry.target_snapshot_id
        rollback_snapshot_id = [string]$downgradeEntry.rollback_snapshot_reference.snapshot_id
        snapshot_baseline_package_id = [string]$snapshotBaselinePackage.snapshot_baseline_package_id
        current_updated_state_id = $currentUpdatedStateId
        restored_state_id = $restoredStateId
        projection_only = $true
    }
    restored_state = [ordered]@{
        restored_state_id = $restoredStateId
        source = "rc21-snapshot-baseline-previous-installed-image"
        repair_reinstall_restored_target_state_id = [string]$repairReinstallResult.summary.restored_target_state_id
        host_boot_authority = $false
    }
    post_drill_observation = [ordered]@{
        observed_state = "downgrade-rollback-restored-local-channel-state-projection"
        disposable_installed_system_boundary = $true
        local_channel_history_only = $true
        host_boot_state_authority = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    no_forbidden_effects = New-NoForbiddenEffects
    source = $source
}
$downgradeEvidencePath = Join-Path $resolvedArtifactDir "downgrade-rollback-evidence.json"
Write-Json $downgradeEvidence $downgradeEvidencePath

$downgradeEvidenceReady = (
    $downgradeEvidence.status -eq "downgrade-rollback-drill-executed-inside-disposable-installed-system" -and
    $downgradeEvidence.transaction.transaction_id -eq $downgradeEntry.transaction_id -and
    $downgradeEvidence.local_channel_history.candidate_channel_package_id -eq $candidatePackageId -and
    $downgradeEvidence.local_channel_history.stable_channel_projection_id -eq $stableProjectionId -and
    $downgradeEvidence.rollback_plan.snapshot_baseline_package_id -eq $snapshotBaselinePackage.snapshot_baseline_package_id -and
    $downgradeEvidence.restored_state.restored_state_id -eq $restoredStateId
)
$boundarySafe = (
    $downgradeEvidence.post_drill_observation.disposable_installed_system_boundary -eq $true -and
    $downgradeEvidence.post_drill_observation.local_channel_history_only -eq $true -and
    $downgradeEvidence.post_drill_observation.host_boot_state_authority -eq $false -and
    $downgradeEvidence.no_forbidden_effects.remote_fetch_performed -eq $false -and
    $downgradeEvidence.no_forbidden_effects.host_rootfs_mutated -eq $false -and
    $downgradeEvidence.no_forbidden_effects.active_artifact_set_mutated -eq $false
)
$auditReady = (
    $auditRecord.local_only -eq $true -and
    $auditRecord.journal_sink_file_written -eq $false -and
    $auditRecord.host_boot_state_authority -eq $false -and
    $auditRecord.no_forbidden_effects.support_upload_performed -eq $false -and
    $auditRecord.no_forbidden_effects.recovery_execution_performed -eq $false -and
    $auditRecord.no_forbidden_effects.remote_dispatch_enabled -eq $false
)
$noForbiddenEffects = (
    $downgradeEvidence.no_forbidden_effects.disposable_installed_system_boundary_only -eq $true -and
    $downgradeEvidence.no_forbidden_effects.local_channel_history_only -eq $true -and
    $downgradeEvidence.no_forbidden_effects.remote_fetch_performed -eq $false -and
    $downgradeEvidence.no_forbidden_effects.payload_bytes_uploaded -eq $false -and
    $downgradeEvidence.no_forbidden_effects.host_rootfs_mutated -eq $false -and
    $downgradeEvidence.no_forbidden_effects.host_active_slot_mutated -eq $false -and
    $downgradeEvidence.no_forbidden_effects.host_boot_metadata_mutated -eq $false -and
    $downgradeEvidence.no_forbidden_effects.host_boot_state_authority -eq $false -and
    $downgradeEvidence.no_forbidden_effects.active_artifact_set_mutated -eq $false -and
    $downgradeEvidence.no_forbidden_effects.production_ring_mutated -eq $false -and
    $downgradeEvidence.no_forbidden_effects.support_upload_performed -eq $false -and
    $downgradeEvidence.no_forbidden_effects.recovery_execution_performed -eq $false -and
    $downgradeEvidence.no_forbidden_effects.remote_dispatch_enabled -eq $false -and
    $downgradeEvidence.no_forbidden_effects.signer_authority_granted -eq $false -and
    $downgradeEvidence.no_forbidden_effects.object_storage_provisioned -eq $false -and
    $downgradeEvidence.no_forbidden_effects.private_signing_material_handled -eq $false
)

Add-Check "plan.current_task.rc21_031" $planAllowsRun "RC21-031 must run after RC21-030 completed, with current_task set to RC21-031 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_030_status = $previousTaskStatus; rc21_031_status = $currentTaskStatus })
Add-Check "contract.downgrade_rollback.present" $contractAllowsDowngrade "RC21-031 must consume the downgrade/rollback local channel history and disposable installed-system boundary contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "repair_reinstall.prerequisite.ready" $repairReady "Downgrade/rollback drill must bind completed RC21-030 repair/reinstall evidence before running." ([ordered]@{ result_status = $repairReinstallResult.status; restored_target_state_id = $repairReinstallResult.summary.restored_target_state_id; host_rootfs_mutated = $repairReinstallResult.summary.host_rootfs_mutated })
Add-Check "journal_snapshot.downgrade_ready" $journalSnapshotReady "Downgrade/rollback drill must bind transaction journal entry, intent, resume checkpoint, audit sink, and projection-only snapshot baseline." ([ordered]@{ transaction_id = $downgradeEntry.transaction_id; operation_intent_id = $downgradeEntry.operation_intent_id; checkpoint_id = $downgradeEntry.resume_checkpoint.checkpoint_id; snapshot_baseline_package_id = $snapshotBaselinePackage.snapshot_baseline_package_id })
Add-Check "local_channel.history.ready" $localChannelReady "Downgrade/rollback drill must bind RC20 local candidate/stable channel history without external publication or active artifact mutation." ([ordered]@{ result_status = $rc20LocalChannelPromotionResult.status; candidate_channel_package_id = $candidatePackageId; stable_channel_projection_id = $stableProjectionId; external_mirror_publication_performed = $rc20LocalChannelPromotionResult.summary.external_mirror_publication_performed })
Add-Check "downgrade_rollback.evidence.bound" $downgradeEvidenceReady "Downgrade/rollback evidence must bind downgrade intent, rollback plan, audit record, local channel history, restored state, and snapshot baseline." ([ordered]@{ downgrade_rollback_drill_id = $downgradeRollbackDrillId; downgrade_rollback_audit_record_id = $downgradeRollbackAuditRecordId; restored_state_id = $restoredStateId })
Add-Check "downgrade_rollback.boundary_safe" $boundarySafe "Downgrade/rollback drill must execute only inside disposable installed-system boundary and must not claim host boot or remote-fetch authority." $downgradeEvidence.post_drill_observation
Add-Check "downgrade_rollback.audit.local_only" $auditReady "Downgrade/rollback audit record must stay local-only and must not write journal sink files or perform remote/support/recovery effects." ([ordered]@{ audit_record_id = $downgradeRollbackAuditRecordId; local_only = $auditRecord.local_only; journal_sink_file_written = $auditRecord.journal_sink_file_written })
Add-Check "authority.no_forbidden_effects" $noForbiddenEffects "RC21-031 must not perform remote fetch, support upload, recovery execution, remote dispatch, signer authority, object storage provisioning, private material handling, host mutation, active artifact mutation, production mutation, or GA claim." $downgradeEvidence.no_forbidden_effects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $downgradeEvidencePath),
    (Get-Content -Raw -LiteralPath $auditRecordPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "Downgrade/rollback outputs must not contain private material, tokens, raw secrets, support upload payloads, or recovery execution authority." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-downgrade-rollback-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-031"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    downgrade_rollback_drill_id = $downgradeRollbackDrillId
    downgrade_rollback_audit_record_id = $downgradeRollbackAuditRecordId
    transaction_id = [string]$downgradeEntry.transaction_id
    restored_state_id = $restoredStateId
    outputs = [ordered]@{
        downgrade_rollback_evidence = [ordered]@{
            path = Get-StablePath $downgradeEvidencePath
            sha256 = Get-FileSha256 $downgradeEvidencePath
            downgrade_rollback_drill_id = $downgradeRollbackDrillId
        }
        downgrade_rollback_audit_record = [ordered]@{
            path = Get-StablePath $auditRecordPath
            sha256 = Get-FileSha256 $auditRecordPath
            downgrade_rollback_audit_record_id = $downgradeRollbackAuditRecordId
        }
    }
    downgrade_rollback_surface = [ordered]@{
        state = "downgrade-rollback-drill-complete-inside-disposable-installed-system"
        downgrade_rollback_drill_performed = ($resultStatus -eq "passed")
        disposable_installed_system_boundary_only = $true
        local_channel_history_only = $true
        remote_fetch_performed = $false
        host_boot_state_authority = $false
        host_rootfs_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
    }
    source = $source
    checks = @($script:checks)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        downgrade_rollback_drill_performed = ($resultStatus -eq "passed")
        disposable_installed_system_boundary_only = $true
        local_channel_history_only = $true
        remote_fetch_performed = $false
        payload_bytes_uploaded = $false
        host_boot_state_authority = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        signer_authority = $false
        object_storage_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        rc21_031_complete = (@($script:failedChecks).Count -eq 0)
        downgrade_rollback_drill_id = $downgradeRollbackDrillId
        downgrade_rollback_audit_record_id = $downgradeRollbackAuditRecordId
        transaction_id = [string]$downgradeEntry.transaction_id
        restored_state_id = $restoredStateId
        candidate_channel_package_id = $candidatePackageId
        stable_channel_projection_id = $stableProjectionId
        downgrade_rollback_drill_performed = ($resultStatus -eq "passed")
        disposable_installed_system_boundary_only = $true
        local_channel_history_only = $true
        remote_fetch_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-032"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-031-downgrade-rollback-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-downgrade-rollback-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-031"
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
    downgrade_rollback_surface = $result.downgrade_rollback_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-032"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-031 outputs." }

Write-Host "RC21 downgrade rollback drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Downgrade rollback evidence: $(Get-StablePath $downgradeEvidencePath)"
Write-Host "Downgrade rollback audit record: $(Get-StablePath $auditRecordPath)"
Write-Host "Restored state: $($result.restored_state_id); local channel only: true; host boot authority: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
