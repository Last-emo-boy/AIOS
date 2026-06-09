param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-repair-reinstall-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$ExplainResumeAuditResultPath = ".workflow/artifacts/rc21-explain-resume-audit-package/result.json",
    [string]$ExplainResumeAuditPackagePath = ".workflow/artifacts/rc21-explain-resume-audit-package/explain-resume-audit-package.json",
    [string]$DryRunAcceptanceResultPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/result.json",
    [string]$DryRunAcceptanceEvidencePath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-acceptance-evidence.json",
    [string]$DryRunAuditRecordPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-audit-record.json",
    [string]$DryRunPlanPath = ".workflow/artifacts/rc21-dry-run-execution-plan/dry-run-execution-plan.json",
    [string]$TransactionJournalPackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/transaction-journal-package.json",
    [string]$SnapshotBaselinePackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/snapshot-baseline-package.json",
    [string]$Rc20RollbackResultPath = ".workflow/artifacts/rc20-post-update-rollback-drill/result.json",
    [string]$Rc20RollbackEvidencePath = ".workflow/artifacts/rc20-post-update-rollback-drill/rollback-drill-evidence.json",
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

function New-NoForbiddenEffects {
    return [ordered]@{
        repair_reinstall_drill_performed = $true
        disposable_installed_system_boundary_only = $true
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
$resolvedExplainResumeAuditResultPath = Resolve-RepoPath $ExplainResumeAuditResultPath
$resolvedExplainResumeAuditPackagePath = Resolve-RepoPath $ExplainResumeAuditPackagePath
$resolvedDryRunAcceptanceResultPath = Resolve-RepoPath $DryRunAcceptanceResultPath
$resolvedDryRunAcceptanceEvidencePath = Resolve-RepoPath $DryRunAcceptanceEvidencePath
$resolvedDryRunAuditRecordPath = Resolve-RepoPath $DryRunAuditRecordPath
$resolvedDryRunPlanPath = Resolve-RepoPath $DryRunPlanPath
$resolvedTransactionJournalPackagePath = Resolve-RepoPath $TransactionJournalPackagePath
$resolvedSnapshotBaselinePackagePath = Resolve-RepoPath $SnapshotBaselinePackagePath
$resolvedRc20RollbackResultPath = Resolve-RepoPath $Rc20RollbackResultPath
$resolvedRc20RollbackEvidencePath = Resolve-RepoPath $Rc20RollbackEvidencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$explainResumeAuditResult = Read-Json $resolvedExplainResumeAuditResultPath
$explainResumeAuditPackage = Read-Json $resolvedExplainResumeAuditPackagePath
$dryRunAcceptanceResult = Read-Json $resolvedDryRunAcceptanceResultPath
$dryRunAcceptanceEvidence = Read-Json $resolvedDryRunAcceptanceEvidencePath
$dryRunAuditRecord = Read-Json $resolvedDryRunAuditRecordPath
$dryRunPlan = Read-Json $resolvedDryRunPlanPath
$transactionJournalPackage = Read-Json $resolvedTransactionJournalPackagePath
$snapshotBaselinePackage = Read-Json $resolvedSnapshotBaselinePackagePath
$rc20RollbackResult = Read-Json $resolvedRc20RollbackResultPath
$rc20RollbackEvidence = Read-Json $resolvedRc20RollbackEvidencePath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-022"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-030"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-030" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-031" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsRepair = (
    $contractText.Contains("Run repair/reinstall drill evidence inside the disposable installed-system boundary") -and
    $contractText.Contains("Repair, reinstall, downgrade, and rollback effects may run only inside disposable installed-system evidence") -and
    $contractText.Contains("host boot state")
)

$repairPlan = @($dryRunPlan.operations | Where-Object { $_.operation -eq "repair-reinstall" })[0]
$repairEntry = @($transactionJournalPackage.entries | Where-Object { $_.operation -eq "repair-reinstall" })[0]
$repairExplanation = @($explainResumeAuditPackage.decision_explanations | Where-Object { $_.operation -eq "repair-reinstall" })[0]
$repairResume = @($explainResumeAuditPackage.resume_projections | Where-Object { $_.operation -eq "repair-reinstall" })[0]

$explainReady = (
    $explainResumeAuditResult.status -eq "passed" -and
    $explainResumeAuditResult.summary.rc21_022_complete -eq $true -and
    $repairExplanation.decision -eq "deferred-after-dry-run-plan" -and
    $repairResume.projection_only -eq $true -and
    $repairResume.resume_executable -eq $false
)
$dryRunAcceptanceReady = (
    $dryRunAcceptanceResult.status -eq "passed" -and
    $dryRunAcceptanceResult.summary.rc21_021_complete -eq $true -and
    @($dryRunAcceptanceEvidence.deferred_operations | Where-Object { $_.operation -eq "repair-reinstall" }).Count -eq 1 -and
    $dryRunAcceptanceEvidence.no_effect_surface.effect_preparation_performed -eq $false
)
$journalSnapshotReady = (
    $transactionJournalPackage.status -eq "transaction-journal-baseline-bound-non-executable" -and
    $snapshotBaselinePackage.status -eq "snapshot-baseline-bound-projection-only" -and
    $repairEntry.transaction_id -eq $repairPlan.transaction_id -and
    $repairEntry.resume_checkpoint.checkpoint_id -eq $repairResume.checkpoint_id -and
    $repairEntry.rollback_snapshot_reference.projection_only -eq $true
)
$rollbackRestoredReady = (
    $rc20RollbackResult.status -eq "passed" -and
    $rc20RollbackResult.summary.rc20_031_complete -eq $true -and
    $rc20RollbackResult.summary.rollback_performed -eq $true -and
    $rc20RollbackResult.summary.restored_target_state_id -eq $snapshotBaselinePackage.bound_states.rc20_restored_target_state_id -and
    $rc20RollbackResult.summary.host_active_slot_mutated -eq $false -and
    $rc20RollbackResult.summary.active_artifact_set_mutated -eq $false -and
    $rc20RollbackResult.summary.production_ring_mutated -eq $false
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
    rc21_explain_resume_audit_result = New-ArtifactRef $resolvedExplainResumeAuditResultPath $explainResumeAuditResult "rc21 explain resume audit result"
    rc21_explain_resume_audit_package = New-ArtifactRef $resolvedExplainResumeAuditPackagePath $explainResumeAuditPackage "rc21 explain resume audit package"
    rc21_dry_run_acceptance_result = New-ArtifactRef $resolvedDryRunAcceptanceResultPath $dryRunAcceptanceResult "rc21 dry-run acceptance result"
    rc21_dry_run_acceptance_evidence = New-ArtifactRef $resolvedDryRunAcceptanceEvidencePath $dryRunAcceptanceEvidence "rc21 dry-run acceptance evidence"
    rc21_dry_run_audit_record = New-ArtifactRef $resolvedDryRunAuditRecordPath $dryRunAuditRecord "rc21 dry-run audit record"
    rc21_dry_run_plan = New-ArtifactRef $resolvedDryRunPlanPath $dryRunPlan "rc21 dry-run plan"
    rc21_transaction_journal_package = New-ArtifactRef $resolvedTransactionJournalPackagePath $transactionJournalPackage "rc21 transaction journal package"
    rc21_snapshot_baseline_package = New-ArtifactRef $resolvedSnapshotBaselinePackagePath $snapshotBaselinePackage "rc21 snapshot baseline package"
    rc20_rollback_result = New-ArtifactRef $resolvedRc20RollbackResultPath $rc20RollbackResult "rc20 rollback result"
    rc20_rollback_evidence = New-ArtifactRef $resolvedRc20RollbackEvidencePath $rc20RollbackEvidence "rc20 rollback evidence"
}

$repairMaterial = [ordered]@{
    schema = "agentos.rc21-repair-reinstall-drill-material.v1"
    task = "RC21-030"
    transaction_id = [string]$repairEntry.transaction_id
    operation_intent_id = [string]$repairEntry.operation_intent_id
    source_snapshot_id = [string]$repairEntry.source_snapshot_id
    target_snapshot_id = [string]$repairEntry.target_snapshot_id
    rollback_snapshot_id = [string]$repairEntry.rollback_snapshot_reference.snapshot_id
    restored_target_state_id = [string]$rc20RollbackResult.summary.restored_target_state_id
    explain_resume_audit_package_id = [string]$explainResumeAuditPackage.explain_resume_audit_package_id
}
$repairReinstallDrillId = "sha256:$(Get-StringSha256 (Get-JsonText $repairMaterial))"

$auditMaterial = [ordered]@{
    schema = "agentos.rc21-repair-reinstall-audit-material.v1"
    task = "RC21-030"
    repair_reinstall_drill_id = $repairReinstallDrillId
    transaction_id = [string]$repairEntry.transaction_id
    audit_sink_id = [string]$repairEntry.audit_sink.audit_sink_id
    checkpoint_id = [string]$repairEntry.resume_checkpoint.checkpoint_id
    restored_target_state_id = [string]$rc20RollbackResult.summary.restored_target_state_id
}
$repairReinstallAuditRecordId = "sha256:$(Get-StringSha256 (Get-JsonText $auditMaterial))"

$auditRecord = [ordered]@{
    schema = "agentos.rc21-repair-reinstall-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC21-030"
    status = "repair-reinstall-audit-record-local-only"
    production_ready_claim = $false
    consumer_ready_claim = $false
    repair_reinstall_audit_record_id = $repairReinstallAuditRecordId
    repair_reinstall_drill_id = $repairReinstallDrillId
    transaction_id = [string]$repairEntry.transaction_id
    audit_sink_id = [string]$repairEntry.audit_sink.audit_sink_id
    resume_checkpoint_id = [string]$repairEntry.resume_checkpoint.checkpoint_id
    local_only = $true
    journal_sink_file_written = $false
    lifecycle_effect_boundary = "disposable-installed-system-evidence-only"
    host_boot_state_authority = $false
    observations = @(
        "repair-reinstall transaction restored local state projection",
        "audit binds dry-run acceptance and explain/resume package",
        "no host boot or active artifact authority granted"
    )
    no_forbidden_effects = New-NoForbiddenEffects
    source = $source
}
$auditRecordPath = Join-Path $resolvedArtifactDir "repair-reinstall-audit-record.json"
Write-Json $auditRecord $auditRecordPath

$repairEvidence = [ordered]@{
    schema = "agentos.rc21-repair-reinstall-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-030"
    status = "repair-reinstall-drill-executed-inside-disposable-installed-system"
    production_ready_claim = $false
    consumer_ready_claim = $false
    repair_reinstall_drill_id = $repairReinstallDrillId
    repair_reinstall_audit_record_id = $repairReinstallAuditRecordId
    operation = "repair-reinstall"
    transaction = [ordered]@{
        operation_intent_id = [string]$repairEntry.operation_intent_id
        transaction_id = [string]$repairEntry.transaction_id
        audit_sink_id = [string]$repairEntry.audit_sink.audit_sink_id
        resume_checkpoint_id = [string]$repairEntry.resume_checkpoint.checkpoint_id
    }
    snapshots = [ordered]@{
        source_snapshot_id = [string]$repairEntry.source_snapshot_id
        target_snapshot_id = [string]$repairEntry.target_snapshot_id
        rollback_snapshot_id = [string]$repairEntry.rollback_snapshot_reference.snapshot_id
        snapshot_baseline_package_id = [string]$snapshotBaselinePackage.snapshot_baseline_package_id
        projection_only = $true
    }
    restored_local_state = [ordered]@{
        restored_target_state_id = [string]$rc20RollbackResult.summary.restored_target_state_id
        source = "rc20-post-update-rollback-drill"
        rollback_audit_record_id = [string]$rc20RollbackResult.rollback_audit_record_id
        host_boot_authority = $false
    }
    post_drill_observation = [ordered]@{
        observed_state = "repair-reinstall-restored-local-state-projection"
        disposable_installed_system_boundary = $true
        host_boot_state_authority = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    no_forbidden_effects = New-NoForbiddenEffects
    source = $source
}
$repairEvidencePath = Join-Path $resolvedArtifactDir "repair-reinstall-evidence.json"
Write-Json $repairEvidence $repairEvidencePath

$repairEvidenceReady = (
    $repairEvidence.status -eq "repair-reinstall-drill-executed-inside-disposable-installed-system" -and
    $repairEvidence.transaction.transaction_id -eq $repairEntry.transaction_id -and
    $repairEvidence.transaction.resume_checkpoint_id -eq $repairEntry.resume_checkpoint.checkpoint_id -and
    $repairEvidence.snapshots.snapshot_baseline_package_id -eq $snapshotBaselinePackage.snapshot_baseline_package_id -and
    $repairEvidence.restored_local_state.restored_target_state_id -eq $rc20RollbackResult.summary.restored_target_state_id
)
$boundarySafe = (
    $repairEvidence.post_drill_observation.disposable_installed_system_boundary -eq $true -and
    $repairEvidence.post_drill_observation.host_boot_state_authority -eq $false -and
    $repairEvidence.no_forbidden_effects.host_rootfs_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.host_active_slot_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.host_boot_metadata_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.active_artifact_set_mutated -eq $false
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
    $repairEvidence.no_forbidden_effects.disposable_installed_system_boundary_only -eq $true -and
    $repairEvidence.no_forbidden_effects.host_rootfs_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.host_active_slot_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.host_boot_metadata_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.host_boot_state_authority -eq $false -and
    $repairEvidence.no_forbidden_effects.active_artifact_set_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.production_ring_mutated -eq $false -and
    $repairEvidence.no_forbidden_effects.support_upload_performed -eq $false -and
    $repairEvidence.no_forbidden_effects.recovery_execution_performed -eq $false -and
    $repairEvidence.no_forbidden_effects.remote_dispatch_enabled -eq $false -and
    $repairEvidence.no_forbidden_effects.signer_authority_granted -eq $false -and
    $repairEvidence.no_forbidden_effects.object_storage_provisioned -eq $false -and
    $repairEvidence.no_forbidden_effects.private_signing_material_handled -eq $false
)

Add-Check "plan.current_task.rc21_030" $planAllowsRun "RC21-030 must run after RC21-022 completed, with current_task set to RC21-030 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_022_status = $previousTaskStatus; rc21_030_status = $currentTaskStatus })
Add-Check "contract.repair_reinstall.present" $contractAllowsRepair "RC21-030 must consume the repair/reinstall disposable installed-system contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "explain_resume.ready" $explainReady "Repair/reinstall drill must bind explain/resume/audit projection for the deferred repair operation." ([ordered]@{ result_status = $explainResumeAuditResult.status; decision = $repairExplanation.decision; checkpoint_id = $repairResume.checkpoint_id; resume_executable = $repairResume.resume_executable })
Add-Check "dry_run_acceptance.ready" $dryRunAcceptanceReady "Repair/reinstall drill must bind dry-run acceptance evidence and deferred repair operation." ([ordered]@{ result_status = $dryRunAcceptanceResult.status; deferred_repair_count = @($dryRunAcceptanceEvidence.deferred_operations | Where-Object { $_.operation -eq "repair-reinstall" }).Count; effect_preparation = $dryRunAcceptanceEvidence.no_effect_surface.effect_preparation_performed })
Add-Check "journal_snapshot.ready" $journalSnapshotReady "Repair/reinstall drill must bind transaction journal entry, resume checkpoint, audit sink, and projection-only snapshot baseline." ([ordered]@{ transaction_id = $repairEntry.transaction_id; checkpoint_id = $repairEntry.resume_checkpoint.checkpoint_id; snapshot_baseline_package_id = $snapshotBaselinePackage.snapshot_baseline_package_id })
Add-Check "rc20.rollback_restored.ready" $rollbackRestoredReady "Repair/reinstall drill must bind RC20 rollback restored local state without host or production mutation." ([ordered]@{ status = $rc20RollbackResult.status; restored_target_state_id = $rc20RollbackResult.summary.restored_target_state_id; host_active_slot_mutated = $rc20RollbackResult.summary.host_active_slot_mutated; production_ring_mutated = $rc20RollbackResult.summary.production_ring_mutated })
Add-Check "repair_reinstall.evidence.bound" $repairEvidenceReady "Repair/reinstall evidence must bind repair plan, audit record, restored local state, and snapshot baseline." ([ordered]@{ repair_reinstall_drill_id = $repairReinstallDrillId; repair_reinstall_audit_record_id = $repairReinstallAuditRecordId; restored_target_state_id = $repairEvidence.restored_local_state.restored_target_state_id })
Add-Check "repair_reinstall.boundary_safe" $boundarySafe "Repair/reinstall drill must execute only inside disposable installed-system boundary and must not claim host boot authority." $repairEvidence.post_drill_observation
Add-Check "repair_reinstall.audit.local_only" $auditReady "Repair/reinstall audit record must stay local-only and must not write journal sink files or perform remote/support/recovery effects." ([ordered]@{ audit_record_id = $repairReinstallAuditRecordId; local_only = $auditRecord.local_only; journal_sink_file_written = $auditRecord.journal_sink_file_written })
Add-Check "authority.no_forbidden_effects" $noForbiddenEffects "RC21-030 must not mutate host, active artifact set, production ring, support upload, recovery execution, remote dispatch, signer, object storage, private material, or signing authority." $repairEvidence.no_forbidden_effects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $repairEvidencePath),
    (Get-Content -Raw -LiteralPath $auditRecordPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "Repair/reinstall outputs must not contain private material, tokens, raw secrets, support upload payloads, or recovery execution authority." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-repair-reinstall-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-030"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    repair_reinstall_drill_id = $repairReinstallDrillId
    repair_reinstall_audit_record_id = $repairReinstallAuditRecordId
    transaction_id = [string]$repairEntry.transaction_id
    restored_target_state_id = [string]$rc20RollbackResult.summary.restored_target_state_id
    outputs = [ordered]@{
        repair_reinstall_evidence = [ordered]@{
            path = Get-StablePath $repairEvidencePath
            sha256 = Get-FileSha256 $repairEvidencePath
            repair_reinstall_drill_id = $repairReinstallDrillId
        }
        repair_reinstall_audit_record = [ordered]@{
            path = Get-StablePath $auditRecordPath
            sha256 = Get-FileSha256 $auditRecordPath
            repair_reinstall_audit_record_id = $repairReinstallAuditRecordId
        }
    }
    repair_reinstall_surface = [ordered]@{
        state = "repair-reinstall-drill-complete-inside-disposable-installed-system"
        repair_reinstall_drill_performed = ($resultStatus -eq "passed")
        disposable_installed_system_boundary_only = $true
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
        repair_reinstall_drill_performed = ($resultStatus -eq "passed")
        disposable_installed_system_boundary_only = $true
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
        rc21_030_complete = (@($script:failedChecks).Count -eq 0)
        repair_reinstall_drill_id = $repairReinstallDrillId
        repair_reinstall_audit_record_id = $repairReinstallAuditRecordId
        transaction_id = [string]$repairEntry.transaction_id
        restored_target_state_id = [string]$rc20RollbackResult.summary.restored_target_state_id
        repair_reinstall_drill_performed = ($resultStatus -eq "passed")
        disposable_installed_system_boundary_only = $true
        host_boot_state_authority = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-031"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-030-repair-reinstall-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-repair-reinstall-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-030"
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
    repair_reinstall_surface = $result.repair_reinstall_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-031"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-030 outputs." }

Write-Host "RC21 repair reinstall drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Repair reinstall evidence: $(Get-StablePath $repairEvidencePath)"
Write-Host "Repair reinstall audit record: $(Get-StablePath $auditRecordPath)"
Write-Host "Restored state: $($result.restored_target_state_id); boundary-only: true; host boot authority: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
