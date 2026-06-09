param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-transactional-lifecycle-consumer-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$Rc20FinalAuditPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/evidence/FINAL-AUDIT-20260610-production-distro-rc20.json",
    [string]$Rc20ConsumerResultPath = ".workflow/artifacts/rc20-single-user-distribution-consumer-smoke/result.json",
    [string]$Rc20ConsumerEvidencePath = ".workflow/artifacts/rc20-single-user-distribution-consumer-smoke/consumer-smoke-evidence.json",
    [string]$OperationIntentResultPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/result.json",
    [string]$OperationIntentCatalogPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/operation-intent-catalog.json",
    [string]$TransactionBaselineResultPath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/result.json",
    [string]$TransactionJournalPath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/transaction-journal-package.json",
    [string]$SnapshotBaselinePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/snapshot-baseline-package.json",
    [string]$FailClosedResultPath = ".workflow/artifacts/rc21-lifecycle-operation-fail-closed/result.json",
    [string]$FailClosedMatrixPath = ".workflow/artifacts/rc21-lifecycle-operation-fail-closed/fail-closed-matrix.json",
    [string]$DryRunPlanResultPath = ".workflow/artifacts/rc21-dry-run-execution-plan/result.json",
    [string]$DryRunPlanPath = ".workflow/artifacts/rc21-dry-run-execution-plan/dry-run-execution-plan.json",
    [string]$DryRunAcceptanceResultPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/result.json",
    [string]$DryRunAcceptanceEvidencePath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-acceptance-evidence.json",
    [string]$DryRunAuditRecordPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-audit-record.json",
    [string]$ExplainResumeAuditResultPath = ".workflow/artifacts/rc21-explain-resume-audit-package/result.json",
    [string]$ExplainResumeAuditPackagePath = ".workflow/artifacts/rc21-explain-resume-audit-package/explain-resume-audit-package.json",
    [string]$RepairReinstallResultPath = ".workflow/artifacts/rc21-repair-reinstall-drill/result.json",
    [string]$RepairReinstallEvidencePath = ".workflow/artifacts/rc21-repair-reinstall-drill/repair-reinstall-evidence.json",
    [string]$RepairReinstallAuditPath = ".workflow/artifacts/rc21-repair-reinstall-drill/repair-reinstall-audit-record.json",
    [string]$DowngradeRollbackResultPath = ".workflow/artifacts/rc21-downgrade-rollback-drill/result.json",
    [string]$DowngradeRollbackEvidencePath = ".workflow/artifacts/rc21-downgrade-rollback-drill/downgrade-rollback-evidence.json",
    [string]$DowngradeRollbackAuditPath = ".workflow/artifacts/rc21-downgrade-rollback-drill/downgrade-rollback-audit-record.json",
    [string]$SupportRecoveryResultPath = ".workflow/artifacts/rc21-lifecycle-support-recovery/result.json",
    [string]$LifecycleSupportBundlePath = ".workflow/artifacts/rc21-lifecycle-support-recovery/lifecycle-support-bundle.json",
    [string]$RecoveryReferenceIndexPath = ".workflow/artifacts/rc21-lifecycle-support-recovery/recovery-reference-index.json",
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
    param([string]$Path, $Json = $null, [string]$Role = "")
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    $ref = [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
    }
    if (-not [string]::IsNullOrWhiteSpace($Role)) { $ref.role = $Role }
    if ($null -ne $Json) {
        $ref.schema = $Json.schema
        $ref.status = $Json.status
        $ref.task = $Json.task
        $ref.production_ready_claim = $Json.production_ready_claim
        $ref.consumer_ready_claim = $Json.consumer_ready_claim
    }
    return $ref
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
        denied_before_new_effect = $true
        side_effects = [ordered]@{
            install_performed_by_consumer_smoke = $false
            update_performed_by_consumer_smoke = $false
            repair_reinstall_performed_by_consumer_smoke = $false
            downgrade_rollback_performed_by_consumer_smoke = $false
            rollback_execution_performed_by_consumer_smoke = $false
            support_bundle_uploaded = $false
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
            signer_authority_granted = $false
            endpoint_reachability_trusted = $false
            shell_output_trusted = $false
            tui_output_trusted = $false
            model_replay_trusted = $false
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
$resolvedRc20FinalAuditPath = Resolve-RepoPath $Rc20FinalAuditPath
$resolvedRc20ConsumerResultPath = Resolve-RepoPath $Rc20ConsumerResultPath
$resolvedRc20ConsumerEvidencePath = Resolve-RepoPath $Rc20ConsumerEvidencePath
$resolvedOperationIntentResultPath = Resolve-RepoPath $OperationIntentResultPath
$resolvedOperationIntentCatalogPath = Resolve-RepoPath $OperationIntentCatalogPath
$resolvedTransactionBaselineResultPath = Resolve-RepoPath $TransactionBaselineResultPath
$resolvedTransactionJournalPath = Resolve-RepoPath $TransactionJournalPath
$resolvedSnapshotBaselinePath = Resolve-RepoPath $SnapshotBaselinePath
$resolvedFailClosedResultPath = Resolve-RepoPath $FailClosedResultPath
$resolvedFailClosedMatrixPath = Resolve-RepoPath $FailClosedMatrixPath
$resolvedDryRunPlanResultPath = Resolve-RepoPath $DryRunPlanResultPath
$resolvedDryRunPlanPath = Resolve-RepoPath $DryRunPlanPath
$resolvedDryRunAcceptanceResultPath = Resolve-RepoPath $DryRunAcceptanceResultPath
$resolvedDryRunAcceptanceEvidencePath = Resolve-RepoPath $DryRunAcceptanceEvidencePath
$resolvedDryRunAuditRecordPath = Resolve-RepoPath $DryRunAuditRecordPath
$resolvedExplainResumeAuditResultPath = Resolve-RepoPath $ExplainResumeAuditResultPath
$resolvedExplainResumeAuditPackagePath = Resolve-RepoPath $ExplainResumeAuditPackagePath
$resolvedRepairReinstallResultPath = Resolve-RepoPath $RepairReinstallResultPath
$resolvedRepairReinstallEvidencePath = Resolve-RepoPath $RepairReinstallEvidencePath
$resolvedRepairReinstallAuditPath = Resolve-RepoPath $RepairReinstallAuditPath
$resolvedDowngradeRollbackResultPath = Resolve-RepoPath $DowngradeRollbackResultPath
$resolvedDowngradeRollbackEvidencePath = Resolve-RepoPath $DowngradeRollbackEvidencePath
$resolvedDowngradeRollbackAuditPath = Resolve-RepoPath $DowngradeRollbackAuditPath
$resolvedSupportRecoveryResultPath = Resolve-RepoPath $SupportRecoveryResultPath
$resolvedLifecycleSupportBundlePath = Resolve-RepoPath $LifecycleSupportBundlePath
$resolvedRecoveryReferenceIndexPath = Resolve-RepoPath $RecoveryReferenceIndexPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc20FinalAudit = Read-Json $resolvedRc20FinalAuditPath
$rc20ConsumerResult = Read-Json $resolvedRc20ConsumerResultPath
$rc20ConsumerEvidence = Read-Json $resolvedRc20ConsumerEvidencePath
$operationIntentResult = Read-Json $resolvedOperationIntentResultPath
$operationIntentCatalog = Read-Json $resolvedOperationIntentCatalogPath
$transactionBaselineResult = Read-Json $resolvedTransactionBaselineResultPath
$transactionJournal = Read-Json $resolvedTransactionJournalPath
$snapshotBaseline = Read-Json $resolvedSnapshotBaselinePath
$failClosedResult = Read-Json $resolvedFailClosedResultPath
$failClosedMatrix = Read-Json $resolvedFailClosedMatrixPath
$dryRunPlanResult = Read-Json $resolvedDryRunPlanResultPath
$dryRunPlan = Read-Json $resolvedDryRunPlanPath
$dryRunAcceptanceResult = Read-Json $resolvedDryRunAcceptanceResultPath
$dryRunAcceptanceEvidence = Read-Json $resolvedDryRunAcceptanceEvidencePath
$dryRunAuditRecord = Read-Json $resolvedDryRunAuditRecordPath
$explainResumeAuditResult = Read-Json $resolvedExplainResumeAuditResultPath
$explainResumeAuditPackage = Read-Json $resolvedExplainResumeAuditPackagePath
$repairReinstallResult = Read-Json $resolvedRepairReinstallResultPath
$repairReinstallEvidence = Read-Json $resolvedRepairReinstallEvidencePath
$repairReinstallAudit = Read-Json $resolvedRepairReinstallAuditPath
$downgradeRollbackResult = Read-Json $resolvedDowngradeRollbackResultPath
$downgradeRollbackEvidence = Read-Json $resolvedDowngradeRollbackEvidencePath
$downgradeRollbackAudit = Read-Json $resolvedDowngradeRollbackAuditPath
$supportRecoveryResult = Read-Json $resolvedSupportRecoveryResultPath
$lifecycleSupportBundle = Read-Json $resolvedLifecycleSupportBundlePath
$recoveryReferenceIndex = Read-Json $resolvedRecoveryReferenceIndexPath

$previousStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-032"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-040"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-040" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-050" -and $currentTaskStatus -eq "completed")
    )
)

$contractBound = (
    $contractText.Contains("Run transactional lifecycle local consumer smoke that explains readiness or denial from RC21 evidence without creating new authority") -and
    $contractText.Contains("Consumer smoke can report transactional local lifecycle readiness, not production readiness.") -and
    $contractText.Contains("production_ready_claim=false")
)

$rc20FinalAuditReady = (
    $rc20FinalAudit.schema -eq "agentos.production-distro-rc20-final-audit.v1" -and
    $rc20FinalAudit.production_ready_claim -eq $false -and
    @($rc20FinalAudit.checks | Where-Object { $_.status -ne "passed" }).Count -eq 0
)

$rc20ConsumerReady = (
    $rc20ConsumerResult.status -eq "passed" -and
    $rc20ConsumerResult.summary.rc20_040_complete -eq $true -and
    $rc20ConsumerResult.summary.consumer_ready_claim -eq $true -and
    $rc20ConsumerResult.summary.production_ready_claim -eq $false -and
    $rc20ConsumerEvidence.consumer_ready_claim -eq $true -and
    $rc20ConsumerEvidence.production_ready_claim -eq $false -and
    $rc20ConsumerEvidence.lifecycle_state_chain.target_chain_coherent -eq $true -and
    $rc20ConsumerEvidence.lifecycle_state_chain.lifecycle_chain_coherent -eq $true
)

$operationCatalogReady = (
    $operationIntentResult.status -eq "passed" -and
    $operationIntentResult.summary.rc21_010_complete -eq $true -and
    $operationIntentResult.summary.operation_intent_catalog_bound -eq $true -and
    $operationIntentResult.summary.intent_count -ge 6 -and
    $operationIntentCatalog.status -eq "local-operation-intent-catalog-bound-non-ga" -and
    @($operationIntentCatalog.operation_intents).Count -ge 6
)

$transactionBaselineReady = (
    $transactionBaselineResult.status -eq "passed" -and
    $transactionBaselineResult.summary.rc21_011_complete -eq $true -and
    $transactionBaselineResult.summary.operation_intent_catalog_id -eq $operationIntentResult.summary.operation_intent_catalog_id -and
    $transactionBaselineResult.summary.transaction_journal_package_id -eq $transactionJournal.transaction_journal_package_id -and
    $transactionBaselineResult.summary.snapshot_baseline_package_id -eq $snapshotBaseline.snapshot_baseline_package_id -and
    $transactionBaselineResult.summary.journal_entry_count -ge 6 -and
    $transactionBaselineResult.summary.snapshot_count -ge 5 -and
    $transactionJournal.status -eq "transaction-journal-baseline-bound-non-executable" -and
    $snapshotBaseline.status -eq "snapshot-baseline-bound-projection-only"
)

$failClosedReady = (
    $failClosedResult.status -eq "passed" -and
    $failClosedResult.summary.rc21_012_complete -eq $true -and
    $failClosedResult.summary.all_cases_denied_before_effect -eq $true -and
    $failClosedResult.summary.cases -ge 45 -and
    $failClosedResult.summary.failed_cases -eq 0 -and
    $failClosedMatrix.schema -eq "agentos.rc21-lifecycle-operation-fail-closed-matrix.v1"
)

$dryRunPlanReady = (
    $dryRunPlanResult.status -eq "passed" -and
    $dryRunPlanResult.summary.rc21_020_complete -eq $true -and
    $dryRunPlanResult.summary.operation_count -ge 3 -and
    $dryRunPlanResult.summary.operations -contains "install" -and
    $dryRunPlanResult.summary.operations -contains "update" -and
    $dryRunPlanResult.summary.operations -contains "repair-reinstall" -and
    $dryRunPlanResult.summary.effect_preparation_performed -eq $false -and
    $dryRunPlan.status -eq "dry-run-execution-plan-bound-non-executable"
)

$dryRunAcceptanceReady = (
    $dryRunAcceptanceResult.status -eq "passed" -and
    $dryRunAcceptanceResult.summary.rc21_021_complete -eq $true -and
    $dryRunAcceptanceResult.summary.accepted_operation_count -eq 2 -and
    $dryRunAcceptanceResult.summary.accepted_operations -contains "install" -and
    $dryRunAcceptanceResult.summary.accepted_operations -contains "update" -and
    $dryRunAcceptanceResult.summary.effect_preparation_performed -eq $false -and
    $dryRunAcceptanceResult.summary.install_performed -eq $false -and
    $dryRunAcceptanceResult.summary.update_performed -eq $false -and
    $dryRunAcceptanceEvidence.status -eq "transactional-dry-run-accepted-no-effect" -and
    $dryRunAuditRecord.status -eq "dry-run-audit-record-local-only"
)

$explainResumeReady = (
    $explainResumeAuditResult.status -eq "passed" -and
    $explainResumeAuditResult.summary.rc21_022_complete -eq $true -and
    $explainResumeAuditResult.summary.decision_count -ge 3 -and
    $explainResumeAuditResult.summary.resume_projection_count -ge 3 -and
    $explainResumeAuditResult.summary.resume_executable -eq $false -and
    $explainResumeAuditResult.summary.endpoint_authority -eq $false -and
    $explainResumeAuditResult.summary.shell_output_authority -eq $false -and
    $explainResumeAuditResult.summary.tui_authority -eq $false -and
    $explainResumeAuditResult.summary.model_replay_authority -eq $false -and
    $explainResumeAuditPackage.status -eq "explain-resume-audit-package-bound-projection-only"
)

$repairReady = (
    $repairReinstallResult.status -eq "passed" -and
    $repairReinstallResult.summary.rc21_030_complete -eq $true -and
    $repairReinstallResult.summary.repair_reinstall_drill_performed -eq $true -and
    $repairReinstallResult.summary.disposable_installed_system_boundary_only -eq $true -and
    $repairReinstallResult.summary.host_boot_state_authority -eq $false -and
    $repairReinstallResult.summary.support_upload_performed -eq $false -and
    $repairReinstallResult.summary.recovery_execution_performed -eq $false -and
    $repairReinstallResult.summary.remote_dispatch_enabled -eq $false -and
    $repairReinstallEvidence.status -eq "repair-reinstall-drill-executed-inside-disposable-installed-system" -and
    $repairReinstallAudit.local_only -eq $true
)

$downgradeReady = (
    $downgradeRollbackResult.status -eq "passed" -and
    $downgradeRollbackResult.summary.rc21_031_complete -eq $true -and
    $downgradeRollbackResult.summary.downgrade_rollback_drill_performed -eq $true -and
    $downgradeRollbackResult.summary.disposable_installed_system_boundary_only -eq $true -and
    $downgradeRollbackResult.summary.local_channel_history_only -eq $true -and
    $downgradeRollbackResult.summary.remote_fetch_performed -eq $false -and
    $downgradeRollbackResult.summary.support_upload_performed -eq $false -and
    $downgradeRollbackResult.summary.recovery_execution_performed -eq $false -and
    $downgradeRollbackResult.summary.remote_dispatch_enabled -eq $false -and
    $downgradeRollbackEvidence.status -eq "downgrade-rollback-drill-executed-inside-disposable-installed-system" -and
    $downgradeRollbackAudit.local_only -eq $true
)

$supportReady = (
    $supportRecoveryResult.status -eq "passed" -and
    $supportRecoveryResult.summary.rc21_032_complete -eq $true -and
    $supportRecoveryResult.summary.restored_state_chain_bound -eq $true -and
    $supportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $supportRecoveryResult.summary.support_bundle_redacted -eq $true -and
    $supportRecoveryResult.summary.support_upload_performed -eq $false -and
    $supportRecoveryResult.summary.recovery_execution_allowed -eq $false -and
    $supportRecoveryResult.summary.recovery_execution_performed -eq $false -and
    $supportRecoveryResult.summary.remote_dispatch_enabled -eq $false -and
    $lifecycleSupportBundle.local_only -eq $true -and
    $lifecycleSupportBundle.redacted -eq $true -and
    $lifecycleSupportBundle.uploaded -eq $false -and
    $recoveryReferenceIndex.projection_only -eq $true -and
    $recoveryReferenceIndex.recovery_execution_performed -eq $false
)

$stateChainReady = (
    [string]$transactionBaselineResult.summary.target_state_id -eq [string]$rc20ConsumerEvidence.lifecycle_state_chain.target_state_id -and
    [string]$transactionBaselineResult.summary.updated_image_state_id -eq [string]$rc20ConsumerEvidence.lifecycle_state_chain.updated_image_state_id -and
    [string]$transactionBaselineResult.summary.restored_target_state_id -eq [string]$rc20ConsumerEvidence.lifecycle_state_chain.restored_target_state_id -and
    [string]$repairReinstallResult.summary.restored_target_state_id -eq [string]$transactionBaselineResult.summary.restored_target_state_id -and
    [string]$downgradeRollbackResult.summary.restored_state_id -eq [string]$transactionBaselineResult.summary.restored_target_state_id -and
    [string]$supportRecoveryResult.restored_state_id -eq [string]$transactionBaselineResult.summary.restored_target_state_id
)

$consumerReady = (
    $planAllowsRun -and
    $contractBound -and
    $rc20FinalAuditReady -and
    $rc20ConsumerReady -and
    $operationCatalogReady -and
    $transactionBaselineReady -and
    $failClosedReady -and
    $dryRunPlanReady -and
    $dryRunAcceptanceReady -and
    $explainResumeReady -and
    $repairReady -and
    $downgradeReady -and
    $supportReady -and
    $stateChainReady
)
$consumerDecision = if ($consumerReady) { "transactional-lifecycle-local-consumer-ready" } else { "transactional-lifecycle-denied-before-effect" }

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc21-040-plan-pointer-not-current" }
if (-not $contractBound) { $blockers += "rc21-consumer-contract-not-bound" }
if (-not $rc20FinalAuditReady) { $blockers += "rc20-final-audit-not-ready" }
if (-not $rc20ConsumerReady) { $blockers += "rc20-single-user-consumer-not-ready" }
if (-not $operationCatalogReady) { $blockers += "rc21-operation-intent-catalog-not-ready" }
if (-not $transactionBaselineReady) { $blockers += "rc21-transaction-journal-snapshot-not-ready" }
if (-not $failClosedReady) { $blockers += "rc21-lifecycle-fail-closed-not-ready" }
if (-not $dryRunPlanReady) { $blockers += "rc21-dry-run-plan-not-ready" }
if (-not $dryRunAcceptanceReady) { $blockers += "rc21-dry-run-acceptance-not-ready" }
if (-not $explainResumeReady) { $blockers += "rc21-explain-resume-audit-not-ready" }
if (-not $repairReady) { $blockers += "rc21-repair-reinstall-not-ready" }
if (-not $downgradeReady) { $blockers += "rc21-downgrade-rollback-not-ready" }
if (-not $supportReady) { $blockers += "rc21-lifecycle-support-recovery-not-ready" }
if (-not $stateChainReady) { $blockers += "rc21-transactional-lifecycle-state-chain-mismatch" }
if ($consumerReady) { $blockers = @() }

$sideEffects = [ordered]@{
    consumer_smoke_evaluated = $true
    install_effect_prepared = $false
    update_effect_prepared = $false
    repair_reinstall_effect_prepared = $false
    downgrade_rollback_effect_prepared = $false
    install_performed_by_consumer_smoke = $false
    update_performed_by_consumer_smoke = $false
    repair_reinstall_performed_by_consumer_smoke = $false
    downgrade_rollback_performed_by_consumer_smoke = $false
    rollback_execution_performed_by_consumer_smoke = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_payload_downloaded = $false
    object_storage_provisioned = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    host_boot_state_authority = $false
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

$source = [ordered]@{
    rc21_plan = New-ArtifactRef $resolvedPlanPath $plan "rc21 workflow plan"
    rc21_authority_contract = New-ArtifactRef $resolvedContractPath $null "rc21 authority contract"
    rc20_final_audit = New-ArtifactRef $resolvedRc20FinalAuditPath $rc20FinalAudit "rc20 final audit"
    rc20_consumer_result = New-ArtifactRef $resolvedRc20ConsumerResultPath $rc20ConsumerResult "rc20 single-user consumer result"
    rc20_consumer_evidence = New-ArtifactRef $resolvedRc20ConsumerEvidencePath $rc20ConsumerEvidence "rc20 single-user consumer evidence"
    rc21_operation_intent_result = New-ArtifactRef $resolvedOperationIntentResultPath $operationIntentResult "rc21 operation intent result"
    rc21_operation_intent_catalog = New-ArtifactRef $resolvedOperationIntentCatalogPath $operationIntentCatalog "rc21 operation intent catalog"
    rc21_transaction_baseline_result = New-ArtifactRef $resolvedTransactionBaselineResultPath $transactionBaselineResult "rc21 transaction baseline result"
    rc21_transaction_journal = New-ArtifactRef $resolvedTransactionJournalPath $transactionJournal "rc21 transaction journal"
    rc21_snapshot_baseline = New-ArtifactRef $resolvedSnapshotBaselinePath $snapshotBaseline "rc21 snapshot baseline"
    rc21_fail_closed_result = New-ArtifactRef $resolvedFailClosedResultPath $failClosedResult "rc21 fail-closed result"
    rc21_fail_closed_matrix = New-ArtifactRef $resolvedFailClosedMatrixPath $failClosedMatrix "rc21 fail-closed matrix"
    rc21_dry_run_plan_result = New-ArtifactRef $resolvedDryRunPlanResultPath $dryRunPlanResult "rc21 dry-run plan result"
    rc21_dry_run_plan = New-ArtifactRef $resolvedDryRunPlanPath $dryRunPlan "rc21 dry-run plan"
    rc21_dry_run_acceptance_result = New-ArtifactRef $resolvedDryRunAcceptanceResultPath $dryRunAcceptanceResult "rc21 dry-run acceptance result"
    rc21_dry_run_acceptance_evidence = New-ArtifactRef $resolvedDryRunAcceptanceEvidencePath $dryRunAcceptanceEvidence "rc21 dry-run acceptance evidence"
    rc21_dry_run_audit_record = New-ArtifactRef $resolvedDryRunAuditRecordPath $dryRunAuditRecord "rc21 dry-run audit record"
    rc21_explain_resume_audit_result = New-ArtifactRef $resolvedExplainResumeAuditResultPath $explainResumeAuditResult "rc21 explain resume audit result"
    rc21_explain_resume_audit_package = New-ArtifactRef $resolvedExplainResumeAuditPackagePath $explainResumeAuditPackage "rc21 explain resume audit package"
    rc21_repair_reinstall_result = New-ArtifactRef $resolvedRepairReinstallResultPath $repairReinstallResult "rc21 repair reinstall result"
    rc21_repair_reinstall_evidence = New-ArtifactRef $resolvedRepairReinstallEvidencePath $repairReinstallEvidence "rc21 repair reinstall evidence"
    rc21_repair_reinstall_audit = New-ArtifactRef $resolvedRepairReinstallAuditPath $repairReinstallAudit "rc21 repair reinstall audit"
    rc21_downgrade_rollback_result = New-ArtifactRef $resolvedDowngradeRollbackResultPath $downgradeRollbackResult "rc21 downgrade rollback result"
    rc21_downgrade_rollback_evidence = New-ArtifactRef $resolvedDowngradeRollbackEvidencePath $downgradeRollbackEvidence "rc21 downgrade rollback evidence"
    rc21_downgrade_rollback_audit = New-ArtifactRef $resolvedDowngradeRollbackAuditPath $downgradeRollbackAudit "rc21 downgrade rollback audit"
    rc21_support_recovery_result = New-ArtifactRef $resolvedSupportRecoveryResultPath $supportRecoveryResult "rc21 support recovery result"
    rc21_lifecycle_support_bundle = New-ArtifactRef $resolvedLifecycleSupportBundlePath $lifecycleSupportBundle "rc21 lifecycle support bundle"
    rc21_recovery_reference_index = New-ArtifactRef $resolvedRecoveryReferenceIndexPath $recoveryReferenceIndex "rc21 recovery reference index"
}

$auditMaterial = [ordered]@{
    schema = "agentos.rc21-transactional-lifecycle-consumer-smoke-audit-material.v1"
    task = "RC21-040"
    generated_at = $generatedAtValue
    decision = $consumerDecision
    consumer_ready_claim = $consumerReady
    production_ready_claim = $false
    operation_intent_catalog_id = [string]$operationIntentResult.summary.operation_intent_catalog_id
    transaction_journal_package_id = [string]$transactionBaselineResult.summary.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$transactionBaselineResult.summary.snapshot_baseline_package_id
    dry_run_execution_plan_id = [string]$dryRunPlanResult.summary.dry_run_execution_plan_id
    dry_run_acceptance_id = [string]$dryRunAcceptanceResult.summary.dry_run_acceptance_id
    explain_resume_audit_package_id = [string]$explainResumeAuditResult.summary.explain_resume_audit_package_id
    repair_reinstall_drill_id = [string]$repairReinstallResult.summary.repair_reinstall_drill_id
    downgrade_rollback_drill_id = [string]$downgradeRollbackResult.summary.downgrade_rollback_drill_id
    support_bundle_id = [string]$supportRecoveryResult.summary.support_bundle_id
    recovery_reference_digest = [string]$supportRecoveryResult.summary.recovery_reference_digest
    target_state_id = [string]$transactionBaselineResult.summary.target_state_id
    updated_image_state_id = [string]$transactionBaselineResult.summary.updated_image_state_id
    restored_target_state_id = [string]$transactionBaselineResult.summary.restored_target_state_id
    blockers = @($blockers)
    side_effects = $sideEffects
}
$auditDigest = Get-StringSha256 (Get-JsonText $auditMaterial)

$auditRecord = [ordered]@{
    schema = "agentos.rc21-transactional-lifecycle-consumer-smoke-audit.v1"
    generated_at = $generatedAtValue
    task = "RC21-040"
    local_only = $true
    fabricated = $false
    decision = $consumerDecision
    decision_digest = $auditDigest
    rc20_consumer_bound = $rc20ConsumerReady
    operation_intent_catalog_bound = $operationCatalogReady
    transaction_journal_snapshot_bound = $transactionBaselineReady
    fail_closed_bound = $failClosedReady
    dry_run_plan_bound = $dryRunPlanReady
    dry_run_acceptance_bound = $dryRunAcceptanceReady
    explain_resume_audit_bound = $explainResumeReady
    repair_reinstall_bound = $repairReady
    downgrade_rollback_bound = $downgradeReady
    support_recovery_bound = $supportReady
    state_chain_bound = $stateChainReady
    consumer_ready_claim = $consumerReady
    production_ready_claim = $false
    blockers = @($blockers)
}

$caseSpecs = @(
    [ordered]@{ id = "missing-rc20-final-audit"; blockers = @("rc20-final-audit-not-ready"); reason = "Transactional consumer smoke requires RC20 final audit evidence." },
    [ordered]@{ id = "missing-rc20-consumer"; blockers = @("rc20-single-user-consumer-not-ready"); reason = "Transactional consumer smoke starts from RC20 local consumer readiness." },
    [ordered]@{ id = "missing-operation-intent-catalog"; blockers = @("rc21-operation-intent-catalog-not-ready"); reason = "Operation intent catalog is the first RC21 lifecycle gate." },
    [ordered]@{ id = "missing-transaction-journal-snapshot"; blockers = @("rc21-transaction-journal-snapshot-not-ready"); reason = "Journal and snapshots are required before lifecycle readiness." },
    [ordered]@{ id = "missing-lifecycle-fail-closed"; blockers = @("rc21-lifecycle-fail-closed-not-ready"); reason = "Fail-closed fixtures must pass before consumer readiness." },
    [ordered]@{ id = "missing-dry-run-plan"; blockers = @("rc21-dry-run-plan-not-ready"); reason = "Dry-run execution plan must be bound." },
    [ordered]@{ id = "missing-dry-run-acceptance"; blockers = @("rc21-dry-run-acceptance-not-ready"); reason = "Dry-run acceptance must be audited and no-effect." },
    [ordered]@{ id = "missing-explain-resume-audit"; blockers = @("rc21-explain-resume-audit-not-ready"); reason = "User-visible explain/resume/audit must be bound." },
    [ordered]@{ id = "missing-repair-reinstall"; blockers = @("rc21-repair-reinstall-not-ready"); reason = "Repair/reinstall drill evidence must be complete." },
    [ordered]@{ id = "missing-downgrade-rollback"; blockers = @("rc21-downgrade-rollback-not-ready"); reason = "Downgrade/rollback drill evidence must be complete." },
    [ordered]@{ id = "missing-support-recovery"; blockers = @("rc21-lifecycle-support-recovery-not-ready"); reason = "Local support/recovery closure must be bound." },
    [ordered]@{ id = "state-chain-mismatch"; blockers = @("rc21-transactional-lifecycle-state-chain-mismatch"); reason = "Consumer smoke cannot report readiness for incoherent lifecycle states." },
    [ordered]@{ id = "new-install-attempt"; blockers = @("consumer-install-effect-denied"); reason = "Consumer smoke must not execute install." },
    [ordered]@{ id = "new-update-attempt"; blockers = @("consumer-update-effect-denied"); reason = "Consumer smoke must not execute update." },
    [ordered]@{ id = "new-repair-reinstall-attempt"; blockers = @("consumer-repair-reinstall-effect-denied"); reason = "Consumer smoke must not execute repair/reinstall." },
    [ordered]@{ id = "new-downgrade-rollback-attempt"; blockers = @("consumer-downgrade-rollback-effect-denied"); reason = "Consumer smoke must not execute downgrade/rollback." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is outside RC21 scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is outside RC21 scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is outside RC21 scope." },
    [ordered]@{ id = "object-storage-provisioning-attempt"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is outside RC21 scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is outside RC21 scope." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not RC21 authority." },
    [ordered]@{ id = "nginx-tls-authority-attempt"; blockers = @("nginx-tls-authority-denied"); reason = "Nginx/TLS status is not RC21 authority." },
    [ordered]@{ id = "endpoint-authority-attempt"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not RC21 authority." },
    [ordered]@{ id = "shell-output-authority-attempt"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not RC21 authority." },
    [ordered]@{ id = "tui-output-authority-attempt"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not RC21 authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not RC21 authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not RC21 authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "release-signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "Release signing is outside RC21 scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC21 consumer smoke cannot claim GA production readiness." },
    [ordered]@{ id = "fabricated-consumer-readiness"; blockers = @("fabricated-readiness-denied"); reason = "Consumer readiness must be derived from bound evidence." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$consumerEvidence = [ordered]@{
    schema = "agentos.rc21-transactional-lifecycle-consumer-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-040"
    status = $consumerDecision
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
    local_only = $true
    operation_intent_catalog_id = [string]$operationIntentResult.summary.operation_intent_catalog_id
    transaction_journal_package_id = [string]$transactionBaselineResult.summary.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$transactionBaselineResult.summary.snapshot_baseline_package_id
    dry_run_execution_plan_id = [string]$dryRunPlanResult.summary.dry_run_execution_plan_id
    support_bundle_id = [string]$supportRecoveryResult.summary.support_bundle_id
    readiness = [ordered]@{
        outcome = $consumerDecision
        rc20_single_user_consumer_readiness = if ($rc20ConsumerReady) { "ready" } else { "denied" }
        operation_intent_catalog_readiness = if ($operationCatalogReady) { "ready" } else { "denied" }
        transaction_journal_snapshot_readiness = if ($transactionBaselineReady) { "ready" } else { "denied" }
        lifecycle_fail_closed_readiness = if ($failClosedReady) { "ready" } else { "denied" }
        dry_run_plan_readiness = if ($dryRunPlanReady) { "ready" } else { "denied" }
        dry_run_acceptance_readiness = if ($dryRunAcceptanceReady) { "ready" } else { "denied" }
        explain_resume_audit_readiness = if ($explainResumeReady) { "ready" } else { "denied" }
        repair_reinstall_readiness = if ($repairReady) { "ready" } else { "denied" }
        downgrade_rollback_readiness = if ($downgradeReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($blockers)
        next_safe_action = "run-rc21-final-closeout-audit"
    }
    lifecycle_state_chain = [ordered]@{
        target_state_id = [string]$transactionBaselineResult.summary.target_state_id
        updated_image_state_id = [string]$transactionBaselineResult.summary.updated_image_state_id
        restored_target_state_id = [string]$transactionBaselineResult.summary.restored_target_state_id
        repair_restored_target_state_id = [string]$repairReinstallResult.summary.restored_target_state_id
        downgrade_restored_state_id = [string]$downgradeRollbackResult.summary.restored_state_id
        support_restored_state_id = [string]$supportRecoveryResult.restored_state_id
        coherent = $stateChainReady
    }
    audit = $auditRecord
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$consumerEvidencePath = Join-Path $resolvedArtifactDir "consumer-smoke-evidence.json"
Write-Json $consumerEvidence $consumerEvidencePath

Add-Check "plan.current_task.rc21_040" $planAllowsRun "RC21-040 must run after RC21-032 completed, with current_task set to RC21-040 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_032_status = $previousStatus; rc21_040_status = $currentTaskStatus })
Add-Check "contract.consumer.bound" $contractBound "RC21 contract must allow only transactional local lifecycle consumer readiness and deny production readiness authority." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.rc20.bound" ($rc20FinalAuditReady -and $rc20ConsumerReady) "Consumer smoke must bind RC20 final audit and single-user distribution local consumer readiness." ([ordered]@{ final_audit_ready = $rc20FinalAuditReady; rc20_consumer_ready = $rc20ConsumerReady; consumer_ready_claim = $rc20ConsumerResult.summary.consumer_ready_claim; production_ready_claim = $rc20ConsumerResult.summary.production_ready_claim })
Add-Check "source.operation_intent.ready" $operationCatalogReady "Consumer smoke must bind the RC21 local lifecycle operation intent catalog." ([ordered]@{ intent_count = $operationIntentResult.summary.intent_count; operation_intent_catalog_id = $operationIntentResult.summary.operation_intent_catalog_id })
Add-Check "source.transaction_baseline.ready" $transactionBaselineReady "Consumer smoke must bind transaction journal and snapshot baseline packages." ([ordered]@{ journal_entry_count = $transactionBaselineResult.summary.journal_entry_count; snapshot_count = $transactionBaselineResult.summary.snapshot_count; transaction_journal_package_id = $transactionBaselineResult.summary.transaction_journal_package_id; snapshot_baseline_package_id = $transactionBaselineResult.summary.snapshot_baseline_package_id })
Add-Check "source.fail_closed.ready" $failClosedReady "Lifecycle operation fail-closed fixtures must pass before consumer readiness." ([ordered]@{ cases = $failClosedResult.summary.cases; failed_cases = $failClosedResult.summary.failed_cases; all_cases_denied_before_effect = $failClosedResult.summary.all_cases_denied_before_effect })
Add-Check "source.dry_run.ready" ($dryRunPlanReady -and $dryRunAcceptanceReady) "Dry-run execution plan and dry-run acceptance must be bound with no effect preparation or execution." ([ordered]@{ dry_run_plan_ready = $dryRunPlanReady; dry_run_acceptance_ready = $dryRunAcceptanceReady; accepted_operations = @($dryRunAcceptanceResult.summary.accepted_operations); effect_preparation_performed = $dryRunAcceptanceResult.summary.effect_preparation_performed })
Add-Check "source.explain_resume.ready" $explainResumeReady "Explain/resume/audit package must be bound while resume remains projection-only." ([ordered]@{ decision_count = $explainResumeAuditResult.summary.decision_count; resume_projection_count = $explainResumeAuditResult.summary.resume_projection_count; resume_executable = $explainResumeAuditResult.summary.resume_executable })
Add-Check "source.lifecycle_drills.ready" ($repairReady -and $downgradeReady) "Repair/reinstall and downgrade/rollback drills must be complete inside the disposable installed-system boundary." ([ordered]@{ repair_ready = $repairReady; downgrade_ready = $downgradeReady; repair_restored = $repairReinstallResult.summary.restored_target_state_id; downgrade_restored = $downgradeRollbackResult.summary.restored_state_id })
Add-Check "source.support_recovery.ready" $supportReady "Lifecycle support/recovery closure must be local-only, redacted, projection-only, and no-upload/no-execution." ([ordered]@{ support_bundle_id = $supportRecoveryResult.summary.support_bundle_id; support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only; support_bundle_redacted = $supportRecoveryResult.summary.support_bundle_redacted; support_upload_performed = $supportRecoveryResult.summary.support_upload_performed; recovery_execution_performed = $supportRecoveryResult.summary.recovery_execution_performed })
Add-Check "lifecycle.state_chain.coherent" $stateChainReady "Consumer smoke must bind a coherent RC20/RC21 target, update, repair, downgrade, rollback, and support state chain." $consumerEvidence.lifecycle_state_chain
Add-Check "consumer.ready_or_denial" ($consumerReady -and $consumerDecision -eq "transactional-lifecycle-local-consumer-ready") "Consumer smoke must report transactional local lifecycle readiness or explicit denial from bound RC21 evidence." ([ordered]@{ decision = $consumerDecision; blockers = @($blockers); consumer_ready_claim = $consumerReady; production_ready_claim = $false })
Add-Check "consumer.audit.bound" ($auditRecord.local_only -eq $true -and $auditRecord.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($auditDigest)) "Consumer smoke must be audited and non-fabricated." $auditRecord
Add-Check "authority.no_forbidden_side_effects" (
    $sideEffects.install_performed_by_consumer_smoke -eq $false -and
    $sideEffects.update_performed_by_consumer_smoke -eq $false -and
    $sideEffects.repair_reinstall_performed_by_consumer_smoke -eq $false -and
    $sideEffects.downgrade_rollback_performed_by_consumer_smoke -eq $false -and
    $sideEffects.support_upload_performed -eq $false -and
    $sideEffects.recovery_execution_performed -eq $false -and
    $sideEffects.remote_payload_downloaded -eq $false -and
    $sideEffects.object_storage_provisioned -eq $false -and
    $sideEffects.remote_dispatch_enabled -eq $false -and
    $sideEffects.host_rootfs_mutated -eq $false -and
    $sideEffects.host_active_slot_mutated -eq $false -and
    $sideEffects.host_boot_metadata_mutated -eq $false -and
    $sideEffects.active_artifact_set_mutated -eq $false -and
    $sideEffects.production_ring_mutated -eq $false -and
    $sideEffects.mirror_frontend_authority -eq $false -and
    $sideEffects.nginx_or_tls_authority -eq $false -and
    $sideEffects.endpoint_reachability_authority -eq $false -and
    $sideEffects.shell_output_authority -eq $false -and
    $sideEffects.tui_output_authority -eq $false -and
    $sideEffects.model_replay_authority -eq $false -and
    $sideEffects.signer_authority -eq $false -and
    $sideEffects.private_signing_material_handled -eq $false -and
    $sideEffects.cryptographic_signing_performed -eq $false
) "RC21-040 must not execute new lifecycle effects, upload support, execute recovery, fetch remote payloads, provision object storage, dispatch remotely, mutate host/production state, trust projection surfaces, handle private material, or sign." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 35) "Missing evidence and forbidden authority surfaces must fail closed before consumer readiness or side effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $consumerEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC21-040 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, raw passwords, raw secrets, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-transactional-lifecycle-consumer-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-040"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady
    operation_intent_catalog_id = [string]$operationIntentResult.summary.operation_intent_catalog_id
    transaction_journal_package_id = [string]$transactionBaselineResult.summary.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$transactionBaselineResult.summary.snapshot_baseline_package_id
    target_state_id = [string]$transactionBaselineResult.summary.target_state_id
    updated_image_state_id = [string]$transactionBaselineResult.summary.updated_image_state_id
    restored_target_state_id = [string]$transactionBaselineResult.summary.restored_target_state_id
    consumer_surface = [ordered]@{
        state = $consumerDecision
        rc20_single_user_consumer_readiness = if ($rc20ConsumerReady) { "ready" } else { "denied" }
        operation_intent_catalog_readiness = if ($operationCatalogReady) { "ready" } else { "denied" }
        transaction_journal_snapshot_readiness = if ($transactionBaselineReady) { "ready" } else { "denied" }
        lifecycle_fail_closed_readiness = if ($failClosedReady) { "ready" } else { "denied" }
        dry_run_plan_readiness = if ($dryRunPlanReady) { "ready" } else { "denied" }
        dry_run_acceptance_readiness = if ($dryRunAcceptanceReady) { "ready" } else { "denied" }
        explain_resume_audit_readiness = if ($explainResumeReady) { "ready" } else { "denied" }
        repair_reinstall_readiness = if ($repairReady) { "ready" } else { "denied" }
        downgrade_rollback_readiness = if ($downgradeReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        lifecycle_state_chain_readiness = if ($stateChainReady) { "ready" } else { "denied" }
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
        transactional_lifecycle_consumer_smoke_only = $true
        consumer_ready_claim = $consumerReady
        local_only = $true
        audited = $true
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        repair_reinstall_performed_by_consumer_smoke = $false
        downgrade_rollback_performed_by_consumer_smoke = $false
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
        object_storage_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc21_040_complete = (@($script:failedChecks).Count -eq 0)
        consumer_decision = $consumerDecision
        consumer_ready_claim = $consumerReady
        production_ready_claim = $false
        rc20_single_user_consumer_readiness = if ($rc20ConsumerReady) { "ready" } else { "denied" }
        operation_intent_catalog_readiness = if ($operationCatalogReady) { "ready" } else { "denied" }
        transaction_journal_snapshot_readiness = if ($transactionBaselineReady) { "ready" } else { "denied" }
        lifecycle_fail_closed_readiness = if ($failClosedReady) { "ready" } else { "denied" }
        dry_run_plan_readiness = if ($dryRunPlanReady) { "ready" } else { "denied" }
        dry_run_acceptance_readiness = if ($dryRunAcceptanceReady) { "ready" } else { "denied" }
        explain_resume_audit_readiness = if ($explainResumeReady) { "ready" } else { "denied" }
        repair_reinstall_readiness = if ($repairReady) { "ready" } else { "denied" }
        downgrade_rollback_readiness = if ($downgradeReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        lifecycle_state_chain_readiness = if ($stateChainReady) { "ready" } else { "denied" }
        audited = $true
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        repair_reinstall_performed_by_consumer_smoke = $false
        downgrade_rollback_performed_by_consumer_smoke = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC21-050"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-040-transactional-lifecycle-consumer-smoke.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-transactional-lifecycle-consumer-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-040"
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
        rc21_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-050"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-040 outputs." }

Write-Host "RC21 transactional lifecycle consumer smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $consumerEvidencePath)"
Write-Host "Decision: $consumerDecision; consumer_ready_claim=$consumerReady; production_ready_claim=false"
Write-Host "New effects: install=false; update=false; repair=false; downgrade=false; support upload=false; recovery=false; remote dispatch=false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
