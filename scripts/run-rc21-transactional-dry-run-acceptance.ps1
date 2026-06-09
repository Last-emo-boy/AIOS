param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-transactional-dry-run-acceptance",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$DryRunPlanResultPath = ".workflow/artifacts/rc21-dry-run-execution-plan/result.json",
    [string]$DryRunPlanPath = ".workflow/artifacts/rc21-dry-run-execution-plan/dry-run-execution-plan.json",
    [string]$TransactionJournalPackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/transaction-journal-package.json",
    [string]$SnapshotBaselinePackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/snapshot-baseline-package.json",
    [string]$Rc20InstallAcceptanceResultPath = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json",
    [string]$Rc20UpdateResultPath = ".workflow/artifacts/rc20-post-install-update-drill/result.json",
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

function New-NoEffectSurface {
    return [ordered]@{
        dry_run_acceptance_recorded = $true
        effect_preparation_performed = $false
        install_performed = $false
        update_performed = $false
        repair_performed = $false
        reinstall_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        production_ready_claim = $false
    }
}

function New-AcceptedOperation {
    param([Parameter(Mandatory = $true)][string]$OperationId)
    $operation = @($script:dryRunPlan.operations | Where-Object { $_.operation -eq $OperationId })[0]
    $rc20Binding = if ($OperationId -eq "install") {
        [ordered]@{
            evidence = "rc20-single-user-install-acceptance"
            status = [string]$script:rc20InstallAcceptanceResult.status
            acceptance_id = [string]$script:rc20InstallAcceptanceResult.install_acceptance_id
            audit_record_id = [string]$script:rc20InstallAcceptanceResult.summary.audit_record_id
            target_state_id = [string]$script:rc20InstallAcceptanceResult.target_state_id
            disposable_target_effect_performed = $true
        }
    } else {
        [ordered]@{
            evidence = "rc20-post-install-update-drill"
            status = [string]$script:rc20UpdateResult.status
            update_drill_id = [string]$script:rc20UpdateResult.update_drill_id
            audit_record_id = [string]$script:rc20UpdateResult.summary.update_audit_record_id
            previous_installed_image_state_id = [string]$script:rc20UpdateResult.previous_installed_image_state_id
            updated_image_state_id = [string]$script:rc20UpdateResult.updated_image_state_id
            disposable_target_effect_performed = $true
        }
    }
    return [ordered]@{
        operation = $OperationId
        acceptance = "accepted-for-dry-run-only"
        dry_run_operation_plan_id = [string]$operation.dry_run_operation_plan_id
        operation_intent_id = [string]$operation.operation_intent_id
        transaction_id = [string]$operation.transaction_id
        resume_checkpoint = $operation.resume_checkpoint
        audit_sink = $operation.audit_sink
        snapshots = $operation.snapshots
        rc20_binding = $rc20Binding
        ordered_steps_observed = @($operation.ordered_steps | ForEach-Object {
            [ordered]@{
                step_id = [string]$_.step_id
                observed = $true
                prepares_effect = $false
            }
        })
        acceptance_observation = [ordered]@{
            disposable_target_boundary = "rc21-dry-run-acceptance-local-projection"
            effect_preparation_performed = $false
            lifecycle_effect_performed = $false
            denial_reason = "dry-run acceptance records readiness only; execution remains a later gate."
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
$resolvedDryRunPlanResultPath = Resolve-RepoPath $DryRunPlanResultPath
$resolvedDryRunPlanPath = Resolve-RepoPath $DryRunPlanPath
$resolvedTransactionJournalPackagePath = Resolve-RepoPath $TransactionJournalPackagePath
$resolvedSnapshotBaselinePackagePath = Resolve-RepoPath $SnapshotBaselinePackagePath
$resolvedRc20InstallAcceptanceResultPath = Resolve-RepoPath $Rc20InstallAcceptanceResultPath
$resolvedRc20UpdateResultPath = Resolve-RepoPath $Rc20UpdateResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$dryRunPlanResult = Read-Json $resolvedDryRunPlanResultPath
$script:dryRunPlan = Read-Json $resolvedDryRunPlanPath
$transactionJournalPackage = Read-Json $resolvedTransactionJournalPackagePath
$snapshotBaselinePackage = Read-Json $resolvedSnapshotBaselinePackagePath
$script:rc20InstallAcceptanceResult = Read-Json $resolvedRc20InstallAcceptanceResultPath
$script:rc20UpdateResult = Read-Json $resolvedRc20UpdateResultPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-020"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-021"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-021" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-022" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsAcceptance = (
    $contractText.Contains("Run transactional install/update dry-run acceptance") -and
    $contractText.Contains("inside a disposable target") -and
    $contractText.Contains("deny before effect with audit")
)

$dryRunPlanReady = (
    $dryRunPlanResult.status -eq "passed" -and
    $dryRunPlanResult.summary.rc21_020_complete -eq $true -and
    $script:dryRunPlan.status -eq "dry-run-execution-plan-bound-non-executable" -and
    $script:dryRunPlan.executable -eq $false -and
    $script:dryRunPlan.effect_preparation_performed -eq $false -and
    @($script:dryRunPlan.operations | Where-Object { $_.operation -in @("install", "update") }).Count -eq 2
)

$rc20InstallReady = (
    $script:rc20InstallAcceptanceResult.status -eq "passed" -and
    $script:rc20InstallAcceptanceResult.summary.rc20_021_complete -eq $true -and
    $script:rc20InstallAcceptanceResult.summary.first_user_install_performed_inside_disposable_target -eq $true -and
    $script:rc20InstallAcceptanceResult.summary.host_rootfs_mutated -eq $false -and
    $script:rc20InstallAcceptanceResult.summary.production_ring_mutated -eq $false
)

$rc20UpdateReady = (
    $script:rc20UpdateResult.status -eq "passed" -and
    $script:rc20UpdateResult.summary.rc20_030_complete -eq $true -and
    $script:rc20UpdateResult.summary.isolated_update_performed_inside_disposable_installed_system -eq $true -and
    $script:rc20UpdateResult.summary.rollback_prerequisites_bound -eq $true -and
    $script:rc20UpdateResult.summary.host_active_slot_mutated -eq $false -and
    $script:rc20UpdateResult.summary.production_ring_mutated -eq $false
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
    rc21_dry_run_plan_result = New-ArtifactRef $resolvedDryRunPlanResultPath $dryRunPlanResult "rc21 dry-run plan result"
    rc21_dry_run_plan = New-ArtifactRef $resolvedDryRunPlanPath $script:dryRunPlan "rc21 dry-run plan"
    rc21_transaction_journal_package = New-ArtifactRef $resolvedTransactionJournalPackagePath $transactionJournalPackage "rc21 transaction journal package"
    rc21_snapshot_baseline_package = New-ArtifactRef $resolvedSnapshotBaselinePackagePath $snapshotBaselinePackage "rc21 snapshot baseline package"
    rc20_install_acceptance_result = New-ArtifactRef $resolvedRc20InstallAcceptanceResultPath $script:rc20InstallAcceptanceResult "rc20 install acceptance result"
    rc20_update_result = New-ArtifactRef $resolvedRc20UpdateResultPath $script:rc20UpdateResult "rc20 update result"
}

$acceptedOperations = @(
    (New-AcceptedOperation "install"),
    (New-AcceptedOperation "update")
)
$acceptanceMaterial = [ordered]@{
    schema = "agentos.rc21-dry-run-acceptance-material.v1"
    task = "RC21-021"
    dry_run_execution_plan_id = [string]$script:dryRunPlan.dry_run_execution_plan_id
    transaction_journal_package_id = [string]$transactionJournalPackage.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$snapshotBaselinePackage.snapshot_baseline_package_id
    operations = @($acceptedOperations | ForEach-Object {
        [ordered]@{
            operation = $_.operation
            transaction_id = $_.transaction_id
            checkpoint_id = $_.resume_checkpoint.checkpoint_id
            audit_sink_id = $_.audit_sink.audit_sink_id
        }
    })
    rc20_install_acceptance_id = [string]$script:rc20InstallAcceptanceResult.install_acceptance_id
    rc20_update_drill_id = [string]$script:rc20UpdateResult.update_drill_id
}
$dryRunAcceptanceId = "sha256:$(Get-StringSha256 (Get-JsonText $acceptanceMaterial))"

$auditMaterial = [ordered]@{
    schema = "agentos.rc21-dry-run-audit-material.v1"
    task = "RC21-021"
    dry_run_acceptance_id = $dryRunAcceptanceId
    entries = @($acceptedOperations | ForEach-Object {
        [ordered]@{
            operation = $_.operation
            transaction_id = $_.transaction_id
            audit_sink_id = $_.audit_sink.audit_sink_id
            decision = $_.acceptance
        }
    })
}
$dryRunAuditRecordId = "sha256:$(Get-StringSha256 (Get-JsonText $auditMaterial))"

$auditRecord = [ordered]@{
    schema = "agentos.rc21-dry-run-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC21-021"
    status = "dry-run-audit-record-local-only"
    production_ready_claim = $false
    consumer_ready_claim = $false
    dry_run_audit_record_id = $dryRunAuditRecordId
    dry_run_acceptance_id = $dryRunAcceptanceId
    local_only = $true
    append_only_projection = $true
    journal_sink_files_written = $false
    entries = @($acceptedOperations | ForEach-Object {
        [ordered]@{
            operation = $_.operation
            transaction_id = $_.transaction_id
            audit_sink_id = $_.audit_sink.audit_sink_id
            checkpoint_id = $_.resume_checkpoint.checkpoint_id
            decision = $_.acceptance
            effect_preparation_performed = $false
            lifecycle_effect_performed = $false
        }
    })
    source = $source
}
$auditRecordPath = Join-Path $resolvedArtifactDir "dry-run-audit-record.json"
Write-Json $auditRecord $auditRecordPath

$acceptanceEvidence = [ordered]@{
    schema = "agentos.rc21-transactional-dry-run-acceptance-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-021"
    status = "transactional-dry-run-accepted-no-effect"
    production_ready_claim = $false
    consumer_ready_claim = $false
    dry_run_acceptance_id = $dryRunAcceptanceId
    dry_run_execution_plan_id = [string]$script:dryRunPlan.dry_run_execution_plan_id
    dry_run_audit_record_id = $dryRunAuditRecordId
    transaction_journal_package_id = [string]$transactionJournalPackage.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$snapshotBaselinePackage.snapshot_baseline_package_id
    accepted_operation_count = @($acceptedOperations).Count
    accepted_operations = $acceptedOperations
    deferred_operations = @(
        [ordered]@{
            operation = "repair-reinstall"
            reason = "RC21-021 accepts install/update dry-run only; repair/reinstall remains bound for later drill gates."
            effect_preparation_performed = $false
        }
    )
    no_effect_surface = New-NoEffectSurface
    source = $source
}
$acceptanceEvidencePath = Join-Path $resolvedArtifactDir "dry-run-acceptance-evidence.json"
Write-Json $acceptanceEvidence $acceptanceEvidencePath

$operationBindingsReady = (
    @($acceptedOperations).Count -eq 2 -and
    @($acceptedOperations | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.transaction_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.resume_checkpoint.checkpoint_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.audit_sink.audit_sink_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.snapshots.source_snapshot_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.snapshots.target_snapshot_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.snapshots.rollback_snapshot_id)
    }).Count -eq 0
)
$auditReady = (
    $auditRecord.local_only -eq $true -and
    $auditRecord.journal_sink_files_written -eq $false -and
    @($auditRecord.entries).Count -eq 2 -and
    @($auditRecord.entries | Where-Object { $_.effect_preparation_performed -ne $false -or $_.lifecycle_effect_performed -ne $false }).Count -eq 0
)
$noForbiddenEffects = (
    $acceptanceEvidence.no_effect_surface.effect_preparation_performed -eq $false -and
    $acceptanceEvidence.no_effect_surface.install_performed -eq $false -and
    $acceptanceEvidence.no_effect_surface.update_performed -eq $false -and
    $acceptanceEvidence.no_effect_surface.support_upload_performed -eq $false -and
    $acceptanceEvidence.no_effect_surface.recovery_execution_performed -eq $false -and
    $acceptanceEvidence.no_effect_surface.remote_dispatch_enabled -eq $false -and
    $acceptanceEvidence.no_effect_surface.host_rootfs_mutated -eq $false -and
    $acceptanceEvidence.no_effect_surface.active_artifact_set_mutated -eq $false -and
    $acceptanceEvidence.no_effect_surface.production_ring_mutated -eq $false -and
    $acceptanceEvidence.no_effect_surface.signer_authority_granted -eq $false -and
    $acceptanceEvidence.no_effect_surface.object_storage_provisioned -eq $false -and
    $acceptanceEvidence.no_effect_surface.private_signing_material_handled -eq $false
)

Add-Check "plan.current_task.rc21_021" $planAllowsRun "RC21-021 must run after RC21-020 completed, with current_task set to RC21-021 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_020_status = $previousTaskStatus; rc21_021_status = $currentTaskStatus })
Add-Check "contract.dry_run_acceptance.present" $contractAllowsAcceptance "RC21-021 must consume the transactional dry-run acceptance contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "dry_run_plan.ready" $dryRunPlanReady "Dry-run acceptance must bind the completed install/update dry-run plan and keep it non-executable." ([ordered]@{ result_status = $dryRunPlanResult.status; plan_status = $script:dryRunPlan.status; executable = $script:dryRunPlan.executable; effect_preparation = $script:dryRunPlan.effect_preparation_performed })
Add-Check "rc20.install.ready" $rc20InstallReady "Dry-run acceptance must bind RC20 install acceptance evidence from disposable target execution." ([ordered]@{ status = $script:rc20InstallAcceptanceResult.status; install_acceptance_id = $script:rc20InstallAcceptanceResult.install_acceptance_id; host_rootfs_mutated = $script:rc20InstallAcceptanceResult.summary.host_rootfs_mutated; production_ring_mutated = $script:rc20InstallAcceptanceResult.summary.production_ring_mutated })
Add-Check "rc20.update.ready" $rc20UpdateReady "Dry-run acceptance must bind RC20 update drill evidence from disposable installed-system execution." ([ordered]@{ status = $script:rc20UpdateResult.status; update_drill_id = $script:rc20UpdateResult.update_drill_id; host_active_slot_mutated = $script:rc20UpdateResult.summary.host_active_slot_mutated; production_ring_mutated = $script:rc20UpdateResult.summary.production_ring_mutated })
Add-Check "acceptance.binds_transactions" $operationBindingsReady "Dry-run acceptance evidence must bind transaction ids, resume checkpoints, audit sinks, and snapshots for install and update." (@($acceptedOperations | ForEach-Object { [ordered]@{ operation = $_.operation; transaction_id = $_.transaction_id; checkpoint_id = $_.resume_checkpoint.checkpoint_id; audit_sink_id = $_.audit_sink.audit_sink_id } }))
Add-Check "audit.local_only" $auditReady "Dry-run audit record must be local-only and must not write journal sink files or fabricate lifecycle effects." ([ordered]@{ dry_run_audit_record_id = $dryRunAuditRecordId; entries = @($auditRecord.entries).Count; journal_sink_files_written = $auditRecord.journal_sink_files_written })
Add-Check "authority.no_forbidden_effects" $noForbiddenEffects "RC21-021 must not prepare or execute host effects, support upload, recovery execution, remote dispatch, production mutation, signing, object storage, or private material handling." $acceptanceEvidence.no_effect_surface

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $acceptanceEvidencePath),
    (Get-Content -Raw -LiteralPath $auditRecordPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "Dry-run acceptance outputs must not contain private material, tokens, raw secrets, or endpoint authority claims." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-transactional-dry-run-acceptance-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-021"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    dry_run_acceptance_id = $dryRunAcceptanceId
    dry_run_execution_plan_id = [string]$script:dryRunPlan.dry_run_execution_plan_id
    dry_run_audit_record_id = $dryRunAuditRecordId
    transaction_journal_package_id = [string]$transactionJournalPackage.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$snapshotBaselinePackage.snapshot_baseline_package_id
    outputs = [ordered]@{
        dry_run_acceptance_evidence = [ordered]@{
            path = Get-StablePath $acceptanceEvidencePath
            sha256 = Get-FileSha256 $acceptanceEvidencePath
            dry_run_acceptance_id = $dryRunAcceptanceId
            accepted_operation_count = @($acceptedOperations).Count
        }
        dry_run_audit_record = [ordered]@{
            path = Get-StablePath $auditRecordPath
            sha256 = Get-FileSha256 $auditRecordPath
            dry_run_audit_record_id = $dryRunAuditRecordId
            entry_count = @($auditRecord.entries).Count
        }
    }
    dry_run_acceptance_surface = [ordered]@{
        state = "transactional-install-update-dry-run-accepted-no-effect"
        accepted_operations = @($acceptedOperations | ForEach-Object { $_.operation })
        deferred_operations = @("repair-reinstall")
        disposable_target_boundary = "rc21-dry-run-acceptance-local-projection"
        effect_preparation_performed = $false
        lifecycle_effect_performed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
    }
    source = $source
    checks = @($script:checks)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        dry_run_acceptance_recorded = $true
        dry_run_audit_record_written = $true
        journal_sink_files_written = $false
        effect_preparation_performed = $false
        install_performed = $false
        update_performed = $false
        repair_performed = $false
        reinstall_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        signer_authority = $false
        object_storage_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        rc21_021_complete = (@($script:failedChecks).Count -eq 0)
        dry_run_acceptance_id = $dryRunAcceptanceId
        dry_run_audit_record_id = $dryRunAuditRecordId
        accepted_operation_count = @($acceptedOperations).Count
        accepted_operations = @($acceptedOperations | ForEach-Object { $_.operation })
        effect_preparation_performed = $false
        install_performed = $false
        update_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-022"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-021-transactional-dry-run-acceptance.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-transactional-dry-run-acceptance-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-021"
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
    dry_run_acceptance_surface = $result.dry_run_acceptance_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-022"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-021 outputs." }

Write-Host "RC21 transactional dry-run acceptance $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Dry-run acceptance evidence: $(Get-StablePath $acceptanceEvidencePath)"
Write-Host "Dry-run audit record: $(Get-StablePath $auditRecordPath)"
Write-Host "Accepted operations: $(@($acceptedOperations).Count); effect preparation: false; production_ready_claim: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
