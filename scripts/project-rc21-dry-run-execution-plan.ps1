param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-dry-run-execution-plan",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$OperationIntentCatalogResultPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/result.json",
    [string]$OperationIntentCatalogPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/operation-intent-catalog.json",
    [string]$JournalSnapshotResultPath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/result.json",
    [string]$TransactionJournalPackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/transaction-journal-package.json",
    [string]$SnapshotBaselinePackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/snapshot-baseline-package.json",
    [string]$FailClosedResultPath = ".workflow/artifacts/rc21-lifecycle-operation-fail-closed/result.json",
    [string]$FailClosedMatrixPath = ".workflow/artifacts/rc21-lifecycle-operation-fail-closed/fail-closed-matrix.json",
    [string]$Rc20ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$Rc20LocalChannelResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
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

function New-PredictedEffects {
    return [ordered]@{
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

function New-DryRunOperationPlan {
    param([Parameter(Mandatory = $true)][string]$OperationId)
    $intent = @($script:operationIntentCatalog.operation_intents | Where-Object { $_.id -eq $OperationId })[0]
    $entry = @($script:transactionJournalPackage.entries | Where-Object { $_.operation -eq $OperationId })[0]
    $operationMaterial = [ordered]@{
        schema = "agentos.rc21-dry-run-operation-material.v1"
        task = "RC21-020"
        operation = [string]$OperationId
        operation_intent_id = [string]$intent.operation_intent_id
        transaction_id = [string]$entry.transaction_id
        source_snapshot_id = [string]$entry.source_snapshot_id
        target_snapshot_id = [string]$entry.target_snapshot_id
        rollback_snapshot_id = [string]$entry.rollback_snapshot_reference.snapshot_id
        release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
        local_channel_release_bundle_id = [string]$script:rc20LocalChannelResult.release_bundle_id
    }
    $operationPlanId = "sha256:$(Get-StringSha256 (Get-JsonText $operationMaterial))"
    return [ordered]@{
        operation = [string]$OperationId
        kind = [string]$intent.kind
        title = [string]$intent.title
        dry_run_operation_plan_id = $operationPlanId
        operation_intent_id = [string]$intent.operation_intent_id
        transaction_id = [string]$entry.transaction_id
        audit_sink = $entry.audit_sink
        resume_checkpoint = $entry.resume_checkpoint
        snapshots = [ordered]@{
            source_snapshot_id = [string]$entry.source_snapshot_id
            target_snapshot_id = [string]$entry.target_snapshot_id
            rollback_snapshot_id = [string]$entry.rollback_snapshot_reference.snapshot_id
        }
        release_binding = [ordered]@{
            release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
            selected_version = [string]$script:operationIntentCatalog.selected_version
            local_channel_release_bundle_id = [string]$script:rc20LocalChannelResult.release_bundle_id
            local_channel_status = [string]$script:rc20LocalChannelResult.status
        }
        preconditions = @(
            "rc21-authority-contract-bound",
            "rc20-release-bundle-bound",
            "rc20-local-channel-bound",
            "operation-intent-catalog-bound",
            "transaction-journal-entry-bound",
            "snapshot-baseline-bound",
            "lifecycle-fail-closed-fixtures-passed",
            "dry-run-only-no-effect-preparation"
        )
        ordered_steps = @(
            [ordered]@{
                step_id = "$OperationId-bind-intent"
                action = "bind operation intent and required inputs"
                prepares_effect = $false
                expected_observation = "operation intent identity is stable and local-only"
            },
            [ordered]@{
                step_id = "$OperationId-bind-journal"
                action = "bind transaction id, audit sink, resume checkpoint, and rollback reference"
                prepares_effect = $false
                expected_observation = "journal entry remains append-only evidence"
            },
            [ordered]@{
                step_id = "$OperationId-bind-snapshots"
                action = "bind source, target, and rollback snapshots from projection-only baseline"
                prepares_effect = $false
                expected_observation = "snapshot baseline has no host boot authority"
            },
            [ordered]@{
                step_id = "$OperationId-explain-denial"
                action = "explain denial before lifecycle effect until dry-run acceptance gate"
                prepares_effect = $false
                expected_observation = "effect preparation remains false"
            }
        )
        predicted_effects = New-PredictedEffects
        denial_reasons = @(
            @($intent.denial_reasons),
            "dry-run acceptance gate not yet executed",
            "effect preparation is reserved for RC21-021 acceptance",
            "host mutation, support upload, recovery execution, remote dispatch, signer authority, object storage, and production mutation remain disabled"
        )
        explainability = [ordered]@{
            user_visible_summary = "$OperationId dry-run plan is bound and non-executable until RC21-021 acceptance."
            resume_hint = "Use the bound resume checkpoint after RC21-021 acceptance evidence exists."
            audit_hint = "Use the bound local audit sink; no audit record is fabricated by RC21-020."
        }
        executable = $false
        dry_run_only = $true
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
$resolvedOperationIntentCatalogResultPath = Resolve-RepoPath $OperationIntentCatalogResultPath
$resolvedOperationIntentCatalogPath = Resolve-RepoPath $OperationIntentCatalogPath
$resolvedJournalSnapshotResultPath = Resolve-RepoPath $JournalSnapshotResultPath
$resolvedTransactionJournalPackagePath = Resolve-RepoPath $TransactionJournalPackagePath
$resolvedSnapshotBaselinePackagePath = Resolve-RepoPath $SnapshotBaselinePackagePath
$resolvedFailClosedResultPath = Resolve-RepoPath $FailClosedResultPath
$resolvedFailClosedMatrixPath = Resolve-RepoPath $FailClosedMatrixPath
$resolvedRc20ReleaseBundleResultPath = Resolve-RepoPath $Rc20ReleaseBundleResultPath
$resolvedRc20LocalChannelResultPath = Resolve-RepoPath $Rc20LocalChannelResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$operationIntentCatalogResult = Read-Json $resolvedOperationIntentCatalogResultPath
$script:operationIntentCatalog = Read-Json $resolvedOperationIntentCatalogPath
$journalSnapshotResult = Read-Json $resolvedJournalSnapshotResultPath
$script:transactionJournalPackage = Read-Json $resolvedTransactionJournalPackagePath
$script:snapshotBaselinePackage = Read-Json $resolvedSnapshotBaselinePackagePath
$failClosedResult = Read-Json $resolvedFailClosedResultPath
$failClosedMatrix = Read-Json $resolvedFailClosedMatrixPath
$script:rc20ReleaseBundleResult = Read-Json $resolvedRc20ReleaseBundleResultPath
$script:rc20LocalChannelResult = Read-Json $resolvedRc20LocalChannelResultPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-012"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-020" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-021" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsDryRun = (
    $contractText.Contains("Bind the install/update/reinstall dry-run execution plan") -and
    $contractText.Contains("Dry-run plans may explain ordered operations") -and
    $contractText.Contains("must not prepare or execute host effects")
)

$requiredDryRunOperations = @("install", "update", "repair-reinstall")
$catalogReady = (
    $operationIntentCatalogResult.status -eq "passed" -and
    $script:operationIntentCatalog.status -eq "local-operation-intent-catalog-bound-non-ga" -and
    @($requiredDryRunOperations | Where-Object { $_ -in @($script:operationIntentCatalog.operation_intents | ForEach-Object { $_.id }) }).Count -eq 3
)
$journalSnapshotReady = (
    $journalSnapshotResult.status -eq "passed" -and
    $journalSnapshotResult.summary.rc21_011_complete -eq $true -and
    $script:transactionJournalPackage.entry_count -eq 6 -and
    $script:snapshotBaselinePackage.projection_only -eq $true
)
$failClosedReady = (
    $failClosedResult.status -eq "passed" -and
    $failClosedResult.summary.rc21_012_complete -eq $true -and
    $failClosedResult.summary.all_cases_denied_before_effect -eq $true -and
    $failClosedMatrix.failed_case_count -eq 0
)
$releaseChannelReady = (
    $script:rc20ReleaseBundleResult.status -eq "passed" -and
    $script:rc20LocalChannelResult.status -eq "passed" -and
    $script:rc20ReleaseBundleResult.release_bundle_id -eq $script:operationIntentCatalog.release_bundle_id -and
    $script:rc20LocalChannelResult.release_bundle_id -eq $script:operationIntentCatalog.release_bundle_id -and
    $script:rc20LocalChannelResult.summary.external_mirror_publication_performed -eq $false -and
    $script:rc20LocalChannelResult.summary.active_artifact_set_mutated -eq $false -and
    $script:rc20LocalChannelResult.summary.production_ring_mutated -eq $false
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
    rc21_operation_intent_catalog_result = New-ArtifactRef $resolvedOperationIntentCatalogResultPath $operationIntentCatalogResult "rc21 operation intent catalog result"
    rc21_operation_intent_catalog = New-ArtifactRef $resolvedOperationIntentCatalogPath $script:operationIntentCatalog "rc21 operation intent catalog"
    rc21_journal_snapshot_result = New-ArtifactRef $resolvedJournalSnapshotResultPath $journalSnapshotResult "rc21 journal snapshot result"
    rc21_transaction_journal_package = New-ArtifactRef $resolvedTransactionJournalPackagePath $script:transactionJournalPackage "rc21 transaction journal package"
    rc21_snapshot_baseline_package = New-ArtifactRef $resolvedSnapshotBaselinePackagePath $script:snapshotBaselinePackage "rc21 snapshot baseline package"
    rc21_fail_closed_result = New-ArtifactRef $resolvedFailClosedResultPath $failClosedResult "rc21 fail-closed result"
    rc21_fail_closed_matrix = New-ArtifactRef $resolvedFailClosedMatrixPath $failClosedMatrix "rc21 fail-closed matrix"
    rc20_release_bundle_result = New-ArtifactRef $resolvedRc20ReleaseBundleResultPath $script:rc20ReleaseBundleResult "rc20 release bundle result"
    rc20_local_channel_result = New-ArtifactRef $resolvedRc20LocalChannelResultPath $script:rc20LocalChannelResult "rc20 local channel result"
}

$dryRunOperations = @()
foreach ($operationId in $requiredDryRunOperations) {
    $dryRunOperations += New-DryRunOperationPlan $operationId
}

$planCore = [ordered]@{
    schema = "agentos.rc21-dry-run-execution-plan-core.v1"
    task = "RC21-020"
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    transaction_journal_package_id = [string]$script:transactionJournalPackage.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$script:snapshotBaselinePackage.snapshot_baseline_package_id
    fail_closed_matrix_sha256 = Get-FileSha256 $resolvedFailClosedMatrixPath
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    local_channel_release_bundle_id = [string]$script:rc20LocalChannelResult.release_bundle_id
    operations = $dryRunOperations
}
$dryRunExecutionPlanId = "sha256:$(Get-StringSha256 (Get-JsonText $planCore))"

$dryRunPlan = [ordered]@{
    schema = "agentos.rc21-dry-run-execution-plan.v1"
    generated_at = $generatedAtValue
    task = "RC21-020"
    status = "dry-run-execution-plan-bound-non-executable"
    production_ready_claim = $false
    consumer_ready_claim = $false
    dry_run_execution_plan_id = $dryRunExecutionPlanId
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    transaction_journal_package_id = [string]$script:transactionJournalPackage.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$script:snapshotBaselinePackage.snapshot_baseline_package_id
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    selected_version = [string]$script:operationIntentCatalog.selected_version
    dry_run_only = $true
    executable = $false
    effect_preparation_performed = $false
    operation_count = @($dryRunOperations).Count
    operations = $dryRunOperations
    authority = [ordered]@{
        dry_run_plan_authority = $true
        effect_preparation_authority = $false
        install_authority = $false
        update_authority = $false
        repair_authority = $false
        reinstall_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_rootfs_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        signer_authority = $false
        object_storage_authority = $false
    }
    source = $source
}
$dryRunPlanPath = Join-Path $resolvedArtifactDir "dry-run-execution-plan.json"
Write-Json $dryRunPlan $dryRunPlanPath

$operationBindingsReady = (
    @($dryRunOperations).Count -eq 3 -and
    @($dryRunOperations | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.operation_intent_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.transaction_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.snapshots.source_snapshot_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.snapshots.target_snapshot_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.snapshots.rollback_snapshot_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.release_binding.release_bundle_id)
    }).Count -eq 0
)
$operationsExplainable = (@($dryRunOperations | Where-Object { @($_.preconditions).Count -lt 6 -or @($_.ordered_steps).Count -lt 4 -or @($_.denial_reasons).Count -lt 4 }).Count -eq 0)
$noEffectsPrepared = (
    $dryRunPlan.executable -eq $false -and
    $dryRunPlan.effect_preparation_performed -eq $false -and
    @($dryRunOperations | Where-Object {
        $_.predicted_effects.effect_preparation_performed -ne $false -or
        $_.predicted_effects.install_performed -ne $false -or
        $_.predicted_effects.update_performed -ne $false -or
        $_.predicted_effects.repair_performed -ne $false -or
        $_.predicted_effects.reinstall_performed -ne $false -or
        $_.predicted_effects.host_rootfs_mutated -ne $false -or
        $_.predicted_effects.active_artifact_set_mutated -ne $false -or
        $_.predicted_effects.production_ring_mutated -ne $false -or
        $_.predicted_effects.support_upload_performed -ne $false -or
        $_.predicted_effects.recovery_execution_performed -ne $false -or
        $_.predicted_effects.remote_dispatch_enabled -ne $false -or
        $_.predicted_effects.signer_authority_granted -ne $false -or
        $_.predicted_effects.object_storage_provisioned -ne $false
    }).Count -eq 0
)

Add-Check "plan.current_task.rc21_020" $planAllowsRun "RC21-020 must run after RC21-012 completed, with current_task set to RC21-020 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_012_status = $previousTaskStatus; rc21_020_status = $currentTaskStatus })
Add-Check "contract.dry_run_authority.present" $contractAllowsDryRun "RC21-020 must consume the RC21 dry-run execution plan contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "catalog.ready" $catalogReady "Dry-run plan must bind install, update, and repair/reinstall operation intents." ([ordered]@{ result_status = $operationIntentCatalogResult.status; catalog_status = $script:operationIntentCatalog.status; required_operations = $requiredDryRunOperations })
Add-Check "journal_snapshot.ready" $journalSnapshotReady "Dry-run plan must bind transaction journal and projection-only snapshot baseline packages." ([ordered]@{ journal_status = $journalSnapshotResult.status; entry_count = $script:transactionJournalPackage.entry_count; snapshot_projection_only = $script:snapshotBaselinePackage.projection_only })
Add-Check "fail_closed.ready" $failClosedReady "Dry-run plan must bind lifecycle operation fail-closed evidence before any dry-run acceptance." ([ordered]@{ result_status = $failClosedResult.status; cases = $failClosedResult.summary.cases; failed_cases = $failClosedResult.summary.failed_cases; all_denied_before_effect = $failClosedResult.summary.all_cases_denied_before_effect })
Add-Check "rc20.release_channel.ready" $releaseChannelReady "Dry-run plan must bind RC20 release bundle and local channel evidence without external mirror, active artifact, or production mutation." ([ordered]@{ release_bundle_id = $script:rc20ReleaseBundleResult.release_bundle_id; local_channel_release_bundle_id = $script:rc20LocalChannelResult.release_bundle_id; external_mirror_publication_performed = $script:rc20LocalChannelResult.summary.external_mirror_publication_performed; active_artifact_set_mutated = $script:rc20LocalChannelResult.summary.active_artifact_set_mutated; production_ring_mutated = $script:rc20LocalChannelResult.summary.production_ring_mutated })
Add-Check "dry_run.operations.bindings" $operationBindingsReady "Dry-run operations must bind operation intent, transaction journal, snapshots, release bundle, and local channel evidence." (@($dryRunOperations | ForEach-Object { [ordered]@{ operation = $_.operation; operation_intent_id = $_.operation_intent_id; transaction_id = $_.transaction_id; source_snapshot_id = $_.snapshots.source_snapshot_id; target_snapshot_id = $_.snapshots.target_snapshot_id; rollback_snapshot_id = $_.snapshots.rollback_snapshot_id } }))
Add-Check "dry_run.operations.explainable" $operationsExplainable "Every dry-run operation must record explainable preconditions, ordered steps, and denial reasons." (@($dryRunOperations | ForEach-Object { [ordered]@{ operation = $_.operation; preconditions = @($_.preconditions).Count; steps = @($_.ordered_steps).Count; denial_reasons = @($_.denial_reasons).Count } }))
Add-Check "authority.no_effects_prepared" $noEffectsPrepared "RC21-020 must prepare no real effect and keep host, production, support, recovery, remote, signer, and object storage authority disabled." $dryRunPlan.authority

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $dryRunPlanPath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "Dry-run plan outputs must not contain private material, tokens, raw secrets, or endpoint authority claims." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-dry-run-execution-plan-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-020"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    dry_run_execution_plan_id = $dryRunExecutionPlanId
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    transaction_journal_package_id = [string]$script:transactionJournalPackage.transaction_journal_package_id
    snapshot_baseline_package_id = [string]$script:snapshotBaselinePackage.snapshot_baseline_package_id
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    outputs = [ordered]@{
        dry_run_execution_plan = [ordered]@{
            path = Get-StablePath $dryRunPlanPath
            sha256 = Get-FileSha256 $dryRunPlanPath
            dry_run_execution_plan_id = $dryRunExecutionPlanId
            operation_count = @($dryRunOperations).Count
        }
    }
    dry_run_surface = [ordered]@{
        state = "install-update-reinstall-dry-run-plan-bound-non-executable"
        dry_run_plan_bound = ($resultStatus -eq "passed")
        dry_run_only = $true
        executable = $false
        operation_count = @($dryRunOperations).Count
        operations = @($dryRunOperations | ForEach-Object { $_.operation })
        effect_preparation_performed = $false
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
        dry_run_plan_written = $true
        dry_run_plan_executable = $false
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
        rc21_020_complete = (@($script:failedChecks).Count -eq 0)
        dry_run_execution_plan_id = $dryRunExecutionPlanId
        operation_count = @($dryRunOperations).Count
        operations = @($dryRunOperations | ForEach-Object { $_.operation })
        effect_preparation_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-021"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-020-dry-run-execution-plan.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-dry-run-execution-plan-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-020"
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
    dry_run_surface = $result.dry_run_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-021"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-020 outputs." }

Write-Host "RC21 dry-run execution plan $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Dry-run execution plan: $(Get-StablePath $dryRunPlanPath)"
Write-Host "Operations: $(@($dryRunOperations).Count); executable: false; effect preparation: false; production_ready_claim: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
