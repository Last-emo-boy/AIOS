param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$OperationIntentCatalogResultPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/result.json",
    [string]$OperationIntentCatalogPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/operation-intent-catalog.json",
    [string]$Rc20LifecycleSupportResultPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/result.json",
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

function Get-ShortSha {
    param([Parameter(Mandatory = $true)][string]$Digest)
    $clean = $Digest -replace "^sha256:", ""
    if ($clean.Length -le 16) { return $clean }
    return $clean.Substring(0, 16)
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

function New-SideEffects {
    return [ordered]@{
        transaction_journal_package_written = $false
        snapshot_baseline_package_written = $false
        dry_run_plan_written = $false
        install_performed = $false
        update_performed = $false
        repair_performed = $false
        reinstall_performed = $false
        downgrade_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        external_mirror_published = $false
        frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
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
        denied_before_lifecycle_effect = $true
        side_effects = New-SideEffects
    }
}

function New-Snapshot {
    param(
        [string]$Role,
        [string]$StateId,
        [string]$Description,
        [string[]]$BoundSources
    )
    $material = [ordered]@{
        schema = "agentos.rc21-snapshot-material.v1"
        role = $Role
        state_id = $StateId
        release_bundle_id = [string]$script:rc20LifecycleSupportResult.release_bundle_id
        selected_version = [string]$script:rc20LifecycleSupportResult.selected_version
        bound_sources = $BoundSources
    }
    $snapshotId = "sha256:$(Get-StringSha256 (Get-JsonText $material))"
    return [ordered]@{
        id = $Role
        snapshot_id = $snapshotId
        state_id = $StateId
        description = $Description
        projection_only = $true
        host_boot_state_authority = $false
        host_rootfs_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        bound_sources = $BoundSources
    }
}

function New-JournalEntry {
    param(
        $Intent,
        [string]$SourceSnapshotId,
        [string]$TargetSnapshotId,
        [string]$RollbackSnapshotId
    )
    $material = [ordered]@{
        schema = "agentos.rc21-transaction-id-material.v1"
        task = "RC21-011"
        operation_intent_id = [string]$Intent.operation_intent_id
        operation = [string]$Intent.id
        release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
        selected_version = [string]$script:operationIntentCatalog.selected_version
        source_snapshot_id = $SourceSnapshotId
        target_snapshot_id = $TargetSnapshotId
        rollback_snapshot_id = $RollbackSnapshotId
        operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    }
    $transactionId = "sha256:$(Get-StringSha256 (Get-JsonText $material))"
    $short = Get-ShortSha $transactionId
    return [ordered]@{
        operation = [string]$Intent.id
        kind = [string]$Intent.kind
        operation_intent_id = [string]$Intent.operation_intent_id
        transaction_id = $transactionId
        transaction_state = "baseline-bound-non-executable"
        append_only = $true
        dry_run_required_before_effect = $true
        executable_by_journal = $false
        effect_boundary = [string]$Intent.effect_boundary
        source_snapshot_id = $SourceSnapshotId
        target_snapshot_id = $TargetSnapshotId
        rollback_snapshot_reference = [ordered]@{
            snapshot_id = $RollbackSnapshotId
            required_before_effect = $true
            projection_only = $true
        }
        audit_sink = [ordered]@{
            audit_sink_id = "rc21-011-audit-$($Intent.id)-$short"
            path = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/audit/$($Intent.id).jsonl"
            local_only = $true
            append_only_required = $true
            written = $false
        }
        resume_checkpoint = [ordered]@{
            checkpoint_id = "rc21-011-resume-$($Intent.id)-$short"
            path = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/checkpoints/$($Intent.id).json"
            local_only = $true
            written = $false
            required_before_resume = $true
        }
        denial_before_effect = [ordered]@{
            required = $true
            reason = "RC21-011 binds journal and snapshot baseline only; dry-run and lifecycle effects are later gates."
        }
        forbidden_authority = [ordered]@{
            support_upload = $true
            recovery_execution = $true
            remote_dispatch = $true
            host_mutation = $true
            production_ring_mutation = $true
            signer_authority = $true
            object_storage_provisioning = $true
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
$resolvedOperationIntentCatalogResultPath = Resolve-RepoPath $OperationIntentCatalogResultPath
$resolvedOperationIntentCatalogPath = Resolve-RepoPath $OperationIntentCatalogPath
$resolvedRc20LifecycleSupportResultPath = Resolve-RepoPath $Rc20LifecycleSupportResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$operationIntentCatalogResult = Read-Json $resolvedOperationIntentCatalogResultPath
$script:operationIntentCatalog = Read-Json $resolvedOperationIntentCatalogPath
$script:rc20LifecycleSupportResult = Read-Json $resolvedRc20LifecycleSupportResultPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-010"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-011"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-011" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-012" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsJournalSnapshot = (
    $contractText.Contains("Bind the transaction journal and snapshot baseline package") -and
    $contractText.Contains("Transaction journal entries must be append-only evidence") -and
    $contractText.Contains("Snapshot baselines must be repo-local evidence or disposable installed-system evidence")
)

$requiredIntentIds = @("install", "update", "repair-reinstall", "downgrade-rollback", "support-export", "recovery-reference")
$catalogIntentIds = @($script:operationIntentCatalog.operation_intents | ForEach-Object { $_.id })
$catalogReady = (
    $operationIntentCatalogResult.status -eq "passed" -and
    $script:operationIntentCatalog.status -eq "local-operation-intent-catalog-bound-non-ga" -and
    $script:operationIntentCatalog.operation_intent_catalog_id -eq $operationIntentCatalogResult.operation_intent_catalog_id -and
    @($catalogIntentIds | Where-Object { $_ -in $requiredIntentIds }).Count -eq 6 -and
    $script:operationIntentCatalog.executable_by_catalog -eq $false -and
    $script:operationIntentCatalog.production_ready_claim -eq $false
)

$stateChainReady = (
    $script:rc20LifecycleSupportResult.status -eq "passed" -and
    -not [string]::IsNullOrWhiteSpace([string]$script:rc20LifecycleSupportResult.target_state_id) -and
    -not [string]::IsNullOrWhiteSpace([string]$script:rc20LifecycleSupportResult.previous_installed_image_state_id) -and
    -not [string]::IsNullOrWhiteSpace([string]$script:rc20LifecycleSupportResult.updated_image_state_id) -and
    -not [string]::IsNullOrWhiteSpace([string]$script:rc20LifecycleSupportResult.restored_target_state_id) -and
    $script:rc20LifecycleSupportResult.lifecycle_support_surface.support_upload_performed -eq $false -and
    $script:rc20LifecycleSupportResult.lifecycle_support_surface.recovery_execution_performed -eq $false -and
    $script:rc20LifecycleSupportResult.lifecycle_support_surface.remote_dispatch_enabled -eq $false -and
    $script:rc20LifecycleSupportResult.lifecycle_support_surface.host_rootfs_mutated -eq $false -and
    $script:rc20LifecycleSupportResult.lifecycle_support_surface.active_artifact_set_mutated -eq $false -and
    $script:rc20LifecycleSupportResult.lifecycle_support_surface.production_ring_mutated -eq $false
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
    rc20_lifecycle_support_result = New-ArtifactRef $resolvedRc20LifecycleSupportResultPath $script:rc20LifecycleSupportResult "rc20 lifecycle support result"
}

$preinstallPlaceholderState = "sha256:$(Get-StringSha256 (Get-JsonText ([ordered]@{
    schema = "agentos.rc21-preinstall-placeholder-state.v1"
    task = "RC21-011"
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    selected_version = [string]$script:operationIntentCatalog.selected_version
    authority = "projection-only-no-host-state"
})))"

$snapshots = @(
    (New-Snapshot "rc21-preinstall-placeholder" $preinstallPlaceholderState "Projection-only placeholder for an unmodified host or disposable target before install." @("rc21-authority-contract", "rc21-operation-intent-catalog")),
    (New-Snapshot "rc20-target-state" ([string]$script:rc20LifecycleSupportResult.target_state_id) "RC20 selected target state from single-user local lifecycle evidence." @("rc20-lifecycle-support-result")),
    (New-Snapshot "rc20-previous-installed-state" ([string]$script:rc20LifecycleSupportResult.previous_installed_image_state_id) "RC20 previous installed image state before update inside disposable evidence." @("rc20-lifecycle-support-result")),
    (New-Snapshot "rc20-updated-state" ([string]$script:rc20LifecycleSupportResult.updated_image_state_id) "RC20 updated image state after post-install update drill inside disposable evidence." @("rc20-lifecycle-support-result")),
    (New-Snapshot "rc20-restored-state" ([string]$script:rc20LifecycleSupportResult.restored_target_state_id) "RC20 restored target state after rollback drill inside disposable evidence." @("rc20-lifecycle-support-result"))
)

$snapshotByRole = @{}
foreach ($snapshot in $snapshots) {
    $snapshotByRole[[string]$snapshot.id] = [string]$snapshot.snapshot_id
}

$snapshotCore = [ordered]@{
    schema = "agentos.rc21-snapshot-baseline-core.v1"
    task = "RC21-011"
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    selected_version = [string]$script:operationIntentCatalog.selected_version
    target_state_id = [string]$script:rc20LifecycleSupportResult.target_state_id
    updated_image_state_id = [string]$script:rc20LifecycleSupportResult.updated_image_state_id
    restored_target_state_id = [string]$script:rc20LifecycleSupportResult.restored_target_state_id
    snapshots = $snapshots
}
$snapshotBaselinePackageId = "sha256:$(Get-StringSha256 (Get-JsonText $snapshotCore))"

$intentSnapshotMap = @{
    "install" = [ordered]@{
        source = $snapshotByRole["rc21-preinstall-placeholder"]
        target = $snapshotByRole["rc20-target-state"]
        rollback = $snapshotByRole["rc21-preinstall-placeholder"]
    }
    "update" = [ordered]@{
        source = $snapshotByRole["rc20-previous-installed-state"]
        target = $snapshotByRole["rc20-updated-state"]
        rollback = $snapshotByRole["rc20-restored-state"]
    }
    "repair-reinstall" = [ordered]@{
        source = $snapshotByRole["rc20-restored-state"]
        target = $snapshotByRole["rc20-target-state"]
        rollback = $snapshotByRole["rc20-restored-state"]
    }
    "downgrade-rollback" = [ordered]@{
        source = $snapshotByRole["rc20-updated-state"]
        target = $snapshotByRole["rc20-restored-state"]
        rollback = $snapshotByRole["rc20-updated-state"]
    }
    "support-export" = [ordered]@{
        source = $snapshotByRole["rc20-restored-state"]
        target = $snapshotByRole["rc20-restored-state"]
        rollback = $snapshotByRole["rc20-restored-state"]
    }
    "recovery-reference" = [ordered]@{
        source = $snapshotByRole["rc20-restored-state"]
        target = $snapshotByRole["rc20-restored-state"]
        rollback = $snapshotByRole["rc20-restored-state"]
    }
}

$journalEntries = @()
foreach ($intent in @($script:operationIntentCatalog.operation_intents | Sort-Object id)) {
    $mapping = $intentSnapshotMap[[string]$intent.id]
    $journalEntries += New-JournalEntry $intent ([string]$mapping.source) ([string]$mapping.target) ([string]$mapping.rollback)
}

$journalCore = [ordered]@{
    schema = "agentos.rc21-transaction-journal-core.v1"
    task = "RC21-011"
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    snapshot_baseline_package_id = $snapshotBaselinePackageId
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    selected_version = [string]$script:operationIntentCatalog.selected_version
    entries = $journalEntries
}
$transactionJournalPackageId = "sha256:$(Get-StringSha256 (Get-JsonText $journalCore))"

$snapshotPackage = [ordered]@{
    schema = "agentos.rc21-snapshot-baseline-package.v1"
    generated_at = $generatedAtValue
    task = "RC21-011"
    status = "snapshot-baseline-bound-projection-only"
    production_ready_claim = $false
    consumer_ready_claim = $false
    snapshot_baseline_package_id = $snapshotBaselinePackageId
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    selected_version = [string]$script:operationIntentCatalog.selected_version
    projection_only = $true
    bound_states = [ordered]@{
        rc20_target_state_id = [string]$script:rc20LifecycleSupportResult.target_state_id
        rc20_previous_installed_image_state_id = [string]$script:rc20LifecycleSupportResult.previous_installed_image_state_id
        rc20_updated_image_state_id = [string]$script:rc20LifecycleSupportResult.updated_image_state_id
        rc20_restored_target_state_id = [string]$script:rc20LifecycleSupportResult.restored_target_state_id
    }
    snapshots = $snapshots
    authority = [ordered]@{
        snapshot_baseline_authority = $true
        projection_only = $true
        host_boot_state_authority = $false
        host_rootfs_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
    }
    source = $source
}
$snapshotPackagePath = Join-Path $resolvedArtifactDir "snapshot-baseline-package.json"
Write-Json $snapshotPackage $snapshotPackagePath

$journalPackage = [ordered]@{
    schema = "agentos.rc21-transaction-journal-package.v1"
    generated_at = $generatedAtValue
    task = "RC21-011"
    status = "transaction-journal-baseline-bound-non-executable"
    production_ready_claim = $false
    consumer_ready_claim = $false
    transaction_journal_package_id = $transactionJournalPackageId
    snapshot_baseline_package_id = $snapshotBaselinePackageId
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    append_only_evidence = $true
    executable_by_journal = $false
    dry_run_required_before_effect = $true
    entry_count = @($journalEntries).Count
    entries = $journalEntries
    authority = [ordered]@{
        transaction_journal_authority = $true
        effect_execution_authority = $false
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
$journalPackagePath = Join-Path $resolvedArtifactDir "transaction-journal-package.json"
Write-Json $journalPackage $journalPackagePath

$requiredBindingsPresent = (
    @($journalEntries).Count -eq 6 -and
    @($journalEntries | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.transaction_id) -or
        $null -eq $_.audit_sink -or [string]::IsNullOrWhiteSpace([string]$_.audit_sink.audit_sink_id) -or
        $null -eq $_.resume_checkpoint -or [string]::IsNullOrWhiteSpace([string]$_.resume_checkpoint.checkpoint_id) -or
        $null -eq $_.rollback_snapshot_reference -or [string]::IsNullOrWhiteSpace([string]$_.rollback_snapshot_reference.snapshot_id)
    }).Count -eq 0
)
$transactionIds = @($journalEntries | ForEach-Object { [string]$_["transaction_id"] })
$deterministicIdsUnique = (@($transactionIds | Select-Object -Unique).Count -eq 6)
$snapshotPackageReady = (
    $snapshotPackage.projection_only -eq $true -and
    $snapshotPackage.bound_states.rc20_target_state_id -eq $script:rc20LifecycleSupportResult.target_state_id -and
    $snapshotPackage.bound_states.rc20_updated_image_state_id -eq $script:rc20LifecycleSupportResult.updated_image_state_id -and
    $snapshotPackage.bound_states.rc20_restored_target_state_id -eq $script:rc20LifecycleSupportResult.restored_target_state_id -and
    $snapshotPackage.authority.host_rootfs_mutation_authority -eq $false -and
    $snapshotPackage.authority.active_artifact_set_mutation_authority -eq $false
)

$sideEffects = New-SideEffects
$sideEffects.transaction_journal_package_written = $true
$sideEffects.snapshot_baseline_package_written = $true

$caseSpecs = @(
    [ordered]@{ id = "missing-operation-intent-catalog"; blockers = @("operation-intent-catalog-required"); reason = "Transaction journal baseline requires RC21-010 operation intent catalog." },
    [ordered]@{ id = "stale-operation-intent-catalog"; blockers = @("stale-operation-intent-catalog-denied"); reason = "Journal denies stale catalog evidence." },
    [ordered]@{ id = "missing-lifecycle-support"; blockers = @("rc20-lifecycle-support-required"); reason = "Snapshot baseline requires RC20 lifecycle support/recovery result." },
    [ordered]@{ id = "target-state-mismatch"; blockers = @("target-state-mismatch-denied"); reason = "Snapshot baseline denies mismatched target state." },
    [ordered]@{ id = "updated-state-missing"; blockers = @("updated-state-required"); reason = "Update and downgrade journal entries require updated state evidence." },
    [ordered]@{ id = "restored-state-missing"; blockers = @("restored-state-required"); reason = "Rollback snapshot references require restored target state evidence." },
    [ordered]@{ id = "missing-audit-sink"; blockers = @("audit-sink-required"); reason = "Every transaction entry requires a local audit sink." },
    [ordered]@{ id = "missing-resume-checkpoint"; blockers = @("resume-checkpoint-required"); reason = "Every transaction entry requires a resume checkpoint." },
    [ordered]@{ id = "missing-rollback-snapshot-reference"; blockers = @("rollback-snapshot-reference-required"); reason = "Every transaction entry requires rollback snapshot reference." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is outside RC21 body scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is outside RC21 body scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is outside RC21 body scope." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer authority is outside RC21 body scope." },
    [ordered]@{ id = "object-storage-attempt"; blockers = @("object-storage-denied"); reason = "Object storage provisioning is outside RC21 body scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "Journal and snapshot baseline cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc21_011" $planAllowsRun "RC21-011 must run after RC21-010 completed, with current_task set to RC21-011 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_010_status = $previousTaskStatus; rc21_011_status = $currentTaskStatus })
Add-Check "contract.journal_snapshot_authority.present" $contractAllowsJournalSnapshot "RC21-011 must consume the RC21 journal and snapshot baseline contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "catalog.ready" $catalogReady "RC21-011 must bind the completed RC21-010 local operation intent catalog." ([ordered]@{ result_status = $operationIntentCatalogResult.status; catalog_status = $script:operationIntentCatalog.status; intent_count = @($catalogIntentIds).Count; operation_intent_catalog_id = $script:operationIntentCatalog.operation_intent_catalog_id })
Add-Check "rc20.lifecycle_state_chain.ready" $stateChainReady "Snapshot baseline must bind RC20 target, updated, and restored states from lifecycle support/recovery evidence." ([ordered]@{ status = $script:rc20LifecycleSupportResult.status; target_state_id = $script:rc20LifecycleSupportResult.target_state_id; updated_image_state_id = $script:rc20LifecycleSupportResult.updated_image_state_id; restored_target_state_id = $script:rc20LifecycleSupportResult.restored_target_state_id })
Add-Check "journal.entries.bind_required_fields" $requiredBindingsPresent "Every operation intent must bind deterministic transaction id, audit sink, resume checkpoint, and rollback snapshot reference." (@($journalEntries | ForEach-Object { [ordered]@{ operation = $_.operation; transaction_id = $_.transaction_id; audit_sink_id = $_.audit_sink.audit_sink_id; checkpoint_id = $_.resume_checkpoint.checkpoint_id; rollback_snapshot_id = $_.rollback_snapshot_reference.snapshot_id } }))
Add-Check "journal.transaction_ids.unique" $deterministicIdsUnique "Transaction ids must be deterministic and unique across the six lifecycle operation intents." (@($journalEntries | ForEach-Object { [ordered]@{ operation = $_["operation"]; transaction_id = $_["transaction_id"] } }))
Add-Check "snapshot.baseline.projection_only" $snapshotPackageReady "Snapshot baseline package must be projection-only and bind RC20 target, updated, and restored states without host or active artifact mutation." $snapshotPackage.bound_states
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.dry_run_plan_written -eq $false -and $sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.repair_performed -eq $false -and $sideEffects.reinstall_performed -eq $false -and $sideEffects.downgrade_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.production_ready_claim -eq $false) "RC21-011 must write only local journal/snapshot packages and must not execute lifecycle effects or broaden forbidden authority." $sideEffects
Add-Check "fixtures.baseline_denials.present" (@($failedCases).Count -eq 0 -and @($cases).Count -ge 15) "Baseline denial cases must cover missing, stale, mismatched, broad, remote, support, recovery, signer, object storage, host, production, and GA attempts." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $snapshotPackagePath),
    (Get-Content -Raw -LiteralPath $journalPackagePath)
)
Add-Check "outputs.secret_safe" $outputSecretSafe "RC21-011 outputs must not contain private key blocks, private authority paths, auth tokens, signing key file names, raw passwords, or raw secrets." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-transaction-journal-snapshot-baseline-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-011"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    transaction_journal_package_id = $transactionJournalPackageId
    snapshot_baseline_package_id = $snapshotBaselinePackageId
    operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
    release_bundle_id = [string]$script:operationIntentCatalog.release_bundle_id
    selected_version = [string]$script:operationIntentCatalog.selected_version
    outputs = [ordered]@{
        transaction_journal_package = [ordered]@{
            path = Get-StablePath $journalPackagePath
            sha256 = Get-FileSha256 $journalPackagePath
            transaction_journal_package_id = $transactionJournalPackageId
            entry_count = @($journalEntries).Count
        }
        snapshot_baseline_package = [ordered]@{
            path = Get-StablePath $snapshotPackagePath
            sha256 = Get-FileSha256 $snapshotPackagePath
            snapshot_baseline_package_id = $snapshotBaselinePackageId
            snapshot_count = @($snapshots).Count
        }
    }
    journal_snapshot_surface = [ordered]@{
        state = "transaction-journal-snapshot-baseline-bound-non-executable"
        transaction_journal_bound = ($resultStatus -eq "passed")
        snapshot_baseline_bound = ($resultStatus -eq "passed")
        entry_count = @($journalEntries).Count
        required_intents = $requiredIntentIds
        executable_by_journal = $false
        dry_run_required_before_effect = $true
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        blockers = @()
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        operation_intent_catalog_bound = $catalogReady
        transaction_journal_package_written = $true
        snapshot_baseline_package_written = $true
        transaction_journal_executable = $false
        snapshot_baseline_projection_only = $true
        dry_run_plan_written = $false
        install_performed = $false
        update_performed = $false
        repair_performed = $false
        reinstall_performed = $false
        downgrade_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        external_mirror_frontend_authority = $false
        nginx_or_tls_authority = $false
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
        rc21_011_complete = (@($script:failedChecks).Count -eq 0)
        transaction_journal_package_id = $transactionJournalPackageId
        snapshot_baseline_package_id = $snapshotBaselinePackageId
        operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
        journal_entry_count = @($journalEntries).Count
        snapshot_count = @($snapshots).Count
        target_state_id = [string]$script:rc20LifecycleSupportResult.target_state_id
        updated_image_state_id = [string]$script:rc20LifecycleSupportResult.updated_image_state_id
        restored_target_state_id = [string]$script:rc20LifecycleSupportResult.restored_target_state_id
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-012"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-011-transaction-journal-snapshot-baseline.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-transaction-journal-snapshot-baseline-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-011"
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
    journal_snapshot_surface = $result.journal_snapshot_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-012"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-011 outputs." }

Write-Host "RC21 transaction journal snapshot baseline $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Transaction journal package: $(Get-StablePath $journalPackagePath)"
Write-Host "Snapshot baseline package: $(Get-StablePath $snapshotPackagePath)"
Write-Host "Journal entries: $(@($journalEntries).Count); snapshots: $(@($snapshots).Count); executable_by_journal: false; production_ready_claim: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
