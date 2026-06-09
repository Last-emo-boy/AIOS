param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-lifecycle-operation-fail-closed",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$OperationIntentCatalogResultPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/result.json",
    [string]$OperationIntentCatalogPath = ".workflow/artifacts/rc21-local-operation-intent-catalog/operation-intent-catalog.json",
    [string]$JournalSnapshotResultPath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/result.json",
    [string]$TransactionJournalPackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/transaction-journal-package.json",
    [string]$SnapshotBaselinePackagePath = ".workflow/artifacts/rc21-transaction-journal-snapshot-baseline/snapshot-baseline-package.json",
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

function Convert-JsonClone {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
}

function Add-Reason {
    param([System.Collections.Generic.List[string]]$Reasons, [Parameter(Mandatory = $true)][string]$Reason)
    if (-not $Reasons.Contains($Reason)) { $Reasons.Add($Reason) }
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

function New-SideEffects {
    return [ordered]@{
        effect_preparation_performed = $false
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
        network_dependency_contacted = $false
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
        endpoint_authority_granted = $false
        shell_output_authority_granted = $false
        tui_authority_granted = $false
        model_replay_authority_granted = $false
        production_ready_claim = $false
    }
}

function Test-NoSideEffects {
    param($SideEffects)
    foreach ($property in $SideEffects.PSObject.Properties) {
        if ($property.Value -eq $true) { return $false }
    }
    return $true
}

function New-BaseFixture {
    param([Parameter(Mandatory = $true)][string]$OperationId)
    $intent = @($script:operationIntentCatalog.operation_intents | Where-Object { $_.id -eq $OperationId })[0]
    $entry = @($script:transactionJournalPackage.entries | Where-Object { $_.operation -eq $OperationId })[0]
    $fixture = [ordered]@{
        schema = "agentos.rc21-lifecycle-operation-fail-closed-fixture.v1"
        operation = [ordered]@{
            id = [string]$intent.id
            kind = [string]$intent.kind
            operation_intent_id = [string]$intent.operation_intent_id
            requested_scope = "local-single-user-lifecycle"
            broad_scope = $false
        }
        sources = [ordered]@{
            rc20_lifecycle_support_bound = $true
            rc20_lifecycle_support_stale = $false
            release_bundle_id = [string]$script:rc20LifecycleSupportResult.release_bundle_id
            target_state_id = [string]$script:rc20LifecycleSupportResult.target_state_id
            updated_image_state_id = [string]$script:rc20LifecycleSupportResult.updated_image_state_id
            restored_target_state_id = [string]$script:rc20LifecycleSupportResult.restored_target_state_id
            operation_intent_catalog_id = [string]$script:operationIntentCatalog.operation_intent_catalog_id
        }
        journal = [ordered]@{
            entry_bound = $true
            transaction_journal_package_id = [string]$script:transactionJournalPackage.transaction_journal_package_id
            transaction_id = [string]$entry.transaction_id
            audit_sink_bound = $true
            audit_sink_id = [string]$entry.audit_sink.audit_sink_id
            resume_checkpoint_bound = $true
            checkpoint_id = [string]$entry.resume_checkpoint.checkpoint_id
            rollback_snapshot_reference_bound = $true
            rollback_snapshot_id = [string]$entry.rollback_snapshot_reference.snapshot_id
            stale = $false
        }
        snapshot = [ordered]@{
            baseline_bound = $true
            snapshot_baseline_package_id = [string]$script:snapshotBaselinePackage.snapshot_baseline_package_id
            source_snapshot_id = [string]$entry.source_snapshot_id
            target_snapshot_id = [string]$entry.target_snapshot_id
            rollback_snapshot_id = [string]$entry.rollback_snapshot_reference.snapshot_id
            projection_only = $true
            host_boot_state_authority = $false
            stale = $false
        }
        requests = [ordered]@{
            effect_preparation = $false
            host_rootfs_mutation = $false
            host_active_slot_mutation = $false
            host_boot_metadata_mutation = $false
            active_artifact_set_mutation = $false
            production_ring_mutation = $false
            remote_dependency = $false
            signer_authority = $false
            support_upload = $false
            recovery_execution = $false
            object_storage_provisioning = $false
            endpoint_authority = $false
            shell_output_authority = $false
            tui_authority = $false
            model_replay_authority = $false
            ga_claim = $false
        }
        authority = [ordered]@{
            dry_run_acceptance_bound = $false
            effect_execution_authority = $false
            support_upload_authority = $false
            recovery_execution_authority = $false
            remote_dispatch_authority = $false
            host_mutation_authority = $false
            production_ring_mutation_authority = $false
            signer_authority = $false
            object_storage_authority = $false
        }
    }
    return Convert-JsonClone $fixture
}

function Invoke-LifecycleFixtureEvaluation {
    param([Parameter(Mandatory = $true)]$Fixture)
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($Fixture.schema -ne "agentos.rc21-lifecycle-operation-fail-closed-fixture.v1") {
        Add-Reason $reasons "bad-fixture-schema"
    }
    if ($Fixture.sources.rc20_lifecycle_support_bound -ne $true) {
        Add-Reason $reasons "rc20-lifecycle-support-required"
    }
    if ($Fixture.sources.rc20_lifecycle_support_stale -eq $true) {
        Add-Reason $reasons "stale-rc20-lifecycle-support-denied"
    }
    if ($Fixture.sources.release_bundle_id -ne $script:expectedReleaseBundleId -or
        $Fixture.sources.target_state_id -ne $script:expectedTargetStateId -or
        $Fixture.sources.updated_image_state_id -ne $script:expectedUpdatedStateId -or
        $Fixture.sources.restored_target_state_id -ne $script:expectedRestoredStateId) {
        Add-Reason $reasons "rc20-state-identity-mismatch-denied"
    }
    if ($Fixture.sources.operation_intent_catalog_id -ne $script:expectedOperationIntentCatalogId) {
        Add-Reason $reasons "operation-intent-catalog-mismatch-denied"
    }

    $expectedIntent = $script:expectedIntentByOperation[[string]$Fixture.operation.id]
    if ($null -eq $expectedIntent) {
        Add-Reason $reasons "unknown-operation-intent-denied"
    } else {
        if ($Fixture.operation.operation_intent_id -ne $expectedIntent.operation_intent_id -or
            $Fixture.operation.kind -ne $expectedIntent.kind) {
            Add-Reason $reasons "operation-intent-mismatch-denied"
        }
    }
    if ($Fixture.operation.broad_scope -eq $true -or $Fixture.operation.requested_scope -ne "local-single-user-lifecycle") {
        Add-Reason $reasons "broad-operation-scope-denied"
    }

    $expectedEntry = $script:expectedJournalEntryByOperation[[string]$Fixture.operation.id]
    if ($Fixture.journal.entry_bound -ne $true) {
        Add-Reason $reasons "transaction-journal-entry-required"
    }
    if ($Fixture.journal.stale -eq $true) {
        Add-Reason $reasons "stale-transaction-journal-denied"
    }
    if ($Fixture.journal.transaction_journal_package_id -ne $script:expectedTransactionJournalPackageId) {
        Add-Reason $reasons "transaction-journal-package-mismatch-denied"
    }
    if ($null -ne $expectedEntry -and $Fixture.journal.transaction_id -ne $expectedEntry.transaction_id) {
        Add-Reason $reasons "transaction-id-mismatch-denied"
    }
    if ($Fixture.journal.audit_sink_bound -ne $true -or [string]::IsNullOrWhiteSpace([string]$Fixture.journal.audit_sink_id)) {
        Add-Reason $reasons "audit-sink-required"
    }
    if ($Fixture.journal.resume_checkpoint_bound -ne $true -or [string]::IsNullOrWhiteSpace([string]$Fixture.journal.checkpoint_id)) {
        Add-Reason $reasons "resume-checkpoint-required"
    }
    if ($Fixture.journal.rollback_snapshot_reference_bound -ne $true -or [string]::IsNullOrWhiteSpace([string]$Fixture.journal.rollback_snapshot_id)) {
        Add-Reason $reasons "rollback-snapshot-reference-required"
    }

    if ($Fixture.snapshot.baseline_bound -ne $true) {
        Add-Reason $reasons "snapshot-baseline-required"
    }
    if ($Fixture.snapshot.stale -eq $true) {
        Add-Reason $reasons "stale-snapshot-baseline-denied"
    }
    if ($Fixture.snapshot.snapshot_baseline_package_id -ne $script:expectedSnapshotBaselinePackageId) {
        Add-Reason $reasons "snapshot-baseline-package-mismatch-denied"
    }
    if ($Fixture.snapshot.projection_only -ne $true -or $Fixture.snapshot.host_boot_state_authority -eq $true) {
        Add-Reason $reasons "snapshot-authority-broadening-denied"
    }
    if ($null -ne $expectedEntry -and (
        $Fixture.snapshot.source_snapshot_id -ne $expectedEntry.source_snapshot_id -or
        $Fixture.snapshot.target_snapshot_id -ne $expectedEntry.target_snapshot_id -or
        $Fixture.snapshot.rollback_snapshot_id -ne $expectedEntry.rollback_snapshot_reference.snapshot_id
    )) {
        Add-Reason $reasons "snapshot-reference-mismatch-denied"
    }

    if ($Fixture.requests.effect_preparation -eq $true -and $Fixture.authority.dry_run_acceptance_bound -ne $true) {
        Add-Reason $reasons "dry-run-gate-required"
    }
    if ($Fixture.requests.host_rootfs_mutation -eq $true -or $Fixture.requests.host_active_slot_mutation -eq $true -or $Fixture.requests.host_boot_metadata_mutation -eq $true -or $Fixture.requests.active_artifact_set_mutation -eq $true -or $Fixture.authority.host_mutation_authority -eq $true) {
        Add-Reason $reasons "host-mutation-denied"
    }
    if ($Fixture.requests.production_ring_mutation -eq $true -or $Fixture.authority.production_ring_mutation_authority -eq $true) {
        Add-Reason $reasons "production-ring-mutation-denied"
    }
    if ($Fixture.requests.remote_dependency -eq $true -or $Fixture.authority.remote_dispatch_authority -eq $true) {
        Add-Reason $reasons "remote-dependency-denied"
    }
    if ($Fixture.requests.signer_authority -eq $true -or $Fixture.authority.signer_authority -eq $true) {
        Add-Reason $reasons "signer-authority-denied"
    }
    if ($Fixture.requests.object_storage_provisioning -eq $true -or $Fixture.authority.object_storage_authority -eq $true) {
        Add-Reason $reasons "object-storage-provisioning-denied"
    }
    if ($Fixture.requests.support_upload -eq $true -or $Fixture.authority.support_upload_authority -eq $true) {
        Add-Reason $reasons "support-upload-denied"
    }
    if ($Fixture.requests.recovery_execution -eq $true -or $Fixture.authority.recovery_execution_authority -eq $true) {
        Add-Reason $reasons "recovery-execution-denied"
    }
    if ($Fixture.requests.endpoint_authority -eq $true -or $Fixture.requests.shell_output_authority -eq $true -or $Fixture.requests.tui_authority -eq $true -or $Fixture.requests.model_replay_authority -eq $true) {
        Add-Reason $reasons "non-authoritative-surface-denied"
    }
    if ($Fixture.requests.ga_claim -eq $true) {
        Add-Reason $reasons "ga-claim-denied"
    }
    if ($Fixture.authority.effect_execution_authority -eq $true) {
        Add-Reason $reasons "effect-execution-authority-denied"
    }

    $sideEffects = New-SideEffects
    return [ordered]@{
        observed_state = if ($reasons.Count -eq 0) { "fixture-valid-non-authoritative" } else { "fixture-denied-before-lifecycle-effect" }
        observed_reasons = @($reasons)
        denied_before_effect_preparation = $true
        denied_before_host_mutation = $true
        denied_before_support_upload = $true
        denied_before_recovery_execution = $true
        denied_before_remote_dispatch = $true
        denied_before_production_mutation = $true
        side_effects = $sideEffects
    }
}

function Invoke-Case {
    param(
        [string]$Id,
        [string]$Category,
        [string]$OperationId,
        [string[]]$ExpectedReasons,
        [scriptblock]$Mutate
    )
    $fixture = New-BaseFixture $OperationId
    if ($null -ne $Mutate) { & $Mutate $fixture }
    $evaluation = Invoke-LifecycleFixtureEvaluation $fixture
    $missingExpectedReasons = @($ExpectedReasons | Where-Object { $_ -notin @($evaluation.observed_reasons) })
    $passed = (
        @($missingExpectedReasons).Count -eq 0 -and
        @($evaluation.observed_reasons).Count -gt 0 -and
        $evaluation.denied_before_effect_preparation -eq $true -and
        $evaluation.denied_before_host_mutation -eq $true -and
        $evaluation.denied_before_support_upload -eq $true -and
        $evaluation.denied_before_recovery_execution -eq $true -and
        $evaluation.denied_before_remote_dispatch -eq $true -and
        $evaluation.denied_before_production_mutation -eq $true -and
        (Test-NoSideEffects $evaluation.side_effects)
    )
    return [ordered]@{
        id = $Id
        category = $Category
        operation = $OperationId
        status = if ($passed) { "passed" } else { "failed" }
        expected_denied = $true
        observed_denied = (@($evaluation.observed_reasons).Count -gt 0)
        expected_reasons = $ExpectedReasons
        observed_reasons = @($evaluation.observed_reasons)
        missing_expected_reasons = $missingExpectedReasons
        denied_before_effect_preparation = $evaluation.denied_before_effect_preparation
        denied_before_host_mutation = $evaluation.denied_before_host_mutation
        denied_before_support_upload = $evaluation.denied_before_support_upload
        denied_before_recovery_execution = $evaluation.denied_before_recovery_execution
        denied_before_remote_dispatch = $evaluation.denied_before_remote_dispatch
        denied_before_production_mutation = $evaluation.denied_before_production_mutation
        side_effects = $evaluation.side_effects
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
$resolvedRc20LifecycleSupportResultPath = Resolve-RepoPath $Rc20LifecycleSupportResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$operationIntentCatalogResult = Read-Json $resolvedOperationIntentCatalogResultPath
$script:operationIntentCatalog = Read-Json $resolvedOperationIntentCatalogPath
$journalSnapshotResult = Read-Json $resolvedJournalSnapshotResultPath
$script:transactionJournalPackage = Read-Json $resolvedTransactionJournalPackagePath
$script:snapshotBaselinePackage = Read-Json $resolvedSnapshotBaselinePackagePath
$script:rc20LifecycleSupportResult = Read-Json $resolvedRc20LifecycleSupportResultPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-011"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-012"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-012" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-020" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsFixtures = (
    $contractText.Contains("Verify lifecycle operation fail-closed fixtures") -and
    $contractText.Contains("Every RC21 gate must deny before effect") -and
    $contractText.Contains("support-upload") -and
    $contractText.Contains("recovery-execution")
)

$requiredIntentIds = @("install", "update", "repair-reinstall", "downgrade-rollback", "support-export", "recovery-reference")
$script:expectedOperationIntentCatalogId = [string]$script:operationIntentCatalog.operation_intent_catalog_id
$script:expectedTransactionJournalPackageId = [string]$script:transactionJournalPackage.transaction_journal_package_id
$script:expectedSnapshotBaselinePackageId = [string]$script:snapshotBaselinePackage.snapshot_baseline_package_id
$script:expectedReleaseBundleId = [string]$script:rc20LifecycleSupportResult.release_bundle_id
$script:expectedTargetStateId = [string]$script:rc20LifecycleSupportResult.target_state_id
$script:expectedUpdatedStateId = [string]$script:rc20LifecycleSupportResult.updated_image_state_id
$script:expectedRestoredStateId = [string]$script:rc20LifecycleSupportResult.restored_target_state_id

$script:expectedIntentByOperation = @{}
foreach ($intent in @($script:operationIntentCatalog.operation_intents)) {
    $script:expectedIntentByOperation[[string]$intent.id] = $intent
}
$script:expectedJournalEntryByOperation = @{}
foreach ($entry in @($script:transactionJournalPackage.entries)) {
    $script:expectedJournalEntryByOperation[[string]$entry.operation] = $entry
}

$catalogReady = (
    $operationIntentCatalogResult.status -eq "passed" -and
    $script:operationIntentCatalog.status -eq "local-operation-intent-catalog-bound-non-ga" -and
    @($requiredIntentIds | Where-Object { $_ -in @($script:operationIntentCatalog.operation_intents | ForEach-Object { $_.id }) }).Count -eq 6
)
$journalSnapshotReady = (
    $journalSnapshotResult.status -eq "passed" -and
    $journalSnapshotResult.summary.rc21_011_complete -eq $true -and
    $script:transactionJournalPackage.entry_count -eq 6 -and
    $script:transactionJournalPackage.executable_by_journal -eq $false -and
    $script:snapshotBaselinePackage.projection_only -eq $true -and
    $script:snapshotBaselinePackage.authority.host_rootfs_mutation_authority -eq $false -and
    $script:snapshotBaselinePackage.authority.active_artifact_set_mutation_authority -eq $false
)
$rc20StateReady = (
    $script:rc20LifecycleSupportResult.status -eq "passed" -and
    -not [string]::IsNullOrWhiteSpace($script:expectedTargetStateId) -and
    -not [string]::IsNullOrWhiteSpace($script:expectedUpdatedStateId) -and
    -not [string]::IsNullOrWhiteSpace($script:expectedRestoredStateId)
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
    rc20_lifecycle_support_result = New-ArtifactRef $resolvedRc20LifecycleSupportResultPath $script:rc20LifecycleSupportResult "rc20 lifecycle support result"
}

$cases = @()
foreach ($operationId in $requiredIntentIds) {
    $cases += Invoke-Case "operation-$operationId-dry-run-required" "operation-gate" $operationId @("dry-run-gate-required") { param($f) $f.requests.effect_preparation = $true }
}
$cases += Invoke-Case "missing-rc20-lifecycle-support" "source" "install" @("rc20-lifecycle-support-required") { param($f) $f.sources.rc20_lifecycle_support_bound = $false }
$cases += Invoke-Case "stale-rc20-lifecycle-support" "source" "update" @("stale-rc20-lifecycle-support-denied") { param($f) $f.sources.rc20_lifecycle_support_stale = $true }
$cases += Invoke-Case "rc20-state-identity-mismatch" "source" "repair-reinstall" @("rc20-state-identity-mismatch-denied") { param($f) $f.sources.target_state_id = "sha256:0000000000000000000000000000000000000000000000000000000000000000" }
$cases += Invoke-Case "operation-intent-catalog-mismatch" "intent" "install" @("operation-intent-catalog-mismatch-denied") { param($f) $f.sources.operation_intent_catalog_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
$cases += Invoke-Case "operation-intent-id-mismatch" "intent" "update" @("operation-intent-mismatch-denied") { param($f) $f.operation.operation_intent_id = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }
$cases += Invoke-Case "operation-kind-mismatch" "intent" "repair-reinstall" @("operation-intent-mismatch-denied") { param($f) $f.operation.kind = "downgrade-rollback" }
$cases += Invoke-Case "unknown-operation-intent" "intent" "install" @("unknown-operation-intent-denied") { param($f) $f.operation.id = "global-system-upgrade"; $f.operation.kind = "global-system-upgrade" }
$cases += Invoke-Case "broad-operation-scope" "scope" "install" @("broad-operation-scope-denied") { param($f) $f.operation.broad_scope = $true; $f.operation.requested_scope = "host-wide-lifecycle" }
$cases += Invoke-Case "missing-transaction-journal-entry" "journal" "install" @("transaction-journal-entry-required") { param($f) $f.journal.entry_bound = $false }
$cases += Invoke-Case "stale-transaction-journal" "journal" "update" @("stale-transaction-journal-denied") { param($f) $f.journal.stale = $true }
$cases += Invoke-Case "transaction-journal-package-mismatch" "journal" "update" @("transaction-journal-package-mismatch-denied") { param($f) $f.journal.transaction_journal_package_id = "sha256:3333333333333333333333333333333333333333333333333333333333333333" }
$cases += Invoke-Case "transaction-id-mismatch" "journal" "repair-reinstall" @("transaction-id-mismatch-denied") { param($f) $f.journal.transaction_id = "sha256:4444444444444444444444444444444444444444444444444444444444444444" }
$cases += Invoke-Case "missing-audit-sink" "journal" "support-export" @("audit-sink-required") { param($f) $f.journal.audit_sink_bound = $false; $f.journal.audit_sink_id = "" }
$cases += Invoke-Case "missing-resume-checkpoint" "journal" "recovery-reference" @("resume-checkpoint-required") { param($f) $f.journal.resume_checkpoint_bound = $false; $f.journal.checkpoint_id = "" }
$cases += Invoke-Case "missing-rollback-snapshot-reference" "journal" "downgrade-rollback" @("rollback-snapshot-reference-required") { param($f) $f.journal.rollback_snapshot_reference_bound = $false; $f.journal.rollback_snapshot_id = "" }
$cases += Invoke-Case "missing-snapshot-baseline" "snapshot" "install" @("snapshot-baseline-required") { param($f) $f.snapshot.baseline_bound = $false }
$cases += Invoke-Case "stale-snapshot-baseline" "snapshot" "update" @("stale-snapshot-baseline-denied") { param($f) $f.snapshot.stale = $true }
$cases += Invoke-Case "snapshot-package-mismatch" "snapshot" "update" @("snapshot-baseline-package-mismatch-denied") { param($f) $f.snapshot.snapshot_baseline_package_id = "sha256:5555555555555555555555555555555555555555555555555555555555555555" }
$cases += Invoke-Case "source-snapshot-mismatch" "snapshot" "repair-reinstall" @("snapshot-reference-mismatch-denied") { param($f) $f.snapshot.source_snapshot_id = "sha256:6666666666666666666666666666666666666666666666666666666666666666" }
$cases += Invoke-Case "target-snapshot-mismatch" "snapshot" "downgrade-rollback" @("snapshot-reference-mismatch-denied") { param($f) $f.snapshot.target_snapshot_id = "sha256:7777777777777777777777777777777777777777777777777777777777777777" }
$cases += Invoke-Case "rollback-snapshot-mismatch" "snapshot" "support-export" @("snapshot-reference-mismatch-denied") { param($f) $f.snapshot.rollback_snapshot_id = "sha256:8888888888888888888888888888888888888888888888888888888888888888" }
$cases += Invoke-Case "snapshot-authority-broadening" "snapshot" "recovery-reference" @("snapshot-authority-broadening-denied") { param($f) $f.snapshot.projection_only = $false; $f.snapshot.host_boot_state_authority = $true }
$cases += Invoke-Case "effect-preparation-before-dry-run" "effect" "install" @("dry-run-gate-required") { param($f) $f.requests.effect_preparation = $true }
$cases += Invoke-Case "effect-execution-authority" "effect" "update" @("effect-execution-authority-denied") { param($f) $f.authority.effect_execution_authority = $true }
$cases += Invoke-Case "host-rootfs-mutation-request" "host" "install" @("host-mutation-denied") { param($f) $f.requests.host_rootfs_mutation = $true }
$cases += Invoke-Case "host-active-slot-mutation-request" "host" "update" @("host-mutation-denied") { param($f) $f.requests.host_active_slot_mutation = $true }
$cases += Invoke-Case "host-boot-metadata-mutation-request" "host" "downgrade-rollback" @("host-mutation-denied") { param($f) $f.requests.host_boot_metadata_mutation = $true }
$cases += Invoke-Case "active-artifact-set-mutation-request" "host" "repair-reinstall" @("host-mutation-denied") { param($f) $f.requests.active_artifact_set_mutation = $true }
$cases += Invoke-Case "production-ring-mutation-request" "production" "downgrade-rollback" @("production-ring-mutation-denied") { param($f) $f.requests.production_ring_mutation = $true }
$cases += Invoke-Case "remote-dependency-request" "remote" "update" @("remote-dependency-denied") { param($f) $f.requests.remote_dependency = $true }
$cases += Invoke-Case "signer-authority-request" "authority" "install" @("signer-authority-denied") { param($f) $f.requests.signer_authority = $true }
$cases += Invoke-Case "object-storage-request" "authority" "install" @("object-storage-provisioning-denied") { param($f) $f.requests.object_storage_provisioning = $true }
$cases += Invoke-Case "support-upload-request" "support" "support-export" @("support-upload-denied") { param($f) $f.requests.support_upload = $true }
$cases += Invoke-Case "recovery-execution-request" "recovery" "recovery-reference" @("recovery-execution-denied") { param($f) $f.requests.recovery_execution = $true }
$cases += Invoke-Case "endpoint-authority-claim" "non-authority" "install" @("non-authoritative-surface-denied") { param($f) $f.requests.endpoint_authority = $true }
$cases += Invoke-Case "shell-authority-claim" "non-authority" "update" @("non-authoritative-surface-denied") { param($f) $f.requests.shell_output_authority = $true }
$cases += Invoke-Case "tui-authority-claim" "non-authority" "repair-reinstall" @("non-authoritative-surface-denied") { param($f) $f.requests.tui_authority = $true }
$cases += Invoke-Case "model-replay-authority-claim" "non-authority" "downgrade-rollback" @("non-authoritative-surface-denied") { param($f) $f.requests.model_replay_authority = $true }
$cases += Invoke-Case "ga-claim" "production" "install" @("ga-claim-denied") { param($f) $f.requests.ga_claim = $true }

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$coverageCategories = @($cases | ForEach-Object { $_.category } | Select-Object -Unique)
$coveredReasons = @($cases | ForEach-Object { $_.observed_reasons } | Select-Object -Unique)

$matrix = [ordered]@{
    schema = "agentos.rc21-lifecycle-operation-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC21-012"
    status = if (@($failedCases).Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    operation_intent_catalog_id = $script:expectedOperationIntentCatalogId
    transaction_journal_package_id = $script:expectedTransactionJournalPackageId
    snapshot_baseline_package_id = $script:expectedSnapshotBaselinePackageId
    case_count = @($cases).Count
    failed_case_count = @($failedCases).Count
    coverage_categories = $coverageCategories
    covered_reasons = $coveredReasons
    cases = $cases
    source = $source
}
$matrixPath = Join-Path $resolvedArtifactDir "fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$allCasesDenyBeforeEffect = @($cases | Where-Object {
    $_.observed_denied -ne $true -or
    $_.denied_before_effect_preparation -ne $true -or
    $_.denied_before_host_mutation -ne $true -or
    $_.denied_before_support_upload -ne $true -or
    $_.denied_before_recovery_execution -ne $true -or
    $_.denied_before_remote_dispatch -ne $true -or
    $_.denied_before_production_mutation -ne $true -or
    -not (Test-NoSideEffects $_.side_effects)
}).Count -eq 0

Add-Check "plan.current_task.rc21_012" $planAllowsRun "RC21-012 must run after RC21-011 completed, with current_task set to RC21-012 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_011_status = $previousTaskStatus; rc21_012_status = $currentTaskStatus })
Add-Check "contract.fail_closed_authority.present" $contractAllowsFixtures "RC21-012 must consume the RC21 fail-closed contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "catalog.ready" $catalogReady "Fail-closed fixtures must bind the completed operation intent catalog." ([ordered]@{ result_status = $operationIntentCatalogResult.status; catalog_status = $script:operationIntentCatalog.status; intent_count = @($script:operationIntentCatalog.operation_intents).Count })
Add-Check "journal_snapshot.ready" $journalSnapshotReady "Fail-closed fixtures must bind the completed transaction journal and projection-only snapshot baseline packages." ([ordered]@{ result_status = $journalSnapshotResult.status; journal_entry_count = $script:transactionJournalPackage.entry_count; snapshot_projection_only = $script:snapshotBaselinePackage.projection_only })
Add-Check "rc20.state.ready" $rc20StateReady "Fixtures must bind RC20 target, updated, and restored lifecycle states." ([ordered]@{ target_state_id = $script:expectedTargetStateId; updated_image_state_id = $script:expectedUpdatedStateId; restored_target_state_id = $script:expectedRestoredStateId })
Add-Check "fixtures.required_coverage" (@($failedCases).Count -eq 0 -and @($cases).Count -ge 30 -and @($requiredIntentIds | Where-Object { $_ -in @($cases | ForEach-Object { $_.operation }) }).Count -eq 6) "Fixtures must cover required lifecycle intents and fail-closed categories." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases).Count; categories = $coverageCategories })
Add-Check "fixtures.required_reasons.covered" (@("rc20-lifecycle-support-required", "stale-rc20-lifecycle-support-denied", "operation-intent-mismatch-denied", "transaction-id-mismatch-denied", "snapshot-reference-mismatch-denied", "broad-operation-scope-denied", "host-mutation-denied", "remote-dependency-denied", "signer-authority-denied", "support-upload-denied", "recovery-execution-denied", "ga-claim-denied" | Where-Object { $_ -notin $coveredReasons }).Count -eq 0) "Fixtures must cover missing/stale RC20 evidence, intent, journal, snapshot, broad scope, host, remote, signer, support, recovery, and GA denial reasons." $coveredReasons
Add-Check "fixtures.deny_before_effects" $allCasesDenyBeforeEffect "All fixtures must fail closed before effect preparation, host mutation, support upload, recovery execution, remote dispatch, or production mutation." ([ordered]@{ failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $matrixPath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "Fixture outputs must be local-only and contain no private material, tokens, raw secrets, or endpoint authority claims." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-lifecycle-operation-fail-closed-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-012"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    operation_intent_catalog_id = $script:expectedOperationIntentCatalogId
    transaction_journal_package_id = $script:expectedTransactionJournalPackageId
    snapshot_baseline_package_id = $script:expectedSnapshotBaselinePackageId
    outputs = [ordered]@{
        fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
            case_count = @($cases).Count
            failed_case_count = @($failedCases).Count
        }
    }
    fail_closed_surface = [ordered]@{
        state = "lifecycle-operation-fixtures-fail-closed-before-effect"
        fixture_count = @($cases).Count
        failed_fixture_count = @($failedCases).Count
        all_cases_denied_before_effect = $allCasesDenyBeforeEffect
        required_intents = $requiredIntentIds
        coverage_categories = $coverageCategories
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        endpoint_authority = $false
    }
    source = $source
    checks = @($script:checks)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        lifecycle_operation_effect_preparation_performed = $false
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
        signer_authority = $false
        object_storage_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        endpoint_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc21_012_complete = (@($script:failedChecks).Count -eq 0)
        all_cases_denied_before_effect = $allCasesDenyBeforeEffect
        operation_intent_catalog_id = $script:expectedOperationIntentCatalogId
        transaction_journal_package_id = $script:expectedTransactionJournalPackageId
        snapshot_baseline_package_id = $script:expectedSnapshotBaselinePackageId
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-020"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-012-lifecycle-operation-fail-closed.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-lifecycle-operation-fail-closed-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-012"
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
    fail_closed_surface = $result.fail_closed_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-020"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-012 outputs." }

Write-Host "RC21 lifecycle operation fail-closed $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Fail-closed matrix: $(Get-StablePath $matrixPath)"
Write-Host "Cases: $(@($cases).Count); failed cases: $(@($failedCases).Count); all denied before effect: $allCasesDenyBeforeEffect"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
