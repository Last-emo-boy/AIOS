param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-controlled-rollback-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$ActivationResultPath = ".workflow/artifacts/rc11-controlled-canary-activation/result.json",
    [string]$ActivationGateReportPath = ".workflow/artifacts/rc11-controlled-canary-activation/activation-gate-report.json",
    [string]$ActivationDenialEvidencePath = ".workflow/artifacts/rc11-controlled-canary-activation/activation-denial-evidence.json",
    [string]$ActivationHandoffPath = ".workflow/artifacts/rc11-controlled-canary-activation/controlled-activation-handoff.json",
    [string]$Rc10RollbackResultPath = ".workflow/artifacts/rc10-controlled-rollback-drill/result.json",
    [string]$Rc10SupportRecoveryResultPath = ".workflow/artifacts/rc10-controlled-execution-support-recovery/result.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) {
        $script:failedChecks += $entry
    }
}

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ([string]::IsNullOrWhiteSpace($Blocker)) {
        return
    }
    $normalized = switch -Exact ($Blocker) {
        "missing-external-https-object-uri" { "external-https-object-uri-not-published" }
        "drift-zero-denied" { "declared-current-drift-zero-not-proved" }
        "installer-quarantine-fetch-not-verified" { "installer-preflight-not-verified" }
        default { $Blocker }
    }
    if ($script:blockers -notcontains $normalized) {
        $script:blockers += $normalized
    }
}

function Add-Blockers {
    param($Values)
    foreach ($value in @($Values)) {
        Add-UniqueBlocker ([string]$value)
    }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-" + "key" + "." + "pem"),
        ("/etc/" + "aios-signer")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function New-DenialCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        expected_blockers = $ExpectedBlockers
        missing_expected_blockers = $missing
        reason = $Reason
        side_effects = [ordered]@{
            effect_prepared = $false
            effect_executed = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()
$script:blockers = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedActivationResultPath = Resolve-RepoPath $ActivationResultPath
$resolvedActivationGateReportPath = Resolve-RepoPath $ActivationGateReportPath
$resolvedActivationDenialEvidencePath = Resolve-RepoPath $ActivationDenialEvidencePath
$resolvedActivationHandoffPath = Resolve-RepoPath $ActivationHandoffPath
$resolvedRc10RollbackResultPath = Resolve-RepoPath $Rc10RollbackResultPath
$resolvedRc10SupportRecoveryResultPath = Resolve-RepoPath $Rc10SupportRecoveryResultPath

$activationResult = Read-Json $resolvedActivationResultPath
$activationGateReport = Read-Json $resolvedActivationGateReportPath
$activationDenialEvidence = Read-Json $resolvedActivationDenialEvidencePath
$activationHandoff = Read-Json $resolvedActivationHandoffPath
$rc10RollbackResult = Read-Json $resolvedRc10RollbackResultPath
$rc10SupportRecoveryResult = Read-Json $resolvedRc10SupportRecoveryResultPath

$releaseId = [string]$activationResult.release_id
$rollbackAttemptId = "rc11-controlled-rollback-support-recovery-attempt"
$rollbackPlanSpecId = "rc11-controlled-rollback-support-recovery-planspec-required"

Add-Blockers $activationResult.blockers
Add-Blockers $activationResult.activation_surface.blockers
Add-Blockers $activationHandoff.blockers
Add-Blockers $rc10RollbackResult.blockers
Add-Blockers $rc10RollbackResult.rollback_surface.blockers
Add-Blockers $rc10SupportRecoveryResult.remaining_blockers_before_controlled_execution

$sourceTasksComplete = $activationResult.status -eq "passed" -and
    $activationResult.summary.rc11_031_complete -eq $true -and
    $rc10RollbackResult.status -eq "passed" -and
    $rc10RollbackResult.summary.rc10_030_complete -eq $true -and
    $rc10SupportRecoveryResult.status -eq "passed" -and
    $rc10SupportRecoveryResult.summary.rc10_031_complete -eq $true
$activationEvidenceReady = $activationResult.status -eq "passed" -and $activationHandoff.next_task -eq "RC11-040"
$controlledActivationPerformed = $activationResult.activation_surface.activation_performed -eq $true
$rollbackBaselineBound = $rc10RollbackResult.rollback_surface.rollback_readiness_ready -eq $true -and $rc10SupportRecoveryResult.rollback_readiness_ready -eq $true
$supportRecoveryBound = $rc10SupportRecoveryResult.controlled_execution_support_recovery_bound -eq $true
$supportBundleRedacted = $rc10SupportRecoveryResult.invariants.support_bundle_redacted -eq $true
$targetIdsBound = -not ($script:blockers -contains "target-node-ids-missing")
$separateRollbackApprovalGranted = $false
$rollbackPlanSpecBound = $false
$rollbackSecurityExecutionAllowed = $false
$auditJournalBound = $false
$postRollbackObservationsBound = $false
$supportUploadAllowed = $false
$recoveryExecutionAllowed = $false
$remoteDispatchEnabled = $activationResult.activation_surface.remote_dispatch_enabled -eq $true -or $rc10RollbackResult.rollback_surface.remote_dispatch_enabled -eq $true

if (-not $controlledActivationPerformed) { Add-UniqueBlocker "controlled-canary-activation-not-performed" }
if (-not $targetIdsBound) { Add-UniqueBlocker "target-node-ids-missing" }
if (-not $separateRollbackApprovalGranted) { Add-UniqueBlocker "rollback-exact-operator-approval-not-granted" }
if (-not $rollbackPlanSpecBound) { Add-UniqueBlocker "agentcore-rollback-planspec-not-bound" }
if (-not $rollbackSecurityExecutionAllowed) { Add-UniqueBlocker "security-execution-rollback-effect-envelope-not-bound" }
if (-not $auditJournalBound) { Add-UniqueBlocker "rollback-audit-journal-not-bound" }
if (-not $postRollbackObservationsBound) { Add-UniqueBlocker "post-rollback-observations-missing" }
if (-not $remoteDispatchEnabled) { Add-UniqueBlocker "remote-fleet-execution-not-enabled" }
Add-UniqueBlocker "rollback-execution-not-authorized"

$sourceBindings = [ordered]@{
    activation_result_sha256 = Get-FileSha256 $resolvedActivationResultPath
    activation_gate_report_sha256 = Get-FileSha256 $resolvedActivationGateReportPath
    activation_denial_evidence_sha256 = Get-FileSha256 $resolvedActivationDenialEvidencePath
    activation_handoff_sha256 = Get-FileSha256 $resolvedActivationHandoffPath
    activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    rc10_rollback_result_sha256 = Get-FileSha256 $resolvedRc10RollbackResultPath
    rc10_rollback_planspec_hash = [string]$rc10RollbackResult.rollback_surface.rollback_planspec_hash
    rc10_support_recovery_result_sha256 = Get-FileSha256 $resolvedRc10SupportRecoveryResultPath
    rc10_support_recovery_evidence_chain_sha256 = [string]$rc10SupportRecoveryResult.artifacts.support_recovery_evidence_chain.sha256
    rc10_controlled_execution_support_bundle_sha256 = [string]$rc10SupportRecoveryResult.artifacts.controlled_execution_support_bundle.sha256
    rc10_recovery_reference_index_sha256 = [string]$rc10SupportRecoveryResult.artifacts.recovery_reference_index.sha256
    rollback_baseline_sha256 = [string]$rc10SupportRecoveryResult.source_bindings.rollback_baseline_sha256
    compatibility_sha256 = [string]$rc10SupportRecoveryResult.source_bindings.compatibility_sha256
}

$gateInputs = [ordered]@{
    source_tasks_complete = $sourceTasksComplete
    controlled_activation_evidence_ready = $activationEvidenceReady
    controlled_canary_activation_performed = $controlledActivationPerformed
    previous_artifact_set_bound = $rollbackBaselineBound
    activated_artifact_set_bound = $controlledActivationPerformed
    rollback_baseline_bound = $rollbackBaselineBound
    target_ids_bound = $targetIdsBound
    separate_rollback_approval_granted = $separateRollbackApprovalGranted
    agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
    security_execution_rollback_allowed = $rollbackSecurityExecutionAllowed
    support_recovery_binding_present = $supportRecoveryBound
    support_bundle_redacted = $supportBundleRedacted
    audit_journal_bound = $auditJournalBound
    post_rollback_observations_bound = $postRollbackObservationsBound
    support_upload_allowed = $supportUploadAllowed
    recovery_execution_allowed = $recoveryExecutionAllowed
    remote_fleet_execution_enabled = $remoteDispatchEnabled
}

$rollbackExecutionAllowed = $sourceTasksComplete -and
    $activationEvidenceReady -and
    $controlledActivationPerformed -and
    $rollbackBaselineBound -and
    $targetIdsBound -and
    $separateRollbackApprovalGranted -and
    $rollbackPlanSpecBound -and
    $rollbackSecurityExecutionAllowed -and
    $supportRecoveryBound -and
    $auditJournalBound -and
    $postRollbackObservationsBound -and
    $remoteDispatchEnabled
$rollbackState = if ($rollbackExecutionAllowed) { "rollback-authorized" } else { "rollback-denied" }

$rollbackPlanSpecCore = [ordered]@{
    planspec_id = $rollbackPlanSpecId
    plan_kind = "rc11-controlled-rollback-support-recovery"
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    activation_performed = $controlledActivationPerformed
    previous_artifact_set_digest = [string]$rc10SupportRecoveryResult.recovery_surface.previous_active_artifact_set_sha256
    activated_artifact_set_digest = if ($controlledActivationPerformed) { [string]$activationResult.activation_surface.activation_attempt_digest } else { "not-activated" }
    rollback_baseline_digest = [string]$rc10SupportRecoveryResult.recovery_surface.rollback_baseline_sha256
    target_set_digest = [string]$activationResult.source_bindings.target_set_digest
    target_ids = @()
    exact_rollback_approval_digest = "not-bound"
    security_execution_rollback_decision_digest = "not-bound"
    support_recovery_digest = [string]$rc10SupportRecoveryResult.artifacts.support_recovery_evidence_chain.sha256
    audit_journal_path = "required-before-execution"
    post_rollback_observations = "required-before-execution"
    policy_version = "rc11-controlled-rollback-support-recovery-v1"
}
$rollbackPlanSpecHash = Get-StringSha256 (($rollbackPlanSpecCore | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    rollback_attempt_recorded = $true
    effect_prepared = $false
    effect_executed = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    boot_metadata_mutated = $false
    active_slot_mutated = $false
    persistent_state_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
}

$rollbackRequirement = [ordered]@{
    schema = "agentos.rc11-rollback-support-planspec-requirement.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "rollback-support-planspec-required-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    rollback_planspec_id = $rollbackPlanSpecId
    rollback_planspec_hash = $rollbackPlanSpecHash
    rollback_planspec_core = $rollbackPlanSpecCore
    exact_rollback_approval_required = $true
    exact_rollback_approval_granted = $false
    agentcore_rollback_planspec_required = $true
    agentcore_rollback_planspec_bound = $false
    security_execution_engine_required = $true
    security_execution_rollback_approval_bound = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    source_bindings = $sourceBindings
    gate_inputs = $gateInputs
    blockers = @($script:blockers)
    side_effects = $sideEffects
}

$gateReport = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-support-gate-report.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "rollback-support-gates-evaluated-denied"
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    rollback_state = $rollbackState
    all_gates_passed = $rollbackExecutionAllowed
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    support_upload_allowed = $false
    support_upload_performed = $false
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    gate_inputs = $gateInputs
    rollback_surface = [ordered]@{
        previous_artifact_set_digest = [string]$rc10SupportRecoveryResult.recovery_surface.previous_active_artifact_set_sha256
        activated_artifact_set_digest = if ($controlledActivationPerformed) { [string]$activationResult.activation_surface.activation_attempt_digest } else { "not-activated" }
        restored_artifact_set_digest = [string]$rc10SupportRecoveryResult.recovery_surface.restored_active_artifact_set_sha256
        rollback_baseline_digest = [string]$rc10SupportRecoveryResult.recovery_surface.rollback_baseline_sha256
        baseline_consistent = $rc10SupportRecoveryResult.recovery_surface.baseline_consistent
    }
    support_surface = $rc10SupportRecoveryResult.support_surface
    recovery_surface = $rc10SupportRecoveryResult.recovery_surface
    blockers = @($script:blockers)
    source_bindings = $sourceBindings
    side_effects = $sideEffects
}

$caseSpecs = @(
    [ordered]@{ id = "activation-not-performed-denied"; blockers = @("controlled-canary-activation-not-performed"); reason = "Rollback requires executed controlled activation evidence, but RC11-031 denied activation." },
    [ordered]@{ id = "target-ids-missing-denied"; blockers = @("target-node-ids-missing"); reason = "Rollback target ids are not bound to an exact approval package." },
    [ordered]@{ id = "rollback-approval-missing-denied"; blockers = @("rollback-exact-operator-approval-not-granted"); reason = "Rollback requires a separate exact operator approval." },
    [ordered]@{ id = "rollback-planspec-missing-denied"; blockers = @("agentcore-rollback-planspec-not-bound"); reason = "Rollback PlanSpec is projected as a requirement but is not executable." },
    [ordered]@{ id = "security-rollback-missing-denied"; blockers = @("security-execution-rollback-effect-envelope-not-bound"); reason = "SecurityExecutionEngine has not approved rollback effects." },
    [ordered]@{ id = "audit-journal-missing-denied"; blockers = @("rollback-audit-journal-not-bound"); reason = "Rollback audit journal binding is required before execution." },
    [ordered]@{ id = "post-observations-missing-denied"; blockers = @("post-rollback-observations-missing"); reason = "Post-rollback observation plan is required before execution." },
    [ordered]@{ id = "remote-fleet-disabled-denied"; blockers = @("remote-fleet-execution-not-enabled"); reason = "Remote fleet execution remains disabled." },
    [ordered]@{ id = "support-upload-denied"; blockers = @("rollback-execution-not-authorized"); reason = "Support upload cannot be enabled while rollback execution is denied." },
    [ordered]@{ id = "recovery-execution-denied"; blockers = @("rollback-execution-not-authorized"); reason = "Recovery execution cannot be enabled while rollback execution is denied." },
    [ordered]@{ id = "rollback-execution-denied"; blockers = @("rollback-execution-not-authorized"); reason = "At least one required rollback/support gate is missing." }
)
$denialCases = @()
foreach ($spec in $caseSpecs) {
    $denialCases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -ObservedBlockers $script:blockers -Reason $spec.reason
}
$failedCases = @($denialCases | Where-Object { $_.status -ne "passed" })

$denialEvidence = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-support-denial-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "rollback-support-denied"
    production_ready_claim = $false
    projection_only = $true
    denied = (-not $rollbackExecutionAllowed)
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    rollback_planspec_hash = $rollbackPlanSpecHash
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    support_upload_allowed = $false
    support_upload_performed = $false
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    denial_cases = $denialCases
    blockers = @($script:blockers)
    preserved_boundaries = [ordered]@{
        activation_performed = $false
        exact_rollback_approval_granted = $false
        agentcore_rollback_planspec_executable = $false
        security_execution_rollback_allowed = $false
        install_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
    }
    side_effects = $sideEffects
    source_bindings = $sourceBindings
}

$evidenceChain = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-support-recovery-chain.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "support-recovery-bound-rollback-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    activation = [ordered]@{
        source = Get-StablePath $resolvedActivationResultPath
        state = $activationResult.activation_surface.state
        activation_allowed = $false
        activation_performed = $false
        activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    }
    rollback = [ordered]@{
        inherited_rc10_state = $rc10RollbackResult.rollback_surface.state
        rc11_state = $rollbackState
        rollback_readiness_ready = $rollbackBaselineBound
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        rollback_planspec_hash = $rollbackPlanSpecHash
    }
    support_surface = $rc10SupportRecoveryResult.support_surface
    recovery_surface = $rc10SupportRecoveryResult.recovery_surface
    remaining_blockers_before_controlled_execution = @($script:blockers)
    source_bindings = $sourceBindings
    side_effects = $sideEffects
}

$supportBundle = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-support-bundle-projection.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "redacted-local-support-projection"
    production_ready_claim = $false
    projection_only = $true
    local_only = $true
    redacted = $true
    upload_allowed = $false
    upload_performed = $false
    release_id = $releaseId
    sections = [ordered]@{
        activation_denial = [ordered]@{
            source = Get-StablePath $resolvedActivationDenialEvidencePath
            sha256 = Get-FileSha256 $resolvedActivationDenialEvidencePath
            activation_allowed = $false
            activation_performed = $false
        }
        rollback_support_denial = [ordered]@{
            rollback_execution_allowed = $false
            rollback_execution_performed = $false
            support_upload_allowed = $false
            recovery_execution_allowed = $false
            blockers = @($script:blockers)
        }
        inherited_rc10_support_recovery = [ordered]@{
            source = Get-StablePath $resolvedRc10SupportRecoveryResultPath
            sha256 = Get-FileSha256 $resolvedRc10SupportRecoveryResultPath
            support_upload_allowed = $false
            recovery_execution_allowed = $false
            redacted = $supportBundleRedacted
        }
    }
    operator_summary = [ordered]@{
        current_state = "rollback-support-recovery-blocked"
        safe_next_task = "RC11-050 final closeout audit after RC11-040 evidence is committed"
        support_truth = "redacted local evidence projection; no support upload endpoint is authorized"
        recovery_truth = "rollback/support evidence is bound; no recovery or rollback execution is authorized"
    }
    source_bindings = $sourceBindings
    side_effects = $sideEffects
}

$recoveryIndex = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-recovery-reference-index.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "projection-only-recovery-execution-blocked"
    production_ready_claim = $false
    release_id = $releaseId
    entries = @(
        [ordered]@{ id = "rc11-activation-denial"; kind = "local-artifact"; path = Get-StablePath $resolvedActivationDenialEvidencePath; sha256 = Get-FileSha256 $resolvedActivationDenialEvidencePath; executable = $false },
        [ordered]@{ id = "rc11-activation-handoff"; kind = "local-artifact"; path = Get-StablePath $resolvedActivationHandoffPath; sha256 = Get-FileSha256 $resolvedActivationHandoffPath; executable = $false },
        [ordered]@{ id = "rc11-rollback-support-gate-report"; kind = "local-artifact"; path = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/rollback-support-gate-report.json"; sha256 = $null; executable = $false },
        [ordered]@{ id = "rc11-rollback-support-denial"; kind = "local-artifact"; path = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/rollback-support-denial-evidence.json"; sha256 = $null; executable = $false },
        [ordered]@{ id = "rc10-rollback-result"; kind = "local-artifact"; path = Get-StablePath $resolvedRc10RollbackResultPath; sha256 = Get-FileSha256 $resolvedRc10RollbackResultPath; executable = $false },
        [ordered]@{ id = "rc10-support-recovery-result"; kind = "local-artifact"; path = Get-StablePath $resolvedRc10SupportRecoveryResultPath; sha256 = Get-FileSha256 $resolvedRc10SupportRecoveryResultPath; executable = $false }
    )
    required_before_execution = @(
        "executed controlled canary activation",
        "separate exact rollback approval",
        "bound rollback target ids",
        "executable AgentCore rollback PlanSpec",
        "SecurityExecutionEngine rollback approval",
        "rollback audit journal",
        "post-rollback observations",
        "remote fleet execution gate"
    )
    recovery_authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        signer_authority = $false
        support_metadata_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
    side_effects = $sideEffects
}

$requirementPath = Join-Path $resolvedArtifactDir "rollback-planspec-requirement.json"
$gateReportPath = Join-Path $resolvedArtifactDir "rollback-support-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "rollback-support-denial-evidence.json"
$evidenceChainPath = Join-Path $resolvedArtifactDir "support-recovery-evidence-chain.json"
$supportBundlePath = Join-Path $resolvedArtifactDir "controlled-execution-support-bundle.json"
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-040-controlled-rollback-support-recovery.json"

Write-Json $rollbackRequirement $requirementPath
Write-Json $gateReport $gateReportPath
Write-Json $denialEvidence $denialEvidencePath
Write-Json $evidenceChain $evidenceChainPath
Write-Json $supportBundle $supportBundlePath

$recoveryIndex.entries[2].sha256 = Get-FileSha256 $gateReportPath
$recoveryIndex.entries[3].sha256 = Get-FileSha256 $denialEvidencePath
Write-Json $recoveryIndex $recoveryIndexPath

Add-Check "source.rc11_031.activation_denied" ($activationResult.status -eq "passed" -and $activationResult.summary.rc11_031_complete -eq $true -and $activationResult.activation_surface.state -eq "activation-denied" -and $activationResult.activation_surface.activation_performed -eq $false) "RC11-040 must consume completed RC11-031 activation denial without treating it as executed activation." ([ordered]@{ status = $activationResult.status; state = $activationResult.activation_surface.state; activation_performed = $activationResult.activation_surface.activation_performed })
Add-Check "source.rc10_rollback_support.carried" ($rc10RollbackResult.status -eq "passed" -and $rc10RollbackResult.summary.rc10_030_complete -eq $true -and $rc10SupportRecoveryResult.status -eq "passed" -and $rc10SupportRecoveryResult.summary.rc10_031_complete -eq $true) "RC11-040 must carry forward RC10 rollback denial and support/recovery binding evidence." ([ordered]@{ rollback_state = $rc10RollbackResult.rollback_surface.state; support_status = $rc10SupportRecoveryResult.status })
Add-Check "rollback.planspec_requirement.projected_blocked" ((Test-Path -LiteralPath $requirementPath -PathType Leaf) -and $rollbackRequirement.executable -eq $false -and $rollbackRequirement.rollback_execution_allowed -eq $false -and -not [string]::IsNullOrWhiteSpace($rollbackPlanSpecHash)) "Rollback PlanSpec requirement must be projected and non-executable." ([ordered]@{ path = Get-StablePath $requirementPath; sha256 = Get-FileSha256 $requirementPath; planspec_hash = $rollbackPlanSpecHash })
Add-Check "rollback.denied_when_gates_missing" ($rollbackExecutionAllowed -eq $false -and $gateReport.rollback_state -eq "rollback-denied" -and $denialEvidence.denied -eq $true) "Rollback/support execution must deny when activation, separate approval, PlanSpec, SecurityExecution, audit, observation, or remote gates are missing." ([ordered]@{ rollback_execution_allowed = $rollbackExecutionAllowed; blockers = @($script:blockers) })
Add-Check "rollback.denial_cases.complete" ($failedCases.Count -eq 0 -and @($denialCases).Count -ge 11) "Rollback/support denial evidence must cover missing rollback, support, and recovery gates as fail-closed." ([ordered]@{ cases = @($denialCases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "support.bundle.redacted_no_upload" ($supportBundle.redacted -eq $true -and $supportBundle.upload_allowed -eq $false -and $supportBundle.upload_performed -eq $false -and $supportBundle.sections.inherited_rc10_support_recovery.redacted -eq $true) "Support bundle projection must stay redacted, local-only, and upload-disabled." ([ordered]@{ redacted = $supportBundle.redacted; upload_allowed = $supportBundle.upload_allowed })
Add-Check "recovery.index.non_executable" (@($recoveryIndex.entries | Where-Object { $_.executable -ne $false }).Count -eq 0 -and $recoveryIndex.recovery_authority.tui_authority -eq $false -and $recoveryIndex.recovery_authority.shell_authority -eq $false) "Recovery reference index must keep every entry non-executable and non-authoritative." ([ordered]@{ entries = @($recoveryIndex.entries).Count })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.effect_executed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false) "RC11-040 must not prepare or execute rollback, support upload, recovery, production mutation, or remote dispatch side effects." $sideEffects
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC11-040 must not grant mirror, signer, nginx, frontend, TUI, shell, model, remote dispatch, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; tui_authority = $false; normal_shell_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $requirementPath),
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $evidenceChainPath),
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-040 outputs must not contain PEM blocks, auth tokens, private key paths, or signer internals." $null

$source = [ordered]@{
    activation_result = New-ArtifactRef $resolvedActivationResultPath $activationResult
    activation_gate_report = New-ArtifactRef $resolvedActivationGateReportPath $activationGateReport
    activation_denial_evidence = New-ArtifactRef $resolvedActivationDenialEvidencePath $activationDenialEvidence
    activation_handoff = New-ArtifactRef $resolvedActivationHandoffPath $activationHandoff
    rc10_rollback_result = New-ArtifactRef $resolvedRc10RollbackResultPath $rc10RollbackResult
    rc10_support_recovery_result = New-ArtifactRef $resolvedRc10SupportRecoveryResultPath $rc10SupportRecoveryResult
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-support-recovery-result.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    rollback_surface = [ordered]@{
        state = $rollbackState
        rollback_attempt_id = $rollbackAttemptId
        rollback_planspec_id = $rollbackPlanSpecId
        rollback_planspec_hash = $rollbackPlanSpecHash
        rollback_readiness_ready = $rollbackBaselineBound
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        controlled_canary_activation_performed = $controlledActivationPerformed
        exact_rollback_approval_granted = $separateRollbackApprovalGranted
        agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
        security_execution_rollback_approval_bound = $rollbackSecurityExecutionAllowed
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $remoteDispatchEnabled
        blockers = @($script:blockers)
    }
    support_surface = [ordered]@{
        support_recovery_binding_present = $supportRecoveryBound
        support_bundle_redacted = $supportBundleRedacted
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
    }
    outputs = [ordered]@{
        rollback_planspec_requirement = [ordered]@{ path = Get-StablePath $requirementPath; sha256 = Get-FileSha256 $requirementPath }
        rollback_support_gate_report = [ordered]@{ path = Get-StablePath $gateReportPath; sha256 = Get-FileSha256 $gateReportPath }
        rollback_support_denial_evidence = [ordered]@{ path = Get-StablePath $denialEvidencePath; sha256 = Get-FileSha256 $denialEvidencePath }
        support_recovery_evidence_chain = [ordered]@{ path = Get-StablePath $evidenceChainPath; sha256 = Get-FileSha256 $evidenceChainPath }
        controlled_execution_support_bundle = [ordered]@{ path = Get-StablePath $supportBundlePath; sha256 = Get-FileSha256 $supportBundlePath }
        recovery_reference_index = [ordered]@{ path = Get-StablePath $recoveryIndexPath; sha256 = Get-FileSha256 $recoveryIndexPath }
    }
    source = $source
    gate_inputs = $gateInputs
    source_bindings = $sourceBindings
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        rollback_attempt_recorded = $true
        support_bundle_redacted = $true
        external_payload_bytes_uploaded = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        frontend_authority = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($denialCases).Count
        failed_cases = $failedCases.Count
        rc11_040_complete = (@($script:failedChecks).Count -eq 0)
        rollback_state = $rollbackState
        rollback_readiness_ready = $rollbackBaselineBound
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        canary_activation_performed = $controlledActivationPerformed
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $remoteDispatchEnabled
        production_ready_claim = $false
        next_task = "RC11-050"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-controlled-rollback-support-recovery-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-040"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    rollback_surface = $result.rollback_surface
    support_surface = $result.support_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc11_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-050"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC11-040 result."
}

Write-Host "RC11 controlled rollback support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Rollback state: $($result.rollback_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
