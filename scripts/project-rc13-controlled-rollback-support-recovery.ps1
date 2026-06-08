param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-controlled-rollback-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$ActivationResultPath = ".workflow/artifacts/rc13-controlled-activation/result.json",
    [string]$ActivationGateReportPath = ".workflow/artifacts/rc13-controlled-activation/activation-gate-report.json",
    [string]$ActivationDenialEvidencePath = ".workflow/artifacts/rc13-controlled-activation/activation-denial-evidence.json",
    [string]$ActivationHandoffPath = ".workflow/artifacts/rc13-controlled-activation/controlled-activation-rollback-handoff.json",
    [string]$ApprovalResultPath = ".workflow/artifacts/rc13-exact-approval-audit-binding/result.json",
    [string]$ApprovalPacketPath = ".workflow/artifacts/rc13-exact-approval-audit-binding/exact-approval-packet.json",
    [string]$PlanSpecReadinessPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/agentcore-planspec-readiness.json",
    [string]$SecurityPreconditionsPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/security-execution-allow-preconditions.json",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
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
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
        "approval-audit-sink-not-bound" { "audit-sink-not-bound" }
        "approval-nonce-not-bound" { "nonce-not-bound" }
        "approval-expiry-not-bound" { "approval-expiry-not-bound" }
        "target-identities-missing" { "rollback-target-identities-missing" }
        "target-identity-set-not-bound" { "rollback-target-identities-missing" }
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
        ("BEGIN PUBLIC " + "KEY"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-" + "key" + "." + "pem"),
        ("/etc/" + "aios-signer"),
        ("finger" + "print")
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
        observed_blocked = $true
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

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedActivationResultPath = Resolve-RepoPath $ActivationResultPath
$resolvedActivationGateReportPath = Resolve-RepoPath $ActivationGateReportPath
$resolvedActivationDenialEvidencePath = Resolve-RepoPath $ActivationDenialEvidencePath
$resolvedActivationHandoffPath = Resolve-RepoPath $ActivationHandoffPath
$resolvedApprovalResultPath = Resolve-RepoPath $ApprovalResultPath
$resolvedApprovalPacketPath = Resolve-RepoPath $ApprovalPacketPath
$resolvedPlanSpecReadinessPath = Resolve-RepoPath $PlanSpecReadinessPath
$resolvedSecurityPreconditionsPath = Resolve-RepoPath $SecurityPreconditionsPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$activationResult = Read-Json $resolvedActivationResultPath
$activationGateReport = Read-Json $resolvedActivationGateReportPath
$activationDenialEvidence = Read-Json $resolvedActivationDenialEvidencePath
$activationHandoff = Read-Json $resolvedActivationHandoffPath
$approvalResult = Read-Json $resolvedApprovalResultPath
$approvalPacket = Read-Json $resolvedApprovalPacketPath
$planSpecReadiness = Read-Json $resolvedPlanSpecReadinessPath
$securityPreconditions = Read-Json $resolvedSecurityPreconditionsPath

$releaseId = [string]$activationResult.release_id
$rollbackAttemptId = "rc13-controlled-rollback-support-recovery-attempt"
$rollbackPlanSpecId = "rc13-controlled-rollback-support-recovery-planspec-required"

Add-Blockers $activationResult.blockers
Add-Blockers $activationResult.activation_surface.blockers
Add-Blockers $activationHandoff.blockers
Add-Blockers $approvalResult.blockers
Add-Blockers $approvalResult.approval_surface.blockers
Add-Blockers $planSpecReadiness.planspec_core.blockers
Add-Blockers $securityPreconditions.blockers

$sourceTasksComplete = $activationResult.status -eq "passed" -and
    $activationResult.summary.rc13_040_complete -eq $true -and
    $approvalResult.status -eq "passed" -and
    $approvalResult.summary.rc13_031_complete -eq $true
$activationEvidenceReady = $activationResult.status -eq "passed" -and $activationHandoff.next_task -eq "RC13-041"
$controlledActivationPerformed = $activationResult.activation_surface.activation_performed -eq $true
$rollbackBaselineBound = -not [string]::IsNullOrWhiteSpace([string]$planSpecReadiness.planspec_core.frozen_inputs.rollback_baseline_sha256)
$supportRecoveryReferenceBound = -not [string]::IsNullOrWhiteSpace([string]$planSpecReadiness.planspec_core.frozen_inputs.support_recovery_sha256)
$supportBundleRedacted = $true
$targetIdsBound = $approvalResult.approval_surface.target_identity_set_bound -eq $true -and
    [int]$approvalResult.approval_surface.enrolled_target_identity_count -ge 2
$separateRollbackApprovalGranted = $false
$rollbackPlanSpecBound = $false
$rollbackPlanSpecExecutable = $false
$rollbackSecurityExecutionAllowed = $false
$auditJournalBound = $false
$postRollbackObservationsBound = $false
$supportUploadAllowed = $false
$recoveryExecutionAllowed = $false
$remoteFleetExecutionEnabled = $activationResult.activation_surface.remote_dispatch_enabled -eq $true

if (-not $controlledActivationPerformed) { Add-UniqueBlocker "controlled-activation-not-performed" }
if (-not $targetIdsBound) { Add-UniqueBlocker "rollback-target-identities-missing" }
if (-not $separateRollbackApprovalGranted) { Add-UniqueBlocker "rollback-exact-operator-approval-not-granted" }
if (-not $rollbackPlanSpecBound) { Add-UniqueBlocker "agentcore-rollback-planspec-not-bound" }
if (-not $rollbackPlanSpecExecutable) { Add-UniqueBlocker "agentcore-rollback-planspec-not-executable" }
if (-not $rollbackSecurityExecutionAllowed) { Add-UniqueBlocker "security-execution-rollback-effect-envelope-not-bound" }
if (-not $auditJournalBound) { Add-UniqueBlocker "rollback-audit-journal-not-bound" }
if (-not $postRollbackObservationsBound) { Add-UniqueBlocker "post-rollback-observations-missing" }
if (-not $supportRecoveryReferenceBound) { Add-UniqueBlocker "support-recovery-binding-not-proved" }
if (-not $supportBundleRedacted) { Add-UniqueBlocker "support-bundle-redaction-not-proved" }
if (-not $remoteFleetExecutionEnabled) { Add-UniqueBlocker "remote-fleet-execution-not-enabled" }
Add-UniqueBlocker "rollback-baseline-not-approved-for-execution"
Add-UniqueBlocker "support-recovery-not-approved-for-execution"
Add-UniqueBlocker "support-upload-not-authorized"
Add-UniqueBlocker "recovery-execution-not-authorized"
Add-UniqueBlocker "rollback-execution-not-authorized"

$sourceBindings = [ordered]@{
    activation_result_sha256 = Get-FileSha256 $resolvedActivationResultPath
    activation_gate_report_sha256 = Get-FileSha256 $resolvedActivationGateReportPath
    activation_denial_evidence_sha256 = Get-FileSha256 $resolvedActivationDenialEvidencePath
    activation_handoff_sha256 = Get-FileSha256 $resolvedActivationHandoffPath
    activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    approval_result_sha256 = Get-FileSha256 $resolvedApprovalResultPath
    approval_packet_sha256 = Get-FileSha256 $resolvedApprovalPacketPath
    approval_binding_digest = [string]$approvalResult.approval_surface.approval_binding_digest
    target_identity_set_digest = [string]$approvalResult.approval_surface.target_identity_set_digest
    enrolled_target_identity_count = [int]$approvalResult.approval_surface.enrolled_target_identity_count
    agentcore_planspec_readiness_sha256 = Get-FileSha256 $resolvedPlanSpecReadinessPath
    agentcore_planspec_core_hash = [string]$planSpecReadiness.planspec_core_hash
    security_execution_preconditions_sha256 = Get-FileSha256 $resolvedSecurityPreconditionsPath
    security_execution_effect_envelope_core_hash = [string]$securityPreconditions.effect_envelope_core_hash
    rollback_baseline_sha256 = [string]$planSpecReadiness.planspec_core.frozen_inputs.rollback_baseline_sha256
    support_recovery_sha256 = [string]$planSpecReadiness.planspec_core.frozen_inputs.support_recovery_sha256
    payload_sha256 = [string]$planSpecReadiness.planspec_core.frozen_inputs.payload_sha256
}

$gateInputs = [ordered]@{
    source_tasks_complete = $sourceTasksComplete
    controlled_activation_evidence_ready = $activationEvidenceReady
    controlled_activation_performed = $controlledActivationPerformed
    rollback_baseline_bound = $rollbackBaselineBound
    support_recovery_reference_bound = $supportRecoveryReferenceBound
    support_bundle_redacted = $supportBundleRedacted
    target_ids_bound = $targetIdsBound
    separate_rollback_approval_granted = $separateRollbackApprovalGranted
    agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
    agentcore_rollback_planspec_executable = $rollbackPlanSpecExecutable
    security_execution_rollback_allowed = $rollbackSecurityExecutionAllowed
    audit_journal_bound = $auditJournalBound
    post_rollback_observations_bound = $postRollbackObservationsBound
    support_upload_allowed = $supportUploadAllowed
    recovery_execution_allowed = $recoveryExecutionAllowed
    remote_fleet_execution_enabled = $remoteFleetExecutionEnabled
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}

$rollbackExecutionAllowed = $sourceTasksComplete -and
    $activationEvidenceReady -and
    $controlledActivationPerformed -and
    $rollbackBaselineBound -and
    $supportRecoveryReferenceBound -and
    $supportBundleRedacted -and
    $targetIdsBound -and
    $separateRollbackApprovalGranted -and
    $rollbackPlanSpecBound -and
    $rollbackPlanSpecExecutable -and
    $rollbackSecurityExecutionAllowed -and
    $auditJournalBound -and
    $postRollbackObservationsBound -and
    $remoteFleetExecutionEnabled
$rollbackState = if ($rollbackExecutionAllowed) { "rollback-authorized" } else { "controlled-rollback-support-recovery-denied" }

$rollbackPlanSpecCore = [ordered]@{
    planspec_id = $rollbackPlanSpecId
    schema = "agentos.agentcore.rollback-planspec.v1"
    plan_kind = "rc13-controlled-rollback-support-recovery"
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    activation_performed = $controlledActivationPerformed
    payload_sha256 = [string]$sourceBindings.payload_sha256
    rollback_baseline_digest = [string]$sourceBindings.rollback_baseline_sha256
    support_recovery_digest = [string]$sourceBindings.support_recovery_sha256
    target_identity_set_digest = [string]$sourceBindings.target_identity_set_digest
    target_identity_ids = @()
    exact_rollback_approval_digest = "not-bound"
    security_execution_rollback_decision_digest = "not-bound"
    audit_journal_path = "required-before-execution"
    post_rollback_observations = "required-before-execution"
    denied_effects = @("rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation")
    policy_version = "rc13-controlled-rollback-support-recovery-v1"
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
    schema = "agentos.rc13-rollback-support-recovery-planspec-requirement.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
    status = "rollback-support-recovery-planspec-required-execution-blocked"
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
    agentcore_rollback_planspec_executable = $false
    security_execution_engine_required = $true
    security_execution_rollback_approval_bound = $false
    audit_journal_required = $true
    post_rollback_observation_plan_required = $true
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
    schema = "agentos.rc13-controlled-rollback-support-recovery-gate-report.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
    status = "rollback-support-recovery-gates-evaluated-denied"
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
        activation_state = $activationResult.activation_surface.state
        activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
        controlled_activation_performed = $controlledActivationPerformed
        rollback_baseline_digest = [string]$sourceBindings.rollback_baseline_sha256
        rollback_baseline_bound = $rollbackBaselineBound
        rollback_planspec_hash = $rollbackPlanSpecHash
        separate_rollback_approval_granted = $false
        security_execution_rollback_allowed = $false
    }
    support_surface = [ordered]@{
        support_recovery_reference_bound = $supportRecoveryReferenceBound
        support_bundle_redacted = $supportBundleRedacted
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
    blockers = @($script:blockers)
    source_bindings = $sourceBindings
    side_effects = $sideEffects
}

$caseSpecs = @(
    [ordered]@{ id = "activation-not-performed-denied"; blockers = @("controlled-activation-not-performed"); reason = "Rollback requires executed controlled activation evidence, but RC13-040 denied activation." },
    [ordered]@{ id = "rollback-target-identities-missing-denied"; blockers = @("rollback-target-identities-missing"); reason = "Rollback target identities are not bound to a separate rollback approval package." },
    [ordered]@{ id = "rollback-approval-missing-denied"; blockers = @("rollback-exact-operator-approval-not-granted"); reason = "Rollback requires a separate exact operator approval." },
    [ordered]@{ id = "rollback-planspec-missing-denied"; blockers = @("agentcore-rollback-planspec-not-bound"); reason = "AgentCore rollback PlanSpec is projected as a requirement but is not bound." },
    [ordered]@{ id = "rollback-planspec-not-executable-denied"; blockers = @("agentcore-rollback-planspec-not-executable"); reason = "AgentCore rollback PlanSpec is not executable." },
    [ordered]@{ id = "security-rollback-missing-denied"; blockers = @("security-execution-rollback-effect-envelope-not-bound"); reason = "SecurityExecutionEngine has not approved rollback effects." },
    [ordered]@{ id = "audit-journal-missing-denied"; blockers = @("rollback-audit-journal-not-bound"); reason = "Rollback audit journal binding is required before execution." },
    [ordered]@{ id = "post-observations-missing-denied"; blockers = @("post-rollback-observations-missing"); reason = "Post-rollback observation plan is required before execution." },
    [ordered]@{ id = "remote-fleet-disabled-denied"; blockers = @("remote-fleet-execution-not-enabled"); reason = "Remote fleet execution remains disabled." },
    [ordered]@{ id = "rollback-baseline-execution-denied"; blockers = @("rollback-baseline-not-approved-for-execution"); reason = "Rollback baseline is bound but not approved for execution." },
    [ordered]@{ id = "support-recovery-execution-denied"; blockers = @("support-recovery-not-approved-for-execution"); reason = "Support/recovery reference is bound but not approved for execution." },
    [ordered]@{ id = "support-upload-denied"; blockers = @("support-upload-not-authorized"); reason = "Support upload remains unauthorized." },
    [ordered]@{ id = "recovery-execution-denied"; blockers = @("recovery-execution-not-authorized"); reason = "Recovery execution remains unauthorized." },
    [ordered]@{ id = "rollback-execution-denied"; blockers = @("rollback-execution-not-authorized"); reason = "At least one required rollback/support/recovery gate is missing." }
)
$denialCases = @()
foreach ($spec in $caseSpecs) {
    $denialCases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -ObservedBlockers $script:blockers -Reason $spec.reason
}
$failedCases = @($denialCases | Where-Object { $_.status -ne "passed" })

$denialEvidence = [ordered]@{
    schema = "agentos.rc13-controlled-rollback-support-recovery-denial-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
    status = "rollback-support-recovery-denied"
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
    schema = "agentos.rc13-controlled-rollback-support-recovery-chain.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
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
        rc13_state = $rollbackState
        rollback_baseline_bound = $rollbackBaselineBound
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        rollback_planspec_hash = $rollbackPlanSpecHash
    }
    support_surface = $gateReport.support_surface
    remaining_blockers_before_controlled_execution = @($script:blockers)
    source_bindings = $sourceBindings
    side_effects = $sideEffects
}

$supportBundle = [ordered]@{
    schema = "agentos.rc13-controlled-rollback-support-bundle-projection.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
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
        rollback_support_recovery_denial = [ordered]@{
            rollback_execution_allowed = $false
            rollback_execution_performed = $false
            support_upload_allowed = $false
            recovery_execution_allowed = $false
            blockers = @($script:blockers)
        }
        exact_approval_context = [ordered]@{
            source = Get-StablePath $resolvedApprovalResultPath
            sha256 = Get-FileSha256 $resolvedApprovalResultPath
            approval_granted = $false
            separate_rollback_approval_granted = $false
        }
    }
    operator_summary = [ordered]@{
        current_state = "rollback-support-recovery-blocked"
        safe_next_task = "RC13-050 final closeout audit after RC13-041 evidence is committed"
        support_truth = "redacted local evidence projection; no support upload endpoint is authorized"
        recovery_truth = "rollback/support evidence is bound as a reference; no recovery or rollback execution is authorized"
    }
    source_bindings = $sourceBindings
    side_effects = $sideEffects
}

$recoveryIndex = [ordered]@{
    schema = "agentos.rc13-controlled-rollback-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
    status = "projection-only-recovery-execution-blocked"
    production_ready_claim = $false
    release_id = $releaseId
    entries = @(
        [ordered]@{ id = "rc13-activation-denial"; kind = "local-artifact"; path = Get-StablePath $resolvedActivationDenialEvidencePath; sha256 = Get-FileSha256 $resolvedActivationDenialEvidencePath; executable = $false },
        [ordered]@{ id = "rc13-activation-handoff"; kind = "local-artifact"; path = Get-StablePath $resolvedActivationHandoffPath; sha256 = Get-FileSha256 $resolvedActivationHandoffPath; executable = $false },
        [ordered]@{ id = "rc13-rollback-support-recovery-gate-report"; kind = "local-artifact"; path = ".workflow/artifacts/rc13-controlled-rollback-support-recovery/rollback-support-recovery-gate-report.json"; sha256 = $null; executable = $false },
        [ordered]@{ id = "rc13-rollback-support-recovery-denial"; kind = "local-artifact"; path = ".workflow/artifacts/rc13-controlled-rollback-support-recovery/rollback-support-recovery-denial-evidence.json"; sha256 = $null; executable = $false },
        [ordered]@{ id = "rc13-exact-approval-result"; kind = "local-artifact"; path = Get-StablePath $resolvedApprovalResultPath; sha256 = Get-FileSha256 $resolvedApprovalResultPath; executable = $false }
    )
    required_before_execution = @(
        "executed controlled activation",
        "separate exact rollback approval",
        "bound rollback target identities",
        "executable AgentCore rollback PlanSpec",
        "SecurityExecutionEngine rollback allow decision",
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
$gateReportPath = Join-Path $resolvedArtifactDir "rollback-support-recovery-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "rollback-support-recovery-denial-evidence.json"
$evidenceChainPath = Join-Path $resolvedArtifactDir "support-recovery-evidence-chain.json"
$supportBundlePath = Join-Path $resolvedArtifactDir "controlled-execution-support-bundle.json"
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-041-controlled-rollback-support-recovery.json"

Write-Json $rollbackRequirement $requirementPath
Write-Json $gateReport $gateReportPath
Write-Json $denialEvidence $denialEvidencePath
Write-Json $evidenceChain $evidenceChainPath
Write-Json $supportBundle $supportBundlePath

$recoveryIndex.entries[2].sha256 = Get-FileSha256 $gateReportPath
$recoveryIndex.entries[3].sha256 = Get-FileSha256 $denialEvidencePath
Write-Json $recoveryIndex $recoveryIndexPath

Add-Check "source.rc13_040.activation_denied" ($activationResult.status -eq "passed" -and $activationResult.summary.rc13_040_complete -eq $true -and $activationResult.activation_surface.state -eq "controlled-activation-denied" -and $activationResult.activation_surface.activation_performed -eq $false) "RC13-041 must consume completed RC13-040 activation denial without treating it as executed activation." ([ordered]@{ status = $activationResult.status; state = $activationResult.activation_surface.state; activation_performed = $activationResult.activation_surface.activation_performed })
Add-Check "source.rc13_031.approval_denied" ($approvalResult.status -eq "passed" -and $approvalResult.summary.rc13_031_complete -eq $true -and $approvalResult.approval_surface.approval_granted -eq $false) "RC13-041 must consume RC13-031 exact approval evidence and keep rollback approval separate and denied." ([ordered]@{ status = $approvalResult.status; approval_granted = $approvalResult.approval_surface.approval_granted; exact_approval_bound = $approvalResult.approval_surface.exact_approval_bound })
Add-Check "contract.rollback_gate.present" ($contractText.Contains("Execute rollback only after controlled activation evidence plus a separate exact rollback approval")) "RC13 contract must include controlled rollback support/recovery gate." (New-ArtifactRef $resolvedContractPath)
Add-Check "rollback.planspec_requirement.projected_blocked" ((Test-Path -LiteralPath $requirementPath -PathType Leaf) -and $rollbackRequirement.executable -eq $false -and $rollbackRequirement.rollback_execution_allowed -eq $false -and -not [string]::IsNullOrWhiteSpace($rollbackPlanSpecHash)) "Rollback PlanSpec requirement must be projected and non-executable." ([ordered]@{ path = Get-StablePath $requirementPath; sha256 = Get-FileSha256 $requirementPath; planspec_hash = $rollbackPlanSpecHash })
Add-Check "rollback.denied_when_gates_missing" ($rollbackExecutionAllowed -eq $false -and $gateReport.rollback_state -eq "controlled-rollback-support-recovery-denied" -and $denialEvidence.denied -eq $true) "Rollback/support/recovery execution must deny when activation, separate approval, PlanSpec, SecurityExecution, audit, observation, or remote gates are missing." ([ordered]@{ rollback_execution_allowed = $rollbackExecutionAllowed; blockers = @($script:blockers) })
Add-Check "rollback.denial_cases.complete" ($failedCases.Count -eq 0 -and @($denialCases).Count -ge 14) "Rollback/support/recovery denial evidence must cover missing rollback, support, and recovery gates as fail-closed." ([ordered]@{ cases = @($denialCases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "support.bundle.redacted_no_upload" ($supportBundle.redacted -eq $true -and $supportBundle.upload_allowed -eq $false -and $supportBundle.upload_performed -eq $false) "Support bundle projection must stay redacted, local-only, and upload-disabled." ([ordered]@{ redacted = $supportBundle.redacted; upload_allowed = $supportBundle.upload_allowed })
Add-Check "recovery.index.non_executable" (@($recoveryIndex.entries | Where-Object { $_.executable -ne $false }).Count -eq 0 -and $recoveryIndex.recovery_authority.tui_authority -eq $false -and $recoveryIndex.recovery_authority.shell_authority -eq $false) "Recovery reference index must keep every entry non-executable and non-authoritative." ([ordered]@{ entries = @($recoveryIndex.entries).Count })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.effect_executed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false) "RC13-041 must not prepare or execute rollback, support upload, recovery, production mutation, or remote dispatch side effects." $sideEffects
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC13-041 must not grant mirror, signer, nginx, frontend, TUI, shell, model, remote dispatch, private signing, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; private_signing_material_handled = $false; tui_authority = $false; normal_shell_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $requirementPath),
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $evidenceChainPath),
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC13-041 outputs must not contain private key material, auth tokens, private signing paths, signer internals, or sensitive approval markers." $null

$source = [ordered]@{
    rc13_contract = New-ArtifactRef $resolvedContractPath
    activation_result = New-ArtifactRef $resolvedActivationResultPath $activationResult
    activation_gate_report = New-ArtifactRef $resolvedActivationGateReportPath $activationGateReport
    activation_denial_evidence = New-ArtifactRef $resolvedActivationDenialEvidencePath $activationDenialEvidence
    activation_handoff = New-ArtifactRef $resolvedActivationHandoffPath $activationHandoff
    approval_result = New-ArtifactRef $resolvedApprovalResultPath $approvalResult
    approval_packet = New-ArtifactRef $resolvedApprovalPacketPath $approvalPacket
    agentcore_planspec_readiness = New-ArtifactRef $resolvedPlanSpecReadinessPath $planSpecReadiness
    security_execution_preconditions = New-ArtifactRef $resolvedSecurityPreconditionsPath $securityPreconditions
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-controlled-rollback-support-recovery-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    rollback_surface = [ordered]@{
        state = $rollbackState
        rollback_attempt_id = $rollbackAttemptId
        rollback_planspec_id = $rollbackPlanSpecId
        rollback_planspec_hash = $rollbackPlanSpecHash
        rollback_baseline_bound = $rollbackBaselineBound
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        controlled_activation_performed = $controlledActivationPerformed
        exact_rollback_approval_granted = $separateRollbackApprovalGranted
        agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
        agentcore_rollback_planspec_executable = $rollbackPlanSpecExecutable
        security_execution_rollback_approval_bound = $rollbackSecurityExecutionAllowed
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    support_surface = [ordered]@{
        support_recovery_reference_bound = $supportRecoveryReferenceBound
        support_bundle_redacted = $supportBundleRedacted
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
    }
    outputs = [ordered]@{
        rollback_planspec_requirement = [ordered]@{ path = Get-StablePath $requirementPath; sha256 = Get-FileSha256 $requirementPath }
        rollback_support_recovery_gate_report = [ordered]@{ path = Get-StablePath $gateReportPath; sha256 = Get-FileSha256 $gateReportPath }
        rollback_support_recovery_denial_evidence = [ordered]@{ path = Get-StablePath $denialEvidencePath; sha256 = Get-FileSha256 $denialEvidencePath }
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
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        external_payload_bytes_uploaded = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
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
        rc13_041_complete = (@($script:failedChecks).Count -eq 0)
        rollback_state = $rollbackState
        rollback_baseline_bound = $rollbackBaselineBound
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        controlled_activation_performed = $controlledActivationPerformed
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ready_claim = $false
        next_task = "RC13-050"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-controlled-rollback-support-recovery-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-041"
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
        rc13_041_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-050"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC13-041 result."
}

Write-Host "RC13 controlled rollback support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Rollback state: $($result.rollback_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
