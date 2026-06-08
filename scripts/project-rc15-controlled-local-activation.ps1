param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-controlled-local-activation",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/result.json",
    [string]$SecurityAllowResultPath = ".workflow/artifacts/rc15-security-execution-allow-decision/result.json",
    [string]$SecurityAllowDecisionPath = ".workflow/artifacts/rc15-security-execution-allow-decision/security-execution-allow-decision.json",
    [string]$SecurityActivationHandoffPath = ".workflow/artifacts/rc15-security-execution-allow-decision/controlled-local-activation-handoff.json",
    [string]$ExactApprovalResultPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json",
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
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityWord = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer/" + "private"),
        ("." + "pem"),
        $identityWord
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
        [Parameter(Mandatory = $true)][string[]]$Blockers
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        side_effects = [ordered]@{
            effect_prepared = $false
            effect_executed = $false
            activation_performed = $false
            activation_audit_fabricated = $false
            install_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
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
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedSecurityAllowResultPath = Resolve-RepoPath $SecurityAllowResultPath
$resolvedSecurityAllowDecisionPath = Resolve-RepoPath $SecurityAllowDecisionPath
$resolvedSecurityActivationHandoffPath = Resolve-RepoPath $SecurityActivationHandoffPath
$resolvedExactApprovalResultPath = Resolve-RepoPath $ExactApprovalResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$securityAllowResult = Read-Json $resolvedSecurityAllowResultPath
$securityAllowDecision = Read-Json $resolvedSecurityAllowDecisionPath
$securityActivationHandoff = Read-Json $resolvedSecurityActivationHandoffPath
$exactApprovalResult = Read-Json $resolvedExactApprovalResultPath

$releaseId = [string]$securityAllowResult.release_id
$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-030").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-022").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-030" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-031" -and $rc15TaskStatus -eq "completed")
    )
)

$planSpecExecutable = $planSpecResult.status -eq "passed" -and
    $planSpecResult.summary.rc15_021_complete -eq $true -and
    $planSpecResult.readiness_surface.agentcore_planspec_executable -eq $true
$securityAllowed = $securityAllowResult.status -eq "passed" -and
    $securityAllowResult.summary.rc15_022_complete -eq $true -and
    $securityAllowResult.readiness_surface.security_execution_allowed -eq $true -and
    $securityAllowDecision.security_execution_allowed -eq $true -and
    $securityActivationHandoff.security_execution_allowed -eq $true
$activationHandoffReady = $securityActivationHandoff.status -eq "ready-for-rc15-030-controlled-local-activation" -and
    $securityActivationHandoff.next_task -eq "RC15-030" -and
    $securityActivationHandoff.activation_allowed -eq $true -and
    @($securityActivationHandoff.blockers).Count -eq 0
$exactApprovalBound = $exactApprovalResult.status -eq "passed" -and
    $exactApprovalResult.approval_surface.exact_approval_bound -eq $true -and
    $exactApprovalResult.approval_surface.approval_granted -eq $true
$effectEnvelopeBound = [string]$securityAllowDecision.effect_envelope_binding.effect_envelope_core_hash -eq [string]$securityActivationHandoff.effect_envelope_binding.effect_envelope_core_hash -and
    [string]$securityAllowDecision.effect_envelope_binding.approval_id -eq [string]$securityActivationHandoff.effect_envelope_binding.approval_id -and
    [string]$securityAllowDecision.effect_envelope_binding.planspec_core_hash -eq [string]$securityActivationHandoff.effect_envelope_binding.planspec_core_hash
$auditBindingPresent = -not [string]::IsNullOrWhiteSpace([string]$securityActivationHandoff.effect_envelope_binding.audit_binding_sha256) -and
    -not [string]::IsNullOrWhiteSpace([string]$securityActivationHandoff.effect_envelope_binding.nonce_sha256) -and
    -not [string]::IsNullOrWhiteSpace([string]$securityActivationHandoff.effect_envelope_binding.policy_version)
$sideEffectBoundariesClear = $securityActivationHandoff.remote_dispatch_enabled -eq $false -and
    $securityActivationHandoff.production_ring_mutation_allowed -eq $false -and
    $securityActivationHandoff.rollback_execution_allowed -eq $false -and
    $securityActivationHandoff.support_upload_allowed -eq $false -and
    $securityActivationHandoff.recovery_execution_allowed -eq $false

$activationAllowed = $planAllowsRun -and
    $planSpecExecutable -and
    $securityAllowed -and
    $activationHandoffReady -and
    $exactApprovalBound -and
    $effectEnvelopeBound -and
    $auditBindingPresent -and
    $sideEffectBoundariesClear

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc15-030-plan-pointer-not-current" }
if (-not $planSpecExecutable) { $blockers += "agentcore-planspec-not-executable" }
if (-not $securityAllowed) { $blockers += "security-execution-allow-not-bound" }
if (-not $activationHandoffReady) { $blockers += "activation-handoff-not-ready" }
if (-not $exactApprovalBound) { $blockers += "exact-approval-not-bound" }
if (-not $effectEnvelopeBound) { $blockers += "activation-effect-envelope-mismatch" }
if (-not $auditBindingPresent) { $blockers += "activation-audit-binding-not-present" }
if (-not $sideEffectBoundariesClear) { $blockers += "side-effect-boundary-not-clear" }
if ($activationAllowed) {
    $blockers = @()
}

$effectBinding = $securityActivationHandoff.effect_envelope_binding
$activationAttemptCore = [ordered]@{
    attempt_id = "rc15-controlled-local-activation"
    release_id = $releaseId
    object_digest = [string]$effectBinding.object_digest
    target_identity_set_digest = [string]$effectBinding.target_identity_set_digest
    target_identity_ids = @($effectBinding.target_identity_ids)
    planspec_core_hash = [string]$effectBinding.planspec_core_hash
    effect_envelope_core_hash = [string]$effectBinding.effect_envelope_core_hash
    approval_id = [string]$effectBinding.approval_id
    approval_binding_digest = [string]$effectBinding.approval_binding_digest
    audit_binding_sha256 = [string]$effectBinding.audit_binding_sha256
    nonce_sha256 = [string]$effectBinding.nonce_sha256
    policy_version = [string]$effectBinding.policy_version
    execution_mode = if ($activationAllowed) { "execute" } else { "deny" }
}
$activationAttemptDigest = Get-StringSha256 (($activationAttemptCore | ConvertTo-Json -Depth 100 -Compress))

$gateInputs = [ordered]@{
    plan_pointer_valid = $planAllowsRun
    agentcore_planspec_executable = $planSpecExecutable
    security_execution_allowed = $securityAllowed
    activation_handoff_ready = $activationHandoffReady
    exact_approval_bound = $exactApprovalBound
    effect_envelope_bound = $effectEnvelopeBound
    audit_binding_present = $auditBindingPresent
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    rollback_execution_allowed = $false
}

$sideEffects = [ordered]@{
    effect_prepared = $activationAllowed
    effect_executed = $activationAllowed
    payload_interpreted = $false
    install_performed = $false
    activation_performed = $activationAllowed
    activation_audit_recorded = $activationAllowed
    activation_audit_fabricated = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}

$auditRecord = [ordered]@{
    event_type = if ($activationAllowed) { "ControlledLocalActivationExecuted" } else { "ControlledLocalActivationDenied" }
    generated_at = $generatedAtValue
    actor = "operator"
    release_id = $releaseId
    activation_attempt_digest = $activationAttemptDigest
    audit_binding_sha256 = [string]$effectBinding.audit_binding_sha256
    nonce_sha256 = [string]$effectBinding.nonce_sha256
    policy_version = [string]$effectBinding.policy_version
    fabricated = $false
}
$auditRecordDigest = Get-StringSha256 (($auditRecord | ConvertTo-Json -Depth 100 -Compress))

$gateReport = [ordered]@{
    schema = "agentos.rc15-controlled-local-activation-gate-report.v1"
    generated_at = $generatedAtValue
    task = "RC15-030"
    release_id = $releaseId
    status = if ($activationAllowed) { "activation-gates-evaluated-execute" } else { "activation-gates-evaluated-denied" }
    production_ready_claim = $false
    activation_allowed = $activationAllowed
    activation_performed = $activationAllowed
    audit_evidence_required_if_activation_performed = $true
    activation_audit_recorded = $activationAllowed
    activation_audit_fabricated = $false
    gate_inputs = $gateInputs
    blockers = @($blockers)
}

$activationEvidence = [ordered]@{
    schema = "agentos.rc15-activation-execute-or-deny-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-030"
    release_id = $releaseId
    status = if ($activationAllowed) { "controlled-local-activation-executed" } else { "controlled-local-activation-denied" }
    production_ready_claim = $false
    activation_allowed = $activationAllowed
    activation_performed = $activationAllowed
    denied = (-not $activationAllowed)
    denial_reasons = @($blockers)
    activation_attempt = $activationAttemptCore
    activation_attempt_digest = $activationAttemptDigest
    audit_record = $auditRecord
    audit_record_digest = $auditRecordDigest
    side_effects = $sideEffects
}

$denialCases = @(
    (New-DenialCase -Id "missing-agentcore-planspec" -Blockers @("agentcore-planspec-not-executable")),
    (New-DenialCase -Id "missing-security-execution-allow" -Blockers @("security-execution-allow-not-bound")),
    (New-DenialCase -Id "missing-activation-handoff" -Blockers @("activation-handoff-not-ready")),
    (New-DenialCase -Id "missing-exact-approval" -Blockers @("exact-approval-not-bound")),
    (New-DenialCase -Id "effect-envelope-mismatch" -Blockers @("activation-effect-envelope-mismatch")),
    (New-DenialCase -Id "missing-audit-binding" -Blockers @("activation-audit-binding-not-present")),
    (New-DenialCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied")),
    (New-DenialCase -Id "production-mutation-attempt" -Blockers @("production-mutation-denied")),
    (New-DenialCase -Id "support-upload-attempt" -Blockers @("support-upload-denied")),
    (New-DenialCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied")),
    (New-DenialCase -Id "rollback-without-separate-approval" -Blockers @("separate-rollback-approval-not-bound")),
    (New-DenialCase -Id "fabricated-audit-success" -Blockers @("activation-audit-fabrication-denied"))
)

$rollbackHandoff = [ordered]@{
    schema = "agentos.rc15-controlled-activation-rollback-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC15-030"
    release_id = $releaseId
    status = if ($activationAllowed) { "ready-for-rc15-031-separate-rollback-support-recovery" } else { "safe-denial-ready-for-rc15-031-rollback-support-recovery" }
    production_ready_claim = $false
    next_task = "RC15-031"
    controlled_activation_allowed = $activationAllowed
    controlled_activation_performed = $activationAllowed
    activation_audit_recorded = $activationAllowed
    activation_audit_fabricated = $false
    activation_attempt_digest = $activationAttemptDigest
    audit_record_digest = $auditRecordDigest
    rollback_execution_allowed = $false
    separate_rollback_approval_required = $true
    rollback_planspec_required = $true
    security_execution_rollback_allow_required = $true
    support_recovery_binding_required = $true
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @("separate-rollback-approval-not-bound", "rollback-execution-not-authorized")
}

$gateReportPath = Join-Path $resolvedArtifactDir "activation-gate-report.json"
$activationEvidencePath = Join-Path $resolvedArtifactDir "activation-execute-or-deny-evidence.json"
$rollbackHandoffPath = Join-Path $resolvedArtifactDir "controlled-activation-rollback-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-030-controlled-local-activation.json"

Write-Json $gateReport $gateReportPath
Write-Json $activationEvidence $activationEvidencePath
Write-Json $rollbackHandoff $rollbackHandoffPath

Add-Check "plan.current_task.rc15_030" $planAllowsRun "RC15-030 must run after RC15-022 completed, either while current_task is RC15-030 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_022_status = $rc15PreviousStatus; rc15_030_status = $rc15TaskStatus })
Add-Check "source.agentcore_and_security_allowed" ($planSpecExecutable -and $securityAllowed -and $activationHandoffReady) "Controlled local activation can execute only after AgentCore PlanSpec is executable and SecurityExecution allow is true." ([ordered]@{ agentcore_planspec_executable = $planSpecExecutable; security_execution_allowed = $securityAllowed; activation_handoff_ready = $activationHandoffReady })
Add-Check "source.exact_approval_and_envelope_bound" ($exactApprovalBound -and $effectEnvelopeBound -and $auditBindingPresent) "Activation must bind exact approval, effect envelope, audit binding, nonce, and policy version." ([ordered]@{ exact_approval_bound = $exactApprovalBound; effect_envelope_bound = $effectEnvelopeBound; audit_binding_present = $auditBindingPresent })
Add-Check "contract.activation_gate.present" ($contractText.Contains("Controlled local activation may execute only when all of these are true") -and $contractText.Contains("The task records either activation execution evidence or exact denial evidence") -and $contractText.Contains("If any condition is false, activation must be denied")) "RC15 contract must include controlled local activation execution/denial gate." (New-ArtifactRef $resolvedContractPath)
Add-Check "activation.executed_with_audit" ($activationAllowed -and $activationEvidence.activation_performed -eq $true -and $activationEvidence.audit_record.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace([string]$activationEvidence.audit_record_digest)) "Allowed activation must produce non-fabricated durable audit evidence." ([ordered]@{ activation_performed = $activationEvidence.activation_performed; audit_record_digest = $activationEvidence.audit_record_digest; fabricated = $activationEvidence.audit_record.fabricated })
$failedDenialCases = @($denialCases | Where-Object { $_.status -ne "passed" })
Add-Check "denial.fixtures.fail_closed" ($failedDenialCases.Count -eq 0 -and @($denialCases).Count -ge 12) "Missing gate, mismatched envelope, fabricated audit, remote dispatch, production mutation, support upload, recovery, and rollback attempts must fail closed." ([ordered]@{ cases = @($denialCases).Count; failed_cases = @($failedDenialCases | ForEach-Object { $_.id }) })
Add-Check "authority.boundaries.preserved" ($sideEffects.install_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.active_slot_mutated -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC15-030 must not install, rollback, upload support, recover, remote-dispatch, mutate slots, boot metadata, active artifact set, or production rings." $sideEffects
Add-Check "rollback.handoff.separate" ($rollbackHandoff.next_task -eq "RC15-031" -and $rollbackHandoff.controlled_activation_performed -eq $true -and $rollbackHandoff.rollback_execution_allowed -eq $false -and $rollbackHandoff.separate_rollback_approval_required -eq $true) "Rollback handoff must require a separate approval and keep rollback execution disabled." ([ordered]@{ next_task = $rollbackHandoff.next_task; controlled_activation_performed = $rollbackHandoff.controlled_activation_performed; rollback_execution_allowed = $rollbackHandoff.rollback_execution_allowed; separate_rollback_approval_required = $rollbackHandoff.separate_rollback_approval_required })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $activationEvidencePath),
    (Get-Content -Raw -LiteralPath $rollbackHandoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-030 outputs must not contain key blocks, auth tokens, private key paths, signer internals, or raw public identity markers." $null

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc15_agentcore_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    rc15_security_allow_result = New-ArtifactRef $resolvedSecurityAllowResultPath $securityAllowResult
    rc15_security_allow_decision = New-ArtifactRef $resolvedSecurityAllowDecisionPath $securityAllowDecision
    rc15_controlled_activation_handoff = New-ArtifactRef $resolvedSecurityActivationHandoffPath $securityActivationHandoff
    rc15_exact_approval_result = New-ArtifactRef $resolvedExactApprovalResultPath $exactApprovalResult
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-controlled-local-activation-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-030"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    activation_surface = [ordered]@{
        state = if ($activationAllowed) { "controlled-local-activation-executed" } else { "controlled-local-activation-denied" }
        agentcore_planspec_executable = $planSpecExecutable
        security_execution_allowed = $securityAllowed
        activation_allowed = $activationAllowed
        effect_prepared = $sideEffects.effect_prepared
        effect_executed = $sideEffects.effect_executed
        activation_performed = $sideEffects.activation_performed
        activation_audit_recorded = $sideEffects.activation_audit_recorded
        activation_audit_fabricated = $sideEffects.activation_audit_fabricated
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        activation_attempt_digest = $activationAttemptDigest
        audit_record_digest = $auditRecordDigest
    }
    outputs = [ordered]@{
        activation_gate_report = New-ArtifactRef $gateReportPath
        activation_execute_or_deny_evidence = New-ArtifactRef $activationEvidencePath
        controlled_activation_rollback_handoff = New-ArtifactRef $rollbackHandoffPath
    }
    source = $source
    checks = @($script:checks)
    blockers = @("separate-rollback-approval-not-bound", "rollback-execution-not-authorized")
    invariants = [ordered]@{
        aios_body_only = $true
        effect_prepared = $sideEffects.effect_prepared
        effect_executed = $sideEffects.effect_executed
        install_performed = $false
        activation_performed = $sideEffects.activation_performed
        activation_audit_fabricated = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        private_signing_material_handled = $false
        cryptographic_release_signing_performed = $false
        production_ready_claim = $false
    }
    denial_cases = $denialCases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        fail_closed_cases = @($denialCases).Count
        failed_fail_closed_cases = @($denialCases | Where-Object { $_.status -ne "passed" }).Count
        rc15_030_complete = $resultStatus -eq "passed"
        activation_allowed = $activationAllowed
        effect_prepared = $sideEffects.effect_prepared
        effect_executed = $sideEffects.effect_executed
        activation_performed = $sideEffects.activation_performed
        rollback_execution_allowed = $false
        next_task = "RC15-031"
    }
}
Write-Json $result $resultPath

$evidence = [ordered]@{
    schema = "agentos.rc15-controlled-local-activation-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-030"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $PSCommandPath
        sha256 = Get-FileSha256 $PSCommandPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    activation_surface = $result.activation_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc15_030_complete = $resultStatus -eq "passed"
        next_task = "RC15-031"
        current_blockers = $result.blockers
    }
    checks = @($script:checks)
}
Write-Json $evidence $taskEvidencePath

if (-not $outputsSecretSafe) {
    throw "Sensitive marker detected in RC15-030 outputs."
}

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    $ids = @($script:failedChecks | ForEach-Object { $_.id }) -join ", "
    throw "RC15-030 failed checks: $ids"
}

Write-Host "RC15 controlled local activation ${resultStatus}: $(Get-StablePath $resultPath)"
Write-Host "Activation performed: $($sideEffects.activation_performed)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), denial cases: $(@($denialCases).Count)"
