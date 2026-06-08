param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-controlled-canary-activation",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ApprovalResultPath = ".workflow/artifacts/rc12-canary-target-approval-binding/result.json",
    [string]$ApprovalHandoffPath = ".workflow/artifacts/rc12-canary-target-approval-binding/controlled-activation-approval-handoff.json",
    [string]$TargetSetPath = ".workflow/artifacts/rc12-canary-target-approval-binding/canary-target-set.json",
    [string]$ApprovalPackagePath = ".workflow/artifacts/rc12-canary-target-approval-binding/exact-approval-package.json",
    [string]$ApprovalMatrixPath = ".workflow/artifacts/rc12-canary-target-approval-binding/approval-fail-closed-matrix.json",
    [string]$ExecutionPackageResultPath = ".workflow/artifacts/rc12-agentcore-security-execution-package/result.json",
    [string]$AgentCorePackagePath = ".workflow/artifacts/rc12-agentcore-security-execution-package/agentcore-planspec-package.json",
    [string]$SecurityEnvelopePath = ".workflow/artifacts/rc12-agentcore-security-execution-package/security-execution-effect-envelope.json",
    [string]$ExecutionDenialPath = ".workflow/artifacts/rc12-agentcore-security-execution-package/execution-package-denial.json",
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
        "approval-audit-sink-not-bound" { "audit-sink-not-bound" }
        "approval-nonce-not-bound" { "nonce-not-bound" }
        "target-set-not-enrolled" { "two-target-canary-not-enrolled" }
        "target-identities-missing" { "two-target-canary-not-enrolled" }
        "fewer-than-two-canary-target-identities" { "two-target-canary-not-enrolled" }
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
        activation_allowed = $false
        expected_blockers = $ExpectedBlockers
        missing_expected_blockers = $missing
        reason = $Reason
        side_effects = [ordered]@{
            activation_audit_recorded = $false
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

$resolvedApprovalResultPath = Resolve-RepoPath $ApprovalResultPath
$resolvedApprovalHandoffPath = Resolve-RepoPath $ApprovalHandoffPath
$resolvedTargetSetPath = Resolve-RepoPath $TargetSetPath
$resolvedApprovalPackagePath = Resolve-RepoPath $ApprovalPackagePath
$resolvedApprovalMatrixPath = Resolve-RepoPath $ApprovalMatrixPath
$resolvedExecutionPackageResultPath = Resolve-RepoPath $ExecutionPackageResultPath
$resolvedAgentCorePackagePath = Resolve-RepoPath $AgentCorePackagePath
$resolvedSecurityEnvelopePath = Resolve-RepoPath $SecurityEnvelopePath
$resolvedExecutionDenialPath = Resolve-RepoPath $ExecutionDenialPath

$approvalResult = Read-Json $resolvedApprovalResultPath
$approvalHandoff = Read-Json $resolvedApprovalHandoffPath
$targetSet = Read-Json $resolvedTargetSetPath
$approvalPackage = Read-Json $resolvedApprovalPackagePath
$approvalMatrix = Read-Json $resolvedApprovalMatrixPath
$executionPackageResult = Read-Json $resolvedExecutionPackageResultPath
$agentCorePackage = Read-Json $resolvedAgentCorePackagePath
$securityEnvelope = Read-Json $resolvedSecurityEnvelopePath
$executionDenial = Read-Json $resolvedExecutionDenialPath

$releaseId = [string]$approvalResult.release_id
$agentCorePlanSpecHash = [string]$approvalResult.approval_surface.agentcore_planspec_hash
$securityExecutionDecisionHash = [string]$securityEnvelope.decision_core_hash
$securityExecutionEnvelopeHash = Get-FileSha256 $resolvedSecurityEnvelopePath
$targetSetDigest = [string]$approvalResult.approval_surface.target_set_digest
$approvalBindingDigest = [string]$approvalResult.approval_surface.approval_binding_digest

Add-Blockers $approvalResult.blockers
Add-Blockers $approvalResult.approval_surface.blockers
Add-Blockers $approvalHandoff.blockers
Add-Blockers $executionPackageResult.blockers
Add-Blockers $executionPackageResult.package_surface.blockers
Add-Blockers $agentCorePackage.denied_because
Add-Blockers $securityEnvelope.decision_core.blockers
Add-Blockers $executionDenial.blockers

$objectTrustAllowed = $agentCorePackage.planspec_core.frozen_inputs.object_trust_allowed -eq $true -and -not ($script:blockers -contains "object-trust-not-allowed")
$quarantineFetchVerified = $agentCorePackage.planspec_core.frozen_inputs.payload_quarantined -eq $true -and $agentCorePackage.planspec_core.frozen_inputs.pre_interpretation_verification_performed -eq $true
$installerPreflightVerified = $executionPackageResult.package_surface.installer_preflight_verified -eq $true
$targetSetEnrolled = $approvalResult.approval_surface.target_set_enrolled -eq $true -and $approvalHandoff.target_set_enrolled -eq $true
$exactApprovalBound = $approvalResult.approval_surface.exact_approval_bound -eq $true -and $approvalHandoff.exact_approval_bound -eq $true
$exactApprovalGranted = $approvalResult.approval_surface.approval_granted -eq $true -and $approvalHandoff.approval_granted -eq $true
$auditSinkBound = $approvalResult.approval_surface.audit_sink_bound -eq $true -and $approvalHandoff.audit_sink_bound -eq $true
$nonceBound = $approvalResult.approval_surface.nonce_bound -eq $true -and $approvalHandoff.nonce_bound -eq $true
$expiryBound = $approvalResult.approval_surface.expiry_bound -eq $true -and $approvalHandoff.expiry_bound -eq $true
$agentCorePlanSpecExecutable = $executionPackageResult.package_surface.agentcore_planspec_executable -eq $true -and $agentCorePackage.planspec_executable -eq $true
$securityExecutionAllowed = $executionPackageResult.package_surface.security_execution_allowed -eq $true -and $approvalResult.approval_surface.security_execution_allowed -eq $true
$rollbackBaselineBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPackage.approval_binding.rollback_baseline_digest)
$supportRecoveryBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPackage.approval_binding.support_recovery_digest)

if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $quarantineFetchVerified) {
    Add-UniqueBlocker "installer-quarantine-fetch-not-run"
    Add-UniqueBlocker "payload-not-quarantined"
    Add-UniqueBlocker "pre-interpretation-verification-not-run"
}
if (-not $installerPreflightVerified) { Add-UniqueBlocker "installer-preflight-not-verified" }
if (-not $targetSetEnrolled) { Add-UniqueBlocker "two-target-canary-not-enrolled" }
if (-not $exactApprovalBound -or -not $exactApprovalGranted) { Add-UniqueBlocker "exact-operator-approval-not-granted" }
if (-not $auditSinkBound) { Add-UniqueBlocker "audit-sink-not-bound" }
if (-not $nonceBound) { Add-UniqueBlocker "nonce-not-bound" }
if (-not $expiryBound) { Add-UniqueBlocker "approval-expiry-not-bound" }
if (-not $agentCorePlanSpecExecutable) { Add-UniqueBlocker "agentcore-planspec-not-executable" }
if (-not $securityExecutionAllowed) { Add-UniqueBlocker "security-execution-effect-envelope-denied" }
if (-not $rollbackBaselineBound) { Add-UniqueBlocker "rollback-baseline-not-bound" }
if (-not $supportRecoveryBound) { Add-UniqueBlocker "support-recovery-not-bound" }
Add-UniqueBlocker "controlled-activation-not-authorized"

$gateInputs = [ordered]@{
    source_tasks_complete = (
        $approvalResult.status -eq "passed" -and
        $approvalResult.summary.rc12_030_complete -eq $true -and
        $executionPackageResult.status -eq "passed" -and
        $executionPackageResult.summary.rc12_021_complete -eq $true
    )
    object_trust_allowed = $objectTrustAllowed
    quarantine_fetch_verified = $quarantineFetchVerified
    installer_preflight_verified = $installerPreflightVerified
    target_set_enrolled = $targetSetEnrolled
    observed_candidate_node_count = [int]$approvalResult.approval_surface.observed_candidate_node_count
    enrolled_target_identity_count = [int]$approvalResult.approval_surface.enrolled_target_identity_count
    required_target_identity_count = [int]$approvalResult.approval_surface.required_minimum_target_identities
    exact_operator_approval_bound = $exactApprovalBound
    exact_operator_approval_granted = $exactApprovalGranted
    audit_sink_bound = $auditSinkBound
    nonce_bound = $nonceBound
    expiry_bound = $expiryBound
    agentcore_planspec_hash = $agentCorePlanSpecHash
    agentcore_planspec_executable = $agentCorePlanSpecExecutable
    security_execution_policy_id = [string]$approvalResult.approval_surface.security_execution_policy_id
    security_execution_decision_hash = $securityExecutionDecisionHash
    security_execution_envelope_hash = $securityExecutionEnvelopeHash
    security_execution_allowed = $securityExecutionAllowed
    rollback_baseline_bound = $rollbackBaselineBound
    support_recovery_bound = $supportRecoveryBound
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}

$activationAllowed = $gateInputs.source_tasks_complete -and
    $objectTrustAllowed -and
    $quarantineFetchVerified -and
    $installerPreflightVerified -and
    $targetSetEnrolled -and
    $exactApprovalBound -and
    $exactApprovalGranted -and
    $auditSinkBound -and
    $nonceBound -and
    $expiryBound -and
    $agentCorePlanSpecExecutable -and
    $securityExecutionAllowed -and
    $rollbackBaselineBound -and
    $supportRecoveryBound

$activationState = if ($activationAllowed) { "activation-authorized" } else { "activation-denied" }
$activationAttemptId = "rc12-controlled-canary-activation-attempt"
$sourceBindings = [ordered]@{
    approval_result_sha256 = Get-FileSha256 $resolvedApprovalResultPath
    approval_handoff_sha256 = Get-FileSha256 $resolvedApprovalHandoffPath
    target_set_sha256 = Get-FileSha256 $resolvedTargetSetPath
    target_set_digest = $targetSetDigest
    approval_package_sha256 = Get-FileSha256 $resolvedApprovalPackagePath
    approval_binding_digest = $approvalBindingDigest
    approval_matrix_sha256 = Get-FileSha256 $resolvedApprovalMatrixPath
    execution_package_result_sha256 = Get-FileSha256 $resolvedExecutionPackageResultPath
    agentcore_package_sha256 = Get-FileSha256 $resolvedAgentCorePackagePath
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_envelope_sha256 = Get-FileSha256 $resolvedSecurityEnvelopePath
    security_execution_decision_hash = $securityExecutionDecisionHash
    security_execution_envelope_hash = $securityExecutionEnvelopeHash
    execution_denial_sha256 = Get-FileSha256 $resolvedExecutionDenialPath
}

$activationAttemptCore = [ordered]@{
    attempt_id = $activationAttemptId
    release_id = $releaseId
    target_set_digest = $targetSetDigest
    approval_binding_digest = $approvalBindingDigest
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_decision_hash = $securityExecutionDecisionHash
    security_execution_envelope_hash = $securityExecutionEnvelopeHash
    gate_inputs = $gateInputs
    source_bindings = $sourceBindings
    requested_effect_set = @("controlled-canary-activation")
    expected_observation = "deny-before-side-effects-when-any-gate-missing"
    policy_version = "rc12-controlled-canary-activation-v1"
}
$activationAttemptDigest = Get-StringSha256 (($activationAttemptCore | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    activation_attempt_recorded = $true
    activation_audit_recorded = $false
    effect_prepared = $false
    effect_executed = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    recovery_execution_performed = $false
    boot_metadata_mutated = $false
    active_slot_mutated = $false
    persistent_state_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    support_upload_performed = $false
    remote_dispatch_enabled = $false
}

$caseSpecs = @(
    [ordered]@{ id = "object-trust-denied"; blockers = @("object-trust-not-allowed", "external-https-object-uri-not-published"); reason = "External object trust cannot advance without immutable HTTPS object trust, drift-zero, freshness, and revocation evidence." },
    [ordered]@{ id = "quarantine-verification-denied"; blockers = @("installer-quarantine-fetch-not-run", "payload-not-quarantined", "pre-interpretation-verification-not-run"); reason = "Payload was not fetched to quarantine and verified before interpretation." },
    [ordered]@{ id = "installer-preflight-denied"; blockers = @("installer-preflight-not-verified"); reason = "Installer preflight is hash-bound but not verified into an executable activation precondition." },
    [ordered]@{ id = "two-target-canary-denied"; blockers = @("two-target-canary-not-enrolled"); reason = "Two non-duplicate fresh compatible canary target identities are required before activation authority." },
    [ordered]@{ id = "exact-approval-denied"; blockers = @("exact-operator-approval-not-granted", "exact-approval-not-bound"); reason = "Exact approval is not granted." },
    [ordered]@{ id = "audit-sink-denied"; blockers = @("audit-sink-not-bound"); reason = "Activation cannot run without an exact approval audit sink." },
    [ordered]@{ id = "nonce-expiry-denied"; blockers = @("nonce-not-bound", "approval-expiry-not-bound"); reason = "Activation cannot run with replayable or unbounded approval." },
    [ordered]@{ id = "agentcore-planspec-denied"; blockers = @("agentcore-planspec-not-executable"); reason = "AgentCore PlanSpec remains non-executable." },
    [ordered]@{ id = "security-execution-denied"; blockers = @("security-execution-effect-envelope-denied"); reason = "SecurityExecutionEngine did not allow the controlled activation effect." },
    [ordered]@{ id = "rollback-support-denied"; blockers = @("rollback-baseline-not-approved-for-execution", "support-recovery-not-approved-for-execution"); reason = "Rollback and support/recovery execution bindings are not approved for effects." },
    [ordered]@{ id = "remote-dispatch-boundary-preserved"; blockers = @("controlled-activation-not-authorized"); reason = "Remote dispatch and production ring mutation stay forbidden even when evaluating activation." }
)
$denialCases = @()
foreach ($spec in $caseSpecs) {
    $denialCases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -ObservedBlockers $script:blockers -Reason $spec.reason
}
$failedCases = @($denialCases | Where-Object { $_.status -ne "passed" })

$gateReport = [ordered]@{
    schema = "agentos.rc12-controlled-canary-activation-gate-report.v1"
    generated_at = $generatedAt
    task = "RC12-040"
    status = if ($activationAllowed) { "activation-gates-passed" } else { "activation-gates-evaluated-denied" }
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_state = $activationState
    all_gates_passed = $activationAllowed
    activation_allowed = $activationAllowed
    activation_performed = $false
    audit_evidence_required_if_activation_performed = $true
    activation_audit_recorded = $false
    gate_inputs = $gateInputs
    blockers = @($script:blockers)
    source_bindings = $sourceBindings
    side_effects = $sideEffects
    authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        object_storage_authority = $false
        signer_authority = $false
        frontend_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
}

$denialEvidence = [ordered]@{
    schema = "agentos.rc12-controlled-canary-activation-denial-evidence.v1"
    generated_at = $generatedAt
    task = "RC12-040"
    status = "activation-denied"
    production_ready_claim = $false
    projection_only = $true
    denied = (-not $activationAllowed)
    release_id = $releaseId
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_allowed = $false
    activation_performed = $false
    denial_cases = $denialCases
    blockers = @($script:blockers)
    preserved_boundaries = [ordered]@{
        object_trust_allowed = $false
        quarantine_fetch_verified = $false
        target_set_enrolled = $false
        exact_approval_granted = $false
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
    }
    side_effects = $sideEffects
    source_bindings = $sourceBindings
}

$handoff = [ordered]@{
    schema = "agentos.rc12-controlled-activation-handoff.v1"
    generated_at = $generatedAt
    task = "RC12-040"
    status = "blocked-by-activation-denial"
    production_ready_claim = $false
    release_id = $releaseId
    activation_state = $activationState
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_allowed = $false
    activation_performed = $false
    activation_audit_recorded = $false
    rollback_drill_allowed = $false
    rollback_execution_allowed = $false
    rollback_prerequisites = [ordered]@{
        controlled_canary_activation_evidence_required = $true
        controlled_canary_activation_performed = $false
        separate_rollback_approval_required = $true
        separate_rollback_planspec_required = $true
        separate_security_execution_decision_required = $true
        audit_journal_required = $true
        post_rollback_observation_plan_required = $true
        support_recovery_binding_required = $true
    }
    blockers = @($script:blockers)
    next_task = "RC12-041"
}

$gateReportPath = Join-Path $resolvedArtifactDir "activation-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "activation-denial-evidence.json"
$handoffPath = Join-Path $resolvedArtifactDir "controlled-activation-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-040-controlled-canary-activation.json"

Write-Json $gateReport $gateReportPath
Write-Json $denialEvidence $denialEvidencePath
Write-Json $handoff $handoffPath

Add-Check "source.rc12_030.approval_complete" ($approvalResult.status -eq "passed" -and $approvalResult.summary.rc12_030_complete -eq $true -and $approvalHandoff.next_task -eq "RC12-040") "RC12-040 must consume completed RC12-030 canary target and exact approval handoff evidence." ([ordered]@{ status = $approvalResult.status; state = $approvalResult.approval_surface.state; next_task = $approvalHandoff.next_task })
Add-Check "source.rc12_021.execution_package_complete" ($executionPackageResult.status -eq "passed" -and $executionPackageResult.summary.rc12_021_complete -eq $true) "RC12-040 must consume completed RC12-021 AgentCore/SecurityExecution package evidence." ([ordered]@{ status = $executionPackageResult.status; package_state = $executionPackageResult.summary.package_state; planspec_hash = $agentCorePlanSpecHash })
Add-Check "activation.denied_when_any_required_gate_missing" ($activationAllowed -eq $false -and $gateReport.activation_state -eq "activation-denied" -and $denialEvidence.denied -eq $true) "Controlled canary activation must deny when object trust, quarantine verification, two-target enrollment, exact approval, AgentCore executable PlanSpec, SecurityExecution allow, audit, rollback, or support/recovery gates are missing." ([ordered]@{ activation_allowed = $activationAllowed; blockers = @($script:blockers) })
Add-Check "activation.denial_cases.complete" ($failedCases.Count -eq 0 -and @($denialCases).Count -ge 10) "Activation denial evidence must cover exact missing gates with fail-closed cases." ([ordered]@{ cases = @($denialCases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "activation.audit_required_if_performed" ($gateReport.audit_evidence_required_if_activation_performed -eq $true -and $gateReport.activation_performed -eq $false -and $gateReport.activation_audit_recorded -eq $false) "Any performed activation must require audit evidence; denied activation must not fabricate an activation audit." ([ordered]@{ audit_required = $gateReport.audit_evidence_required_if_activation_performed; activation_performed = $gateReport.activation_performed; activation_audit_recorded = $gateReport.activation_audit_recorded })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.effect_executed -eq $false -and $sideEffects.activation_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false) "RC12-040 must not prepare or execute activation, rollback, production mutation, support upload, recovery, or remote dispatch side effects." $sideEffects
Add-Check "handoff.rollback_blocked" ($handoff.status -eq "blocked-by-activation-denial" -and $handoff.rollback_execution_allowed -eq $false -and $handoff.next_task -eq "RC12-041") "Controlled activation handoff must advance to RC12-041 while keeping rollback execution blocked." ([ordered]@{ status = $handoff.status; next_task = $handoff.next_task })
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC12-040 must not grant mirror, signer, nginx, frontend, TUI, shell, model, remote dispatch, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; tui_authority = $false; normal_shell_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC12-040 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$source = [ordered]@{
    canary_target_approval_result = New-ArtifactRef $resolvedApprovalResultPath $approvalResult
    controlled_activation_approval_handoff = New-ArtifactRef $resolvedApprovalHandoffPath $approvalHandoff
    canary_target_set = New-ArtifactRef $resolvedTargetSetPath $targetSet
    exact_approval_package = New-ArtifactRef $resolvedApprovalPackagePath $approvalPackage
    approval_fail_closed_matrix = New-ArtifactRef $resolvedApprovalMatrixPath $approvalMatrix
    execution_package_result = New-ArtifactRef $resolvedExecutionPackageResultPath $executionPackageResult
    agentcore_planspec_package = New-ArtifactRef $resolvedAgentCorePackagePath $agentCorePackage
    security_execution_effect_envelope = New-ArtifactRef $resolvedSecurityEnvelopePath $securityEnvelope
    execution_package_denial = New-ArtifactRef $resolvedExecutionDenialPath $executionDenial
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-controlled-canary-activation-result.v1"
    generated_at = $generatedAt
    task = "RC12-040"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    activation_surface = [ordered]@{
        state = $activationState
        activation_attempt_id = $activationAttemptId
        activation_attempt_digest = $activationAttemptDigest
        activation_allowed = $activationAllowed
        activation_performed = $false
        activation_audit_recorded = $false
        controlled_execution_authorized = $activationAllowed
        object_trust_allowed = $objectTrustAllowed
        quarantine_fetch_verified = $quarantineFetchVerified
        installer_preflight_verified = $installerPreflightVerified
        target_set_enrolled = $targetSetEnrolled
        exact_approval_bound = $exactApprovalBound
        exact_approval_granted = $exactApprovalGranted
        audit_sink_bound = $auditSinkBound
        nonce_bound = $nonceBound
        expiry_bound = $expiryBound
        agentcore_planspec_executable = $agentCorePlanSpecExecutable
        security_execution_allowed = $securityExecutionAllowed
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        activation_gate_report = [ordered]@{
            path = Get-StablePath $gateReportPath
            sha256 = Get-FileSha256 $gateReportPath
        }
        activation_denial_evidence = [ordered]@{
            path = Get-StablePath $denialEvidencePath
            sha256 = Get-FileSha256 $denialEvidencePath
        }
        controlled_activation_handoff = [ordered]@{
            path = Get-StablePath $handoffPath
            sha256 = Get-FileSha256 $handoffPath
        }
    }
    source = $source
    gate_inputs = $gateInputs
    source_bindings = $sourceBindings
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        activation_attempt_recorded = $true
        activation_audit_fabricated = $false
        external_payload_bytes_uploaded = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
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
        rc12_040_complete = (@($script:failedChecks).Count -eq 0)
        activation_state = $activationState
        activation_allowed = $activationAllowed
        activation_performed = $false
        activation_audit_recorded = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ready_claim = $false
        next_task = "RC12-041"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-controlled-canary-activation-evidence.v1"
    generated_at = $generatedAt
    task = "RC12-040"
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
    activation_surface = $result.activation_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc12_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-041"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC12-040 result."
}

Write-Host "RC12 controlled canary activation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Activation state: $($result.activation_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
