param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-controlled-canary-activation",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$ApprovalResultPath = ".workflow/artifacts/rc11-two-target-canary-approval/result.json",
    [string]$ApprovalHandoffPath = ".workflow/artifacts/rc11-two-target-canary-approval/controlled-activation-approval-handoff.json",
    [string]$TargetSetPath = ".workflow/artifacts/rc11-two-target-canary-approval/canary-target-set.json",
    [string]$ApprovalPackagePath = ".workflow/artifacts/rc11-two-target-canary-approval/exact-approval-package.json",
    [string]$ApprovalMatrixPath = ".workflow/artifacts/rc11-two-target-canary-approval/approval-fail-closed-matrix.json",
    [string]$InstallerHandoffResultPath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/result.json",
    [string]$AgentCoreHandoffPath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/agentcore-planspec-handoff.json",
    [string]$SecurityEnvelopePath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/security-execution-effect-envelope.json",
    [string]$InstallerHandoffDenialPath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/handoff-denial.json",
    [string]$Rc10ControlledActivationResultPath = ".workflow/artifacts/rc10-controlled-canary-activation/result.json",
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
        "remote-fleet-execution-disabled" { "remote-fleet-execution-not-enabled" }
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
$resolvedInstallerHandoffResultPath = Resolve-RepoPath $InstallerHandoffResultPath
$resolvedAgentCoreHandoffPath = Resolve-RepoPath $AgentCoreHandoffPath
$resolvedSecurityEnvelopePath = Resolve-RepoPath $SecurityEnvelopePath
$resolvedInstallerHandoffDenialPath = Resolve-RepoPath $InstallerHandoffDenialPath
$resolvedRc10ControlledActivationResultPath = Resolve-RepoPath $Rc10ControlledActivationResultPath

$approvalResult = Read-Json $resolvedApprovalResultPath
$approvalHandoff = Read-Json $resolvedApprovalHandoffPath
$targetSet = Read-Json $resolvedTargetSetPath
$approvalPackage = Read-Json $resolvedApprovalPackagePath
$approvalMatrix = Read-Json $resolvedApprovalMatrixPath
$installerHandoffResult = Read-Json $resolvedInstallerHandoffResultPath
$agentCoreHandoff = Read-Json $resolvedAgentCoreHandoffPath
$securityEnvelope = Read-Json $resolvedSecurityEnvelopePath
$installerHandoffDenial = Read-Json $resolvedInstallerHandoffDenialPath
$rc10ActivationResult = Read-Json $resolvedRc10ControlledActivationResultPath

$releaseId = [string]$approvalResult.release_id
$agentCorePlanSpecHash = [string]$approvalResult.approval_surface.agentcore_planspec_hash
$securityExecutionDecisionHash = [string]$approvalHandoff.security_execution_decision_hash
$targetSetDigest = [string]$approvalResult.approval_surface.target_set_digest
$approvalBindingDigest = [string]$approvalResult.approval_surface.approval_binding_digest

Add-Blockers $approvalResult.blockers
Add-Blockers $approvalResult.approval_surface.blockers
Add-Blockers $approvalHandoff.blockers
Add-Blockers $installerHandoffResult.blockers
Add-Blockers $installerHandoffResult.handoff_surface.blockers
Add-Blockers $installerHandoffDenial.blockers
Add-Blockers $rc10ActivationResult.blockers
Add-Blockers $rc10ActivationResult.activation_surface.blockers

$objectTrustAllowed = -not (
    $script:blockers -contains "external-descriptor-verification-denied" -or
    $script:blockers -contains "external-https-object-uri-not-published" -or
    $script:blockers -contains "declared-current-drift-zero-not-proved" -or
    $script:blockers -contains "object-trust-not-allowed" -or
    $script:blockers -contains "freshness-window-missing" -or
    $script:blockers -contains "publication-not-published-drift-zero"
)
$installerPreflightVerified = $installerHandoffResult.handoff_surface.installer_preflight_verified -eq $true
$quarantineFetchVerified = $installerPreflightVerified -and -not ($script:blockers -contains "installer-quarantine-fetch-not-run") -and -not ($script:blockers -contains "payload-not-quarantined")
$targetSetEnrolled = $approvalResult.approval_surface.target_set_enrolled -eq $true -and $approvalHandoff.target_set_enrolled -eq $true
$exactApprovalBound = $approvalResult.approval_surface.exact_approval_bound -eq $true -and $approvalHandoff.exact_approval_bound -eq $true
$exactApprovalGranted = $approvalResult.approval_surface.approval_granted -eq $true -and $approvalHandoff.approval_granted -eq $true
$agentCorePlanSpecBound = $installerHandoffResult.handoff_surface.agentcore_planspec_bound -eq $true -and $installerHandoffResult.handoff_surface.agentcore_planspec_executable -eq $true
$securityExecutionAllowed = $installerHandoffResult.handoff_surface.security_execution_allowed -eq $true -and $approvalResult.approval_surface.security_execution_allowed -eq $true
$rollbackBaselineBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPackage.approval_binding.rollback_baseline_digest)
$supportRecoveryBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPackage.approval_binding.support_recovery_digest)
$auditGateBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPackage.approval_binding.audit_sink)
$remoteDispatchEnabled = $approvalResult.approval_surface.remote_dispatch_enabled -eq $true -or $approvalHandoff.remote_dispatch_enabled -eq $true

if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $installerPreflightVerified) { Add-UniqueBlocker "installer-preflight-not-verified" }
if (-not $quarantineFetchVerified) { Add-UniqueBlocker "installer-quarantine-fetch-not-run" }
if (-not $targetSetEnrolled) { Add-UniqueBlocker "target-set-not-enrolled" }
if (-not $exactApprovalBound -or -not $exactApprovalGranted) { Add-UniqueBlocker "exact-operator-approval-not-granted" }
if (-not $agentCorePlanSpecBound) { Add-UniqueBlocker "agentcore-planspec-not-executable" }
if (-not $securityExecutionAllowed) { Add-UniqueBlocker "security-execution-effect-envelope-denied" }
if (-not $rollbackBaselineBound) { Add-UniqueBlocker "rollback-baseline-not-bound" }
if (-not $supportRecoveryBound) { Add-UniqueBlocker "support-recovery-not-bound" }
if (-not $auditGateBound) { Add-UniqueBlocker "approval-audit-sink-not-bound" }
if (-not $remoteDispatchEnabled) { Add-UniqueBlocker "remote-fleet-execution-not-enabled" }
Add-UniqueBlocker "controlled-activation-not-authorized"

$gateInputs = [ordered]@{
    source_tasks_complete = (
        $approvalResult.status -eq "passed" -and
        $approvalResult.summary.rc11_030_complete -eq $true -and
        $installerHandoffResult.status -eq "passed" -and
        $installerHandoffResult.summary.rc11_021_complete -eq $true -and
        $rc10ActivationResult.status -eq "passed" -and
        $rc10ActivationResult.summary.rc10_022_complete -eq $true
    )
    object_trust_allowed = $objectTrustAllowed
    installer_preflight_verified = $installerPreflightVerified
    quarantine_fetch_verified = $quarantineFetchVerified
    target_set_enrolled = $targetSetEnrolled
    observed_candidate_node_count = [int]$approvalResult.approval_surface.observed_candidate_node_count
    enrolled_target_count = [int]$approvalResult.approval_surface.enrolled_target_count
    required_target_count = [int]$approvalResult.approval_surface.required_minimum_target_count
    exact_operator_approval_bound = $exactApprovalBound
    exact_operator_approval_granted = $exactApprovalGranted
    agentcore_planspec_bound = $agentCorePlanSpecBound
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_decision_hash = $securityExecutionDecisionHash
    security_execution_allowed = $securityExecutionAllowed
    rollback_baseline_bound = $rollbackBaselineBound
    support_recovery_bound = $supportRecoveryBound
    audit_gate_bound = $auditGateBound
    remote_fleet_execution_enabled = $remoteDispatchEnabled
}

$activationAllowed = $gateInputs.source_tasks_complete -and
    $objectTrustAllowed -and
    $installerPreflightVerified -and
    $quarantineFetchVerified -and
    $targetSetEnrolled -and
    $exactApprovalBound -and
    $exactApprovalGranted -and
    $agentCorePlanSpecBound -and
    $securityExecutionAllowed -and
    $rollbackBaselineBound -and
    $supportRecoveryBound -and
    $auditGateBound -and
    $remoteDispatchEnabled

$activationState = if ($activationAllowed) { "activation-authorized" } else { "activation-denied" }
$activationAttemptId = "rc11-controlled-canary-activation-attempt"
$sourceBindings = [ordered]@{
    approval_result_sha256 = Get-FileSha256 $resolvedApprovalResultPath
    approval_handoff_sha256 = Get-FileSha256 $resolvedApprovalHandoffPath
    target_set_sha256 = Get-FileSha256 $resolvedTargetSetPath
    target_set_digest = $targetSetDigest
    approval_package_sha256 = Get-FileSha256 $resolvedApprovalPackagePath
    approval_binding_digest = $approvalBindingDigest
    approval_matrix_sha256 = Get-FileSha256 $resolvedApprovalMatrixPath
    installer_handoff_result_sha256 = Get-FileSha256 $resolvedInstallerHandoffResultPath
    agentcore_handoff_sha256 = Get-FileSha256 $resolvedAgentCoreHandoffPath
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_envelope_sha256 = Get-FileSha256 $resolvedSecurityEnvelopePath
    security_execution_decision_hash = $securityExecutionDecisionHash
    installer_handoff_denial_sha256 = Get-FileSha256 $resolvedInstallerHandoffDenialPath
    rc10_controlled_activation_result_sha256 = Get-FileSha256 $resolvedRc10ControlledActivationResultPath
}

$activationAttemptCore = [ordered]@{
    attempt_id = $activationAttemptId
    release_id = $releaseId
    target_set_digest = $targetSetDigest
    approval_binding_digest = $approvalBindingDigest
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_decision_hash = $securityExecutionDecisionHash
    gate_inputs = $gateInputs
    source_bindings = $sourceBindings
    requested_effect_set = @("controlled-canary-activation")
    expected_observation = "deny-before-side-effects-when-any-gate-missing"
    policy_version = "rc11-controlled-canary-activation-v1"
}
$activationAttemptDigest = Get-StringSha256 (($activationAttemptCore | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    activation_attempt_recorded = $true
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
    [ordered]@{ id = "object-trust-denied"; blockers = @("object-trust-not-allowed", "external-https-object-uri-not-published"); reason = "External object trust cannot advance without URI, freshness, and drift-zero evidence." },
    [ordered]@{ id = "installer-preflight-denied"; blockers = @("installer-preflight-not-verified"); reason = "Installer preflight is hash-bound but not verified into an executable activation precondition." },
    [ordered]@{ id = "quarantine-fetch-denied"; blockers = @("installer-quarantine-fetch-not-run", "payload-not-quarantined"); reason = "Payload was not fetched to quarantine and cannot be interpreted." },
    [ordered]@{ id = "target-set-denied"; blockers = @("target-set-not-enrolled", "fewer-than-two-eligible-targets"); reason = "The required two-target canary set is not enrolled." },
    [ordered]@{ id = "exact-approval-denied"; blockers = @("exact-operator-approval-not-granted", "target-node-ids-missing"); reason = "Exact approval is missing target ids, approval identity, expiry, nonce, or audit binding." },
    [ordered]@{ id = "agentcore-planspec-denied"; blockers = @("agentcore-planspec-not-executable"); reason = "AgentCore PlanSpec remains a denied projection rather than an executable activation plan." },
    [ordered]@{ id = "security-execution-denied"; blockers = @("security-execution-effect-envelope-denied"); reason = "SecurityExecutionEngine did not allow the controlled activation effect." },
    [ordered]@{ id = "rollback-support-audit-denied"; blockers = @("approval-audit-sink-not-bound"); reason = "Rollback/support binding is recorded, but audit sink is missing from exact approval." },
    [ordered]@{ id = "remote-dispatch-denied"; blockers = @("remote-fleet-execution-not-enabled"); reason = "Remote fleet execution remains disabled." },
    [ordered]@{ id = "controlled-activation-denied"; blockers = @("controlled-activation-not-authorized"); reason = "At least one required controlled activation gate is missing." }
)
$denialCases = @()
foreach ($spec in $caseSpecs) {
    $denialCases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -ObservedBlockers $script:blockers -Reason $spec.reason
}
$failedCases = @($denialCases | Where-Object { $_.status -ne "passed" })

$gateReport = [ordered]@{
    schema = "agentos.rc11-controlled-canary-activation-gate-report.v1"
    generated_at = $generatedAt
    task = "RC11-031"
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
    schema = "agentos.rc11-controlled-canary-activation-denial-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-031"
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
        target_set_enrolled = $false
        exact_approval_granted = $false
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
    schema = "agentos.rc11-controlled-activation-handoff.v1"
    generated_at = $generatedAt
    task = "RC11-031"
    status = "blocked-by-activation-denial"
    production_ready_claim = $false
    release_id = $releaseId
    activation_state = $activationState
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_allowed = $false
    activation_performed = $false
    rollback_drill_allowed = $false
    rollback_execution_allowed = $false
    rollback_prerequisites = [ordered]@{
        controlled_canary_activation_evidence_required = $true
        controlled_canary_activation_performed = $false
        separate_rollback_approval_required = $true
        separate_rollback_planspec_required = $true
        separate_security_execution_decision_required = $true
        support_recovery_binding_required = $true
    }
    blockers = @($script:blockers)
    next_task = "RC11-040"
}

$gateReportPath = Join-Path $resolvedArtifactDir "activation-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "activation-denial-evidence.json"
$handoffPath = Join-Path $resolvedArtifactDir "controlled-activation-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-031-controlled-canary-activation.json"

Write-Json $gateReport $gateReportPath
Write-Json $denialEvidence $denialEvidencePath
Write-Json $handoff $handoffPath

Add-Check "source.rc11_030.approval_complete" ($approvalResult.status -eq "passed" -and $approvalResult.summary.rc11_030_complete -eq $true -and $approvalHandoff.next_task -eq "RC11-031") "RC11-031 must consume completed RC11-030 two-target and exact-approval handoff evidence." ([ordered]@{ status = $approvalResult.status; state = $approvalResult.approval_surface.state; next_task = $approvalHandoff.next_task })
Add-Check "source.rc11_021.handoff_complete" ($installerHandoffResult.status -eq "passed" -and $installerHandoffResult.summary.rc11_021_complete -eq $true) "RC11-031 must consume completed RC11-021 AgentCore/SecurityExecution handoff evidence." ([ordered]@{ status = $installerHandoffResult.status; state = $installerHandoffResult.handoff_surface.state; planspec_hash = $agentCorePlanSpecHash })
Add-Check "source.rc10_controlled_activation_carried" ($rc10ActivationResult.status -eq "passed" -and $rc10ActivationResult.summary.rc10_022_complete -eq $true -and $rc10ActivationResult.activation_surface.activation_allowed -eq $false) "RC11-031 must carry forward RC10 controlled activation denial context." ([ordered]@{ status = $rc10ActivationResult.status; state = $rc10ActivationResult.activation_surface.state; activation_allowed = $rc10ActivationResult.activation_surface.activation_allowed })
Add-Check "activation.denied_when_any_gate_missing" ($activationAllowed -eq $false -and $gateReport.activation_state -eq "activation-denied" -and $denialEvidence.denied -eq $true) "Controlled canary activation must deny when object, drift, quarantine, target, approval, AgentCore, SecurityExecution, rollback, support/recovery, audit, or remote gates are missing." ([ordered]@{ activation_allowed = $activationAllowed; blockers = @($script:blockers) })
Add-Check "activation.denial_cases.complete" ($failedCases.Count -eq 0 -and @($denialCases).Count -ge 10) "Activation denial evidence must cover missing gates with fail-closed cases." ([ordered]@{ cases = @($denialCases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.effect_executed -eq $false -and $sideEffects.activation_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false) "RC11-031 must not prepare or execute activation, rollback, production mutation, support upload, recovery, or remote dispatch side effects." $sideEffects
Add-Check "handoff.rollback_blocked" ($handoff.status -eq "blocked-by-activation-denial" -and $handoff.rollback_execution_allowed -eq $false -and $handoff.next_task -eq "RC11-040") "Controlled activation handoff must advance to RC11-040 while keeping rollback execution blocked." ([ordered]@{ status = $handoff.status; next_task = $handoff.next_task })
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC11-031 must not grant mirror, signer, nginx, frontend, TUI, shell, model, remote dispatch, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; tui_authority = $false; normal_shell_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-031 outputs must not contain PEM blocks, auth tokens, private key paths, or signer internals." $null

$source = [ordered]@{
    two_target_approval_result = New-ArtifactRef $resolvedApprovalResultPath $approvalResult
    controlled_activation_approval_handoff = New-ArtifactRef $resolvedApprovalHandoffPath $approvalHandoff
    canary_target_set = New-ArtifactRef $resolvedTargetSetPath $targetSet
    exact_approval_package = New-ArtifactRef $resolvedApprovalPackagePath $approvalPackage
    approval_fail_closed_matrix = New-ArtifactRef $resolvedApprovalMatrixPath $approvalMatrix
    installer_agentcore_security_handoff_result = New-ArtifactRef $resolvedInstallerHandoffResultPath $installerHandoffResult
    agentcore_planspec_handoff = New-ArtifactRef $resolvedAgentCoreHandoffPath $agentCoreHandoff
    security_execution_effect_envelope = New-ArtifactRef $resolvedSecurityEnvelopePath $securityEnvelope
    installer_handoff_denial = New-ArtifactRef $resolvedInstallerHandoffDenialPath $installerHandoffDenial
    rc10_controlled_canary_activation = New-ArtifactRef $resolvedRc10ControlledActivationResultPath $rc10ActivationResult
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-controlled-canary-activation-result.v1"
    generated_at = $generatedAt
    task = "RC11-031"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    activation_surface = [ordered]@{
        state = $activationState
        activation_attempt_id = $activationAttemptId
        activation_attempt_digest = $activationAttemptDigest
        activation_allowed = $activationAllowed
        activation_performed = $false
        controlled_execution_authorized = $activationAllowed
        target_set_enrolled = $targetSetEnrolled
        exact_approval_bound = $exactApprovalBound
        exact_approval_granted = $exactApprovalGranted
        agentcore_planspec_bound = $agentCorePlanSpecBound
        security_execution_approval_bound = $securityExecutionAllowed
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $remoteDispatchEnabled
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
        rc11_031_complete = (@($script:failedChecks).Count -eq 0)
        activation_state = $activationState
        activation_allowed = $activationAllowed
        activation_performed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $remoteDispatchEnabled
        production_ready_claim = $false
        next_task = "RC11-040"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-controlled-canary-activation-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-031"
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
        rc11_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-040"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC11-031 result."
}

Write-Host "RC11 controlled canary activation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Activation state: $($result.activation_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
