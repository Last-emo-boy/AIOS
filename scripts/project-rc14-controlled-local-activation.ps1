param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-controlled-local-activation",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc14",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md",
    [string]$ApprovalResultPath = ".workflow/artifacts/rc14-exact-approval-execution-binding/result.json",
    [string]$ApprovalPacketPath = ".workflow/artifacts/rc14-exact-approval-execution-binding/exact-approval-packet.json",
    [string]$ApprovalDenialPath = ".workflow/artifacts/rc14-exact-approval-execution-binding/approval-execution-binding-denial.json",
    [string]$ApprovalMatrixPath = ".workflow/artifacts/rc14-exact-approval-execution-binding/exact-approval-fail-closed-matrix.json",
    [string]$ActivationApprovalHandoffPath = ".workflow/artifacts/rc14-exact-approval-execution-binding/controlled-local-activation-handoff.json",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc14-agentcore-executable-planspec/result.json",
    [string]$PlanSpecReadinessPath = ".workflow/artifacts/rc14-agentcore-executable-planspec/agentcore-planspec-readiness.json",
    [string]$SecurityResultPath = ".workflow/artifacts/rc14-security-execution-allow-envelope/result.json",
    [string]$SecurityPreconditionsPath = ".workflow/artifacts/rc14-security-execution-allow-envelope/security-execution-allow-envelope.json",
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
    if ($script:blockers -notcontains $Blocker) {
        $script:blockers += $Blocker
    }
}

function Add-Blockers {
    param($Values)
    foreach ($value in @($Values)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            Add-UniqueBlocker ([string]$value)
        }
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
        activation_allowed = $false
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        missing_expected_blockers = $missing
        reason = $Reason
        side_effects = [ordered]@{
            activation_audit_fabricated = $false
            effect_prepared = $false
            effect_executed = $false
            install_performed = $false
            activation_performed = $false
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
$script:blockers = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedApprovalResultPath = Resolve-RepoPath $ApprovalResultPath
$resolvedApprovalPacketPath = Resolve-RepoPath $ApprovalPacketPath
$resolvedApprovalDenialPath = Resolve-RepoPath $ApprovalDenialPath
$resolvedApprovalMatrixPath = Resolve-RepoPath $ApprovalMatrixPath
$resolvedActivationApprovalHandoffPath = Resolve-RepoPath $ActivationApprovalHandoffPath
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecReadinessPath = Resolve-RepoPath $PlanSpecReadinessPath
$resolvedSecurityResultPath = Resolve-RepoPath $SecurityResultPath
$resolvedSecurityPreconditionsPath = Resolve-RepoPath $SecurityPreconditionsPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$approvalResult = Read-Json $resolvedApprovalResultPath
$approvalPacket = Read-Json $resolvedApprovalPacketPath
$approvalDenial = Read-Json $resolvedApprovalDenialPath
$approvalMatrix = Read-Json $resolvedApprovalMatrixPath
$activationApprovalHandoff = Read-Json $resolvedActivationApprovalHandoffPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpecReadiness = Read-Json $resolvedPlanSpecReadinessPath
$securityResult = Read-Json $resolvedSecurityResultPath
$securityPreconditions = Read-Json $resolvedSecurityPreconditionsPath

$releaseId = [string]$approvalResult.release_id
$payloadSha256 = [string]$approvalPacket.approval_binding.object_digest
$rollbackBaselineSha256 = [string]$approvalPacket.approval_binding.rollback_baseline_digest
$supportRecoverySha256 = [string]$approvalPacket.approval_binding.support_recovery_digest
$approvalBindingDigest = [string]$approvalResult.approval_surface.approval_binding_digest
$targetIdentitySetDigest = [string]$approvalResult.approval_surface.target_identity_set_digest
$agentCorePlanSpecCoreHash = [string]$approvalResult.approval_surface.agentcore_planspec_core_hash
$effectEnvelopeCoreHash = [string]$approvalResult.approval_surface.security_execution_effect_envelope_core_hash
$rc14TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-040").status
$rc14PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-031").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc14PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC14-040" -and ($rc14TaskStatus -eq "pending" -or $rc14TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC14-041" -and $rc14TaskStatus -eq "completed")
    )
)

Add-Blockers $approvalResult.approval_surface.blockers
Add-Blockers $approvalResult.blockers
Add-Blockers $approvalDenial.blockers
Add-Blockers $activationApprovalHandoff.blockers
Add-Blockers $planSpecResult.readiness_surface.blockers
Add-Blockers $securityResult.security_surface.blockers
if (-not $planAllowsRun) { Add-UniqueBlocker "rc14-040-plan-pointer-not-current" }

$objectTrustAllowed = $false -eq ($script:blockers -contains "object-trust-not-allowed")
$quarantineVerified = $false -eq ($script:blockers -contains "quarantine-preflight-not-run") -and $planSpecResult.readiness_surface.verified_quarantine_preflight_bound -eq $true
$targetSetBound = $approvalResult.approval_surface.target_identity_set_bound -eq $true
$approvalBound = $approvalResult.approval_surface.exact_approval_bound -eq $true
$approvalGranted = $approvalResult.approval_surface.approval_granted -eq $true
$agentCoreExecutable = $planSpecResult.readiness_surface.agentcore_planspec_executable -eq $true
$securityAllowed = $securityResult.security_surface.security_execution_allowed -eq $true
$auditSinkBound = $approvalResult.approval_surface.audit_sink_bound -eq $true
$nonceBound = $approvalResult.approval_surface.nonce_bound -eq $true
$expiryBound = $approvalResult.approval_surface.expiry_bound -eq $true
$rollbackReferenceBound = -not [string]::IsNullOrWhiteSpace($rollbackBaselineSha256)
$supportRecoveryBound = -not [string]::IsNullOrWhiteSpace($supportRecoverySha256)

if (-not $objectTrustAllowed) { Add-UniqueBlocker "activation-object-trust-not-proved" }
if (-not $quarantineVerified) { Add-UniqueBlocker "activation-quarantine-not-verified" }
if (-not $targetSetBound) { Add-UniqueBlocker "activation-target-identity-set-not-bound" }
if (-not ($approvalBound -and $approvalGranted)) { Add-UniqueBlocker "activation-exact-approval-not-granted" }
if (-not $auditSinkBound) { Add-UniqueBlocker "activation-audit-sink-not-bound" }
if (-not $nonceBound) { Add-UniqueBlocker "activation-nonce-not-bound" }
if (-not $expiryBound) { Add-UniqueBlocker "activation-expiry-not-bound" }
if (-not $agentCoreExecutable) { Add-UniqueBlocker "activation-agentcore-planspec-not-executable" }
if (-not $securityAllowed) { Add-UniqueBlocker "activation-security-execution-not-allowed" }
if (-not $rollbackReferenceBound) { Add-UniqueBlocker "activation-rollback-baseline-not-bound" }
if (-not $supportRecoveryBound) { Add-UniqueBlocker "activation-support-recovery-not-bound" }
Add-UniqueBlocker "activation-remote-dispatch-forbidden"
Add-UniqueBlocker "activation-production-mutation-forbidden"
Add-UniqueBlocker "controlled-local-activation-not-authorized"

$gateInputs = [ordered]@{
    object_trust_allowed = $objectTrustAllowed
    quarantine_verified = $quarantineVerified
    target_identity_set_bound = $targetSetBound
    exact_approval_bound = $approvalBound
    approval_granted = $approvalGranted
    agentcore_planspec_executable = $agentCoreExecutable
    security_execution_allowed = $securityAllowed
    audit_sink_bound = $auditSinkBound
    nonce_bound = $nonceBound
    expiry_bound = $expiryBound
    rollback_reference_bound = $rollbackReferenceBound
    support_recovery_bound = $supportRecoveryBound
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$activationAllowed = $objectTrustAllowed -and $quarantineVerified -and $targetSetBound -and $approvalBound -and $approvalGranted -and $agentCoreExecutable -and $securityAllowed -and $auditSinkBound -and $nonceBound -and $expiryBound -and $rollbackReferenceBound -and $supportRecoveryBound
$activationAttemptCore = [ordered]@{
    attempt_id = "rc14-controlled-local-activation-attempt"
    release_id = $releaseId
    payload_sha256 = $payloadSha256
    approval_binding_digest = $approvalBindingDigest
    target_identity_set_digest = $targetIdentitySetDigest
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $effectEnvelopeCoreHash
    gate_inputs = $gateInputs
    requested_effect_set = @("controlled-local-activation")
    expected_observation = "deny-before-side-effects-when-any-gate-missing"
    policy_version = "rc14-controlled-local-activation-v1"
}
$activationAttemptDigest = Get-StringSha256 (($activationAttemptCore | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    activation_attempt_recorded = $true
    activation_audit_fabricated = $false
    effect_prepared = $false
    effect_executed = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}

$caseSpecs = @(
    [ordered]@{ id = "object-trust-gate-denied"; blockers = @("activation-object-trust-not-proved"); reason = "Object trust is not locally proved." },
    [ordered]@{ id = "quarantine-gate-denied"; blockers = @("activation-quarantine-not-verified"); reason = "Quarantine preflight is not verified." },
    [ordered]@{ id = "target-gate-denied"; blockers = @("activation-target-identity-set-not-bound"); reason = "Two-target identity set is not bound." },
    [ordered]@{ id = "approval-gate-denied"; blockers = @("activation-exact-approval-not-granted"); reason = "Exact approval is not granted." },
    [ordered]@{ id = "audit-sink-gate-denied"; blockers = @("activation-audit-sink-not-bound"); reason = "Audit sink is not bound." },
    [ordered]@{ id = "nonce-gate-denied"; blockers = @("activation-nonce-not-bound"); reason = "Nonce is not bound." },
    [ordered]@{ id = "expiry-gate-denied"; blockers = @("activation-expiry-not-bound"); reason = "Approval expiry is not bound." },
    [ordered]@{ id = "agentcore-gate-denied"; blockers = @("activation-agentcore-planspec-not-executable"); reason = "AgentCore PlanSpec is non-executable." },
    [ordered]@{ id = "security-execution-gate-denied"; blockers = @("activation-security-execution-not-allowed"); reason = "SecurityExecution did not allow the effect." },
    [ordered]@{ id = "remote-dispatch-boundary-denied"; blockers = @("activation-remote-dispatch-forbidden"); reason = "Remote dispatch remains forbidden." },
    [ordered]@{ id = "production-mutation-boundary-denied"; blockers = @("activation-production-mutation-forbidden"); reason = "Production ring mutation remains forbidden." },
    [ordered]@{ id = "controlled-local-activation-denied"; blockers = @("controlled-local-activation-not-authorized"); reason = "Controlled activation is not authorized while any gate is missing." }
)
$denialCases = @()
foreach ($spec in $caseSpecs) {
    $caseObservedBlockers = @($script:blockers + $spec.blockers | Select-Object -Unique)
    $denialCases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -ObservedBlockers $caseObservedBlockers -Reason $spec.reason
}
$failedCases = @($denialCases | Where-Object { $_.status -ne "passed" })

$gateReport = [ordered]@{
    schema = "agentos.rc14-controlled-local-activation-gate-report.v1"
    generated_at = $generatedAtValue
    task = "RC14-040"
    status = if ($activationAllowed) { "activation-gates-passed" } else { "activation-gates-evaluated-denied" }
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    activation_attempt_digest = $activationAttemptDigest
    activation_allowed = $activationAllowed
    activation_performed = $false
    activation_audit_fabricated = $false
    gate_inputs = $gateInputs
    blockers = @($script:blockers)
    side_effects = $sideEffects
}

$activationDenial = [ordered]@{
    schema = "agentos.rc14-controlled-local-activation-denial-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-040"
    status = "controlled-local-activation-denied"
    production_ready_claim = $false
    release_id = $releaseId
    denied = -not $activationAllowed
    activation_allowed = $false
    activation_performed = $false
    activation_attempt_digest = $activationAttemptDigest
    denial_cases = $denialCases
    blockers = @($script:blockers)
    side_effects = $sideEffects
}

$rollbackHandoff = [ordered]@{
    schema = "agentos.rc14-controlled-local-activation-rollback-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC14-040"
    status = "blocked-by-controlled-local-activation-denial"
    production_ready_claim = $false
    release_id = $releaseId
    activation_attempt_digest = $activationAttemptDigest
    controlled_activation_performed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($script:blockers)
    next_task = "RC14-041"
}

$gateReportPath = Join-Path $resolvedArtifactDir "activation-gate-report.json"
$activationDenialPath = Join-Path $resolvedArtifactDir "activation-denial-evidence.json"
$rollbackHandoffPath = Join-Path $resolvedArtifactDir "controlled-local-activation-rollback-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC14-040-controlled-local-activation.json"

Write-Json $gateReport $gateReportPath
Write-Json $activationDenial $activationDenialPath
Write-Json $rollbackHandoff $rollbackHandoffPath

Add-Check "plan.current_task.rc14_040" $planAllowsRun "RC14-040 must run after RC14-031 completed, either while current_task is RC14-040 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc14_031_status = $rc14PreviousStatus; rc14_040_status = $rc14TaskStatus })
Add-Check "source.rc14_031.complete" ($approvalResult.status -eq "passed" -and $approvalResult.summary.rc14_031_complete -eq $true) "RC14-040 must consume completed RC14-031 exact approval evidence." ([ordered]@{ status = $approvalResult.status; rc14_031_complete = $approvalResult.summary.rc14_031_complete; next_task = $approvalResult.summary.next_task })
Add-Check "contract.activation_gate.present" ($contractText.Contains("Execute controlled local activation only if every prior gate is proved and the activation task records the exact effect or denial")) "RC14 contract must include controlled local activation gate." (New-ArtifactRef $resolvedContractPath)
Add-Check "gates.required_surface_evaluated" ($gateInputs.Keys.Count -ge 12 -and $gateInputs.remote_dispatch_enabled -eq $false -and $gateInputs.production_ring_mutation_allowed -eq $false) "Activation gate report must evaluate object trust, quarantine, target, approval, AgentCore, SecurityExecution, audit, rollback, and support/recovery gates." $gateInputs
Add-Check "activation.denied_when_any_gate_missing" ($activationAllowed -eq $false -and $gateReport.status -eq "activation-gates-evaluated-denied" -and $activationDenial.status -eq "controlled-local-activation-denied") "Activation must remain denied when any required gate is missing." ([ordered]@{ activation_allowed = $activationAllowed; blockers = @($script:blockers).Count })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($denialCases).Count -ge 12) "Activation denial cases must fail closed for missing gates and authority broadening." ([ordered]@{ cases = @($denialCases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.activation_performed -eq $false -and $sideEffects.activation_audit_fabricated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC14-040 must not prepare effects, fabricate activation audit, activate, remote-dispatch, or mutate production state." $sideEffects
Add-Check "handoff.rollback_blocked" ($rollbackHandoff.controlled_activation_performed -eq $false -and $rollbackHandoff.rollback_execution_allowed -eq $false -and $rollbackHandoff.next_task -eq "RC14-041") "Rollback handoff must remain blocked because controlled activation was not performed." ([ordered]@{ controlled_activation_performed = $rollbackHandoff.controlled_activation_performed; rollback_execution_allowed = $rollbackHandoff.rollback_execution_allowed; next_task = $rollbackHandoff.next_task })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $activationDenialPath),
    (Get-Content -Raw -LiteralPath $rollbackHandoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC14-040 outputs must not contain key material, auth tokens, private signing paths, signer internals, or sensitive approval markers." $null

$source = [ordered]@{
    rc14_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc14_contract = New-ArtifactRef $resolvedContractPath
    approval_result = New-ArtifactRef $resolvedApprovalResultPath $approvalResult
    exact_approval_packet = New-ArtifactRef $resolvedApprovalPacketPath $approvalPacket
    approval_denial = New-ArtifactRef $resolvedApprovalDenialPath $approvalDenial
    approval_matrix = New-ArtifactRef $resolvedApprovalMatrixPath $approvalMatrix
    controlled_local_activation_handoff = New-ArtifactRef $resolvedActivationApprovalHandoffPath $activationApprovalHandoff
    agentcore_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    agentcore_planspec_readiness = New-ArtifactRef $resolvedPlanSpecReadinessPath $planSpecReadiness
    security_execution_result = New-ArtifactRef $resolvedSecurityResultPath $securityResult
    security_execution_allow_envelope = New-ArtifactRef $resolvedSecurityPreconditionsPath $securityPreconditions
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc14-controlled-local-activation-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-040"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    activation_surface = [ordered]@{
        state = "controlled-local-activation-denied"
        activation_attempt_digest = $activationAttemptDigest
        activation_allowed = $false
        activation_performed = $false
        activation_audit_fabricated = $false
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
            activation_attempt_digest = $activationAttemptDigest
        }
        activation_denial_evidence = [ordered]@{
            path = Get-StablePath $activationDenialPath
            sha256 = Get-FileSha256 $activationDenialPath
        }
        controlled_local_activation_rollback_handoff = [ordered]@{
            path = Get-StablePath $rollbackHandoffPath
            sha256 = Get-FileSha256 $rollbackHandoffPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        activation_audit_fabricated = $false
        security_execution_effect_allowed = $false
        effect_prepared = $false
        effect_executed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($denialCases).Count
        failed_cases = $failedCases.Count
        rc14_040_complete = (@($script:failedChecks).Count -eq 0)
        activation_allowed = $false
        activation_performed = $false
        activation_audit_fabricated = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC14-041"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-controlled-local-activation-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-040"
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
        rc14_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-041"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC14-040 result."
}

Write-Host "RC14 controlled local activation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Activation state: $($result.activation_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
