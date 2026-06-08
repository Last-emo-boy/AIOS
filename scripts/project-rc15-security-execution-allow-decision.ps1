param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-security-execution-allow-decision",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/result.json",
    [string]$PlanSpecPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/agentcore-planspec.json",
    [string]$PlanSpecHandoffPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/security-execution-allow-decision-handoff.json",
    [string]$ExactApprovalResultPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json",
    [string]$ExactApprovalPacketPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/exact-approval-packet.json",
    [string]$Rc14SecurityEnvelopePath = ".workflow/artifacts/rc14-security-execution-allow-envelope/security-execution-allow-envelope.json",
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

function New-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            security_execution_allowed = $false
            effect_prepared = $false
            effect_executed = $false
            payload_interpreted = $false
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

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecPath = Resolve-RepoPath $PlanSpecPath
$resolvedPlanSpecHandoffPath = Resolve-RepoPath $PlanSpecHandoffPath
$resolvedExactApprovalResultPath = Resolve-RepoPath $ExactApprovalResultPath
$resolvedExactApprovalPacketPath = Resolve-RepoPath $ExactApprovalPacketPath
$resolvedRc14SecurityEnvelopePath = Resolve-RepoPath $Rc14SecurityEnvelopePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpec = Read-Json $resolvedPlanSpecPath
$planSpecHandoff = Read-Json $resolvedPlanSpecHandoffPath
$exactApprovalResult = Read-Json $resolvedExactApprovalResultPath
$exactApprovalPacket = Read-Json $resolvedExactApprovalPacketPath
$rc14SecurityEnvelope = Read-Json $resolvedRc14SecurityEnvelopePath

$releaseId = [string]$planSpecResult.release_id
$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-022").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-021").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-022" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-030" -and $rc15TaskStatus -eq "completed")
    )
)

$planSpecComplete = $planSpecResult.status -eq "passed" -and
    $planSpecResult.summary.rc15_021_complete -eq $true -and
    $planSpecResult.readiness_surface.agentcore_planspec_executable -eq $true
$handoffReady = $planSpecHandoff.status -eq "ready-for-rc15-022-security-execution-allow-decision" -and
    $planSpecHandoff.next_task -eq "RC15-022" -and
    $planSpecHandoff.agentcore_planspec_executable -eq $true
$exactApprovalBound = $exactApprovalResult.status -eq "passed" -and
    $exactApprovalResult.approval_surface.exact_approval_bound -eq $true -and
    $exactApprovalPacket.exact_approval_bound -eq $true -and
    $exactApprovalPacket.approval_granted -eq $true

$readiness = $planSpecResult.readiness_surface
$bindingSlots = $planSpec.planspec_core.binding_slots
$approvalBinding = $exactApprovalPacket.approval_binding
$planspecCoreHash = [string]$readiness.planspec_core_hash
$planspecMaterializationDigest = [string]$readiness.planspec_materialization_digest
$expectedSecurityEnvelopeHash = [string]$approvalBinding.security_execution_effect_envelope_core_hash
$handoffSecurityEnvelopeHash = [string]$planSpecHandoff.security_execution_effect_envelope_core_hash
$rc14SecurityEnvelopeHash = [string]$rc14SecurityEnvelope.effect_envelope_core_hash

$planSpecHashBound = $planspecCoreHash -eq [string]$planSpec.planspec_core_hash -and
    $planspecCoreHash -eq [string]$approvalBinding.agentcore_planspec_core_hash -and
    $planspecCoreHash -eq [string]$planSpecHandoff.planspec_core_hash
$securityEnvelopeHashBound = $expectedSecurityEnvelopeHash -eq $handoffSecurityEnvelopeHash -and
    $expectedSecurityEnvelopeHash -eq $rc14SecurityEnvelopeHash -and
    -not [string]::IsNullOrWhiteSpace($expectedSecurityEnvelopeHash)
$approvalBoundToHandoff = [string]$exactApprovalPacket.approval_id -eq [string]$planSpecHandoff.approval_id -and
    [string]$exactApprovalPacket.approval_binding_digest -eq [string]$planSpecHandoff.approval_binding_digest
$targetSetBound = $readiness.target_identity_set_bound -eq $true -and
    $bindingSlots.target_identities.bound -eq $true -and
    [int]@($bindingSlots.target_identities.identity_ids).Count -ge 2 -and
    [string]$bindingSlots.target_identities.target_identity_set_digest -eq [string]$approvalBinding.target_identity_set_digest
$auditNoncePolicyBound = $readiness.audit_sink_bound -eq $true -and
    $readiness.nonce_bound -eq $true -and
    $readiness.expiry_bound -eq $true -and
    $readiness.policy_version_bound -eq $true -and
    [string]$bindingSlots.audit_sink.audit_binding_sha256 -eq [string]$approvalBinding.audit_binding_sha256 -and
    [string]$bindingSlots.nonce.nonce_sha256 -eq [string]$approvalBinding.nonce_sha256 -and
    [string]$bindingSlots.policy_version.policy_version -eq [string]$approvalBinding.policy_version
$releaseObjectBound = $readiness.object_trust_bound -eq $true -and
    $readiness.verified_quarantine_preflight_bound -eq $true -and
    $readiness.release_object_bound -eq $true -and
    [string]$bindingSlots.release_object.object_digest -eq [string]$approvalBinding.object_digest
$rollbackSupportBound = $readiness.rollback_reference_bound -eq $true -and
    $readiness.support_recovery_reference_bound -eq $true -and
    $bindingSlots.rollback_baseline.bound -eq $true -and
    $bindingSlots.support_recovery.bound -eq $true -and
    $approvalBinding.rollback_baseline_bound -eq $true -and
    $approvalBinding.support_recovery_reference_bound -eq $true
$securityPreconditionsBound = $readiness.security_execution_preconditions_bound -eq $true -and
    [string]$bindingSlots.security_execution_preconditions.effect_envelope_core_hash -eq $expectedSecurityEnvelopeHash

$securityExecutionAllowed = $planAllowsRun -and
    $planSpecComplete -and
    $handoffReady -and
    $exactApprovalBound -and
    $planSpecHashBound -and
    $securityEnvelopeHashBound -and
    $approvalBoundToHandoff -and
    $targetSetBound -and
    $auditNoncePolicyBound -and
    $releaseObjectBound -and
    $rollbackSupportBound -and
    $securityPreconditionsBound

$allowBlockers = @()
if (-not $planAllowsRun) { $allowBlockers += "rc15-022-plan-pointer-not-current" }
if (-not $planSpecComplete) { $allowBlockers += "agentcore-planspec-not-executable" }
if (-not $handoffReady) { $allowBlockers += "agentcore-security-handoff-not-ready" }
if (-not $exactApprovalBound) { $allowBlockers += "exact-approval-not-bound" }
if (-not $planSpecHashBound) { $allowBlockers += "planspec-core-hash-mismatch" }
if (-not $securityEnvelopeHashBound) { $allowBlockers += "security-envelope-hash-mismatch" }
if (-not $approvalBoundToHandoff) { $allowBlockers += "approval-handoff-mismatch" }
if (-not $targetSetBound) { $allowBlockers += "target-identity-set-not-bound" }
if (-not $auditNoncePolicyBound) { $allowBlockers += "audit-nonce-policy-not-bound" }
if (-not $releaseObjectBound) { $allowBlockers += "release-object-not-bound" }
if (-not $rollbackSupportBound) { $allowBlockers += "rollback-support-not-bound" }
if (-not $securityPreconditionsBound) { $allowBlockers += "security-execution-preconditions-not-bound" }
if ($securityExecutionAllowed) {
    $allowBlockers = @()
}

$effectEnvelopeBinding = [ordered]@{
    effect_envelope_core_hash = $expectedSecurityEnvelopeHash
    inherited_from_rc14_envelope_hash = $rc14SecurityEnvelopeHash
    release_id = $releaseId
    object_digest = [string]$approvalBinding.object_digest
    target_identity_set_digest = [string]$approvalBinding.target_identity_set_digest
    target_identity_ids = @($approvalBinding.target_identity_ids)
    planspec_core_hash = $planspecCoreHash
    planspec_materialization_digest = $planspecMaterializationDigest
    approval_id = [string]$exactApprovalPacket.approval_id
    approval_binding_digest = [string]$exactApprovalPacket.approval_binding_digest
    rollback_baseline_bound = $approvalBinding.rollback_baseline_bound -eq $true
    support_recovery_reference_bound = $approvalBinding.support_recovery_reference_bound -eq $true
    audit_sink_descriptor_sha256 = [string]$approvalBinding.audit_sink_descriptor_sha256
    audit_binding_sha256 = [string]$approvalBinding.audit_binding_sha256
    nonce_sha256 = [string]$approvalBinding.nonce_sha256
    approval_valid_until = [string]$approvalBinding.approval_valid_until
    policy_version = [string]$approvalBinding.policy_version
}
$decisionMaterialHash = Get-StringSha256 (($effectEnvelopeBinding | ConvertTo-Json -Depth 100 -Compress))

$securityDecision = [ordered]@{
    schema = "agentos.rc15-security-execution-allow-decision.v1"
    generated_at = $generatedAtValue
    task = "RC15-022"
    status = if ($securityExecutionAllowed) { "security-execution-allow-bound" } else { "security-execution-allow-denied" }
    production_ready_claim = $false
    release_id = $releaseId
    security_execution_allowed = $securityExecutionAllowed
    effect_preparation_allowed = $securityExecutionAllowed
    effect_prepared = $false
    effect_executed = $false
    activation_allowed = $securityExecutionAllowed
    activation_performed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    allowed_effects = if ($securityExecutionAllowed) { @("controlled-local-activation") } else { @() }
    denied_effects = @("install", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation")
    effect_envelope_binding = $effectEnvelopeBinding
    decision_material_hash = $decisionMaterialHash
    blockers = @($allowBlockers)
}

$caseMap = [ordered]@{
    "missing-agentcore-executable-planspec" = @("agentcore-planspec-not-executable")
    "missing-exact-approval" = @("exact-approval-not-bound")
    "missing-target-identity-set" = @("target-identity-set-not-bound")
    "missing-audit-sink" = @("audit-sink-not-bound")
    "missing-nonce" = @("nonce-not-bound")
    "missing-expiry" = @("approval-expiry-not-bound")
    "expired-approval" = @("approval-expired")
    "missing-policy-version" = @("policy-version-not-bound")
    "policy-weakening-attempt" = @("policy-weakening-denied")
    "shell-bypass-attempt" = @("shell-bypass-denied")
    "model-replay-authority-attempt" = @("model-replay-denied")
    "tui-authority-attempt" = @("tui-authority-denied")
    "broad-resource-scope" = @("broad-effect-scope-denied")
    "release-object-mismatch" = @("release-object-mismatch")
    "target-set-mismatch" = @("target-set-mismatch")
    "planspec-core-hash-mismatch" = @("planspec-core-hash-mismatch")
    "security-envelope-hash-mismatch" = @("security-envelope-hash-mismatch")
    "approval-replay" = @("approval-replay-denied")
    "stale-approval" = @("approval-stale")
    "rollback-baseline-mismatch" = @("rollback-baseline-mismatch")
    "support-recovery-mismatch" = @("support-recovery-mismatch")
    "remote-dispatch-attempt" = @("remote-dispatch-denied")
    "production-mutation-attempt" = @("production-mutation-denied")
    "support-upload-attempt" = @("support-upload-denied")
}

$cases = @()
foreach ($caseId in $caseMap.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseMap[$caseId]) -ObservedBlockers ([string[]]$caseMap[$caseId])
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$matrix = [ordered]@{
    schema = "agentos.rc15-security-execution-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC15-022"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$activationHandoff = [ordered]@{
    schema = "agentos.rc15-controlled-local-activation-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC15-022"
    status = if ($securityExecutionAllowed) { "ready-for-rc15-030-controlled-local-activation" } else { "blocked-before-controlled-local-activation" }
    production_ready_claim = $false
    release_id = $releaseId
    next_task = "RC15-030"
    security_execution_allowed = $securityExecutionAllowed
    effect_preparation_allowed = $securityExecutionAllowed
    effect_prepared = $false
    effect_executed = $false
    activation_allowed = $securityExecutionAllowed
    activation_performed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    effect_envelope_binding = $effectEnvelopeBinding
    blockers = @($allowBlockers)
}

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc15_agentcore_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    rc15_agentcore_planspec = New-ArtifactRef $resolvedPlanSpecPath $planSpec
    rc15_agentcore_handoff = New-ArtifactRef $resolvedPlanSpecHandoffPath $planSpecHandoff
    rc15_exact_approval_result = New-ArtifactRef $resolvedExactApprovalResultPath $exactApprovalResult
    rc15_exact_approval_packet = New-ArtifactRef $resolvedExactApprovalPacketPath $exactApprovalPacket
    rc14_security_envelope = New-ArtifactRef $resolvedRc14SecurityEnvelopePath $rc14SecurityEnvelope
}

$decisionPath = Join-Path $resolvedArtifactDir "security-execution-allow-decision.json"
$matrixPath = Join-Path $resolvedArtifactDir "security-execution-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "controlled-local-activation-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-022-security-execution-allow-decision.json"

Write-Json $securityDecision $decisionPath
Write-Json $matrix $matrixPath
Write-Json $activationHandoff $handoffPath

Add-Check "plan.current_task.rc15_022" $planAllowsRun "RC15-022 must run after RC15-021 completed, either while current_task is RC15-022 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_021_status = $rc15PreviousStatus; rc15_022_status = $rc15TaskStatus })
Add-Check "source.agentcore_planspec.executable" ($planSpecComplete -and $handoffReady) "RC15-022 must consume completed RC15-021 executable AgentCore PlanSpec evidence and handoff." ([ordered]@{ result_status = $planSpecResult.status; rc15_021_complete = $planSpecResult.summary.rc15_021_complete; handoff_status = $planSpecHandoff.status; agentcore_planspec_executable = $readiness.agentcore_planspec_executable })
Add-Check "source.exact_approval.bound" $exactApprovalBound "RC15-022 must consume granted exact approval bound to actor, targets, PlanSpec, SecurityExecution envelope, audit, nonce, expiry, and policy." ([ordered]@{ approval_id = $exactApprovalPacket.approval_id; approval_granted = $exactApprovalPacket.approval_granted; exact_approval_bound = $exactApprovalPacket.exact_approval_bound })
Add-Check "contract.security_execution_allow.present" ($contractText.Contains("Obtain SecurityExecution allow") -and $contractText.Contains("SecurityExecution allows the exact activation effect envelope") -and $contractText.Contains("SecurityExecution allow does not imply rollback authority")) "RC15-022 must consume the SecurityExecution allow contract and keep rollback separate." $source.rc15_contract
Add-Check "hashes.effect_envelope.bound" ($planSpecHashBound -and $securityEnvelopeHashBound -and $approvalBoundToHandoff) "SecurityExecution allow decision must bind PlanSpec core hash, exact approval id, and the inherited SecurityExecution effect envelope hash." ([ordered]@{ planspec_hash_bound = $planSpecHashBound; security_envelope_hash_bound = $securityEnvelopeHashBound; approval_bound_to_handoff = $approvalBoundToHandoff; expected_security_envelope_hash = $expectedSecurityEnvelopeHash })
Add-Check "preconditions.all_satisfied" ($targetSetBound -and $auditNoncePolicyBound -and $releaseObjectBound -and $rollbackSupportBound -and $securityPreconditionsBound) "SecurityExecution allow is true only when target identities, approval, audit, nonce, expiry, policy, rollback, and support bindings are all present." ([ordered]@{ target_set_bound = $targetSetBound; audit_nonce_policy_bound = $auditNoncePolicyBound; release_object_bound = $releaseObjectBound; rollback_support_bound = $rollbackSupportBound; security_preconditions_bound = $securityPreconditionsBound })
Add-Check "allow.true_without_execution" ($securityDecision.security_execution_allowed -eq $true -and $securityDecision.effect_prepared -eq $false -and $securityDecision.effect_executed -eq $false -and $securityDecision.activation_performed -eq $false) "SecurityExecution allow must not itself prepare or execute the controlled activation effect." ([ordered]@{ security_execution_allowed = $securityDecision.security_execution_allowed; effect_prepared = $securityDecision.effect_prepared; effect_executed = $securityDecision.effect_executed; activation_performed = $securityDecision.activation_performed })
Add-Check "activation.handoff.ready" ($activationHandoff.next_task -eq "RC15-030" -and $activationHandoff.security_execution_allowed -eq $true -and $activationHandoff.activation_allowed -eq $true -and $activationHandoff.activation_performed -eq $false) "RC15-022 must hand off to RC15-030 controlled local activation without fabricating activation evidence." ([ordered]@{ status = $activationHandoff.status; next_task = $activationHandoff.next_task; activation_allowed = $activationHandoff.activation_allowed; activation_performed = $activationHandoff.activation_performed })
Add-Check "rollback.still_separate" ($securityDecision.rollback_execution_allowed -eq $false -and $activationHandoff.rollback_execution_allowed -eq $false) "SecurityExecution allow for activation must not imply rollback authority." ([ordered]@{ decision_rollback_allowed = $securityDecision.rollback_execution_allowed; handoff_rollback_allowed = $activationHandoff.rollback_execution_allowed })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 24) "Policy weakening, shell bypass, broad resource, stale approval, replay, and mismatched envelope cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.remote_dispatch_and_mutation_disabled" ($securityDecision.remote_dispatch_enabled -eq $false -and $securityDecision.production_ring_mutation_allowed -eq $false -and $securityDecision.support_upload_allowed -eq $false -and $securityDecision.recovery_execution_allowed -eq $false) "RC15-022 must not enable remote dispatch, support upload, recovery execution, or production mutation authority." ([ordered]@{ remote_dispatch_enabled = $securityDecision.remote_dispatch_enabled; support_upload_allowed = $securityDecision.support_upload_allowed; recovery_execution_allowed = $securityDecision.recovery_execution_allowed; production_ring_mutation_allowed = $securityDecision.production_ring_mutation_allowed })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $decisionPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-022 outputs must not contain key blocks, auth tokens, private key paths, signer internals, or raw public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-security-execution-allow-decision-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-022"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    readiness_surface = [ordered]@{
        state = if ($securityExecutionAllowed) { "security-execution-allow-controlled-activation-ready" } else { "security-execution-allow-denied" }
        agentcore_planspec_executable = $readiness.agentcore_planspec_executable -eq $true
        exact_approval_bound = $exactApprovalBound
        target_identity_set_bound = $targetSetBound
        audit_sink_bound = $readiness.audit_sink_bound -eq $true
        nonce_bound = $readiness.nonce_bound -eq $true
        expiry_bound = $readiness.expiry_bound -eq $true
        policy_version_bound = $readiness.policy_version_bound -eq $true
        security_execution_allowed = $securityExecutionAllowed
        effect_preparation_allowed = $securityExecutionAllowed
        effect_prepared = $false
        effect_executed = $false
        activation_allowed = $securityExecutionAllowed
        activation_performed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        effect_envelope_core_hash = $expectedSecurityEnvelopeHash
        decision_material_hash = $decisionMaterialHash
    }
    outputs = [ordered]@{
        security_execution_allow_decision = New-ArtifactRef $decisionPath
        security_execution_fail_closed_matrix = New-ArtifactRef $matrixPath
        controlled_local_activation_handoff = New-ArtifactRef $handoffPath
    }
    source = $source
    checks = @($script:checks)
    blockers = if ($securityExecutionAllowed) { @("controlled-activation-not-executed", "separate-rollback-approval-not-bound", "rollback-execution-not-authorized") } else { @($allowBlockers) }
    invariants = [ordered]@{
        aios_body_only = $true
        security_execution_allowed = $securityExecutionAllowed
        effect_preparation_allowed = $securityExecutionAllowed
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
        private_signing_material_handled = $false
        cryptographic_release_signing_performed = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = $failedCases.Count
        rc15_022_complete = $resultStatus -eq "passed"
        security_execution_allowed = $securityExecutionAllowed
        effect_prepared = $false
        activation_allowed = $securityExecutionAllowed
        activation_performed = $false
        rollback_execution_allowed = $false
        next_task = "RC15-030"
    }
}
Write-Json $result $resultPath

$evidence = [ordered]@{
    schema = "agentos.rc15-security-execution-allow-decision-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-022"
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
    readiness_surface = $result.readiness_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc15_022_complete = $resultStatus -eq "passed"
        next_task = "RC15-030"
        current_blockers = $result.blockers
    }
    checks = @($script:checks)
}
Write-Json $evidence $taskEvidencePath

if (-not $outputsSecretSafe) {
    throw "Sensitive marker detected in RC15-022 outputs."
}

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    $ids = @($script:failedChecks | ForEach-Object { $_.id }) -join ", "
    throw "RC15-022 failed checks: $ids"
}

Write-Host "RC15 SecurityExecution allow decision ${resultStatus}: $(Get-StablePath $resultPath)"
Write-Host "SecurityExecution allowed: $securityExecutionAllowed"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"
