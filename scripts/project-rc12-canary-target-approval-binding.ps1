param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-canary-target-approval-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ExecutionPackageResultPath = ".workflow/artifacts/rc12-agentcore-security-execution-package/result.json",
    [string]$AgentCorePackagePath = ".workflow/artifacts/rc12-agentcore-security-execution-package/agentcore-planspec-package.json",
    [string]$SecurityEnvelopePath = ".workflow/artifacts/rc12-agentcore-security-execution-package/security-execution-effect-envelope.json",
    [string]$ExecutionDenialPath = ".workflow/artifacts/rc12-agentcore-security-execution-package/execution-package-denial.json",
    [string]$Rc11ApprovalResultPath = ".workflow/artifacts/rc11-two-target-canary-approval/result.json",
    [string]$Rc11TargetSetPath = ".workflow/artifacts/rc11-two-target-canary-approval/canary-target-set.json",
    [string]$Rc11ApprovalPackagePath = ".workflow/artifacts/rc11-two-target-canary-approval/exact-approval-package.json",
    [string]$Rc11ActivationHandoffPath = ".workflow/artifacts/rc11-two-target-canary-approval/controlled-activation-approval-handoff.json",
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
        "approval-audit-sink-not-bound" { "audit-sink-not-bound" }
        "fewer-than-two-eligible-targets" { "fewer-than-two-canary-target-identities" }
        "target-node-ids-missing" { "target-identities-missing" }
        "target-set-not-enrolled" { "two-target-canary-not-enrolled" }
        "approval-nonce-not-bound" { "nonce-not-bound" }
        default { $Blocker }
    }
    if ($script:blockers -notcontains $normalized) {
        $script:blockers += $normalized
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
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            activation_prepared = $false
            activation_performed = $false
            install_performed = $false
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

$resolvedExecutionPackageResultPath = Resolve-RepoPath $ExecutionPackageResultPath
$resolvedAgentCorePackagePath = Resolve-RepoPath $AgentCorePackagePath
$resolvedSecurityEnvelopePath = Resolve-RepoPath $SecurityEnvelopePath
$resolvedExecutionDenialPath = Resolve-RepoPath $ExecutionDenialPath
$resolvedRc11ApprovalResultPath = Resolve-RepoPath $Rc11ApprovalResultPath
$resolvedRc11TargetSetPath = Resolve-RepoPath $Rc11TargetSetPath
$resolvedRc11ApprovalPackagePath = Resolve-RepoPath $Rc11ApprovalPackagePath
$resolvedRc11ActivationHandoffPath = Resolve-RepoPath $Rc11ActivationHandoffPath

$executionPackageResult = Read-Json $resolvedExecutionPackageResultPath
$agentCorePackage = Read-Json $resolvedAgentCorePackagePath
$securityEnvelope = Read-Json $resolvedSecurityEnvelopePath
$executionDenial = Read-Json $resolvedExecutionDenialPath
$rc11ApprovalResult = Read-Json $resolvedRc11ApprovalResultPath
$rc11TargetSet = Read-Json $resolvedRc11TargetSetPath
$rc11ApprovalPackage = Read-Json $resolvedRc11ApprovalPackagePath
$rc11ActivationHandoff = Read-Json $resolvedRc11ActivationHandoffPath

$quarantineReportPath = Resolve-RepoPath ([string]$executionPackageResult.source.quarantine_fetch_report.path)
$quarantineReport = Read-Json $quarantineReportPath

$releaseId = [string]$executionPackageResult.release_id
$payloadSha256 = [string]$agentCorePackage.planspec_core.frozen_inputs.payload_sha256
$agentCorePlanSpecHash = [string]$agentCorePackage.planspec_core_hash
$securityPolicyId = [string]$securityEnvelope.decision_core.policy_id
$securityDecisionHash = [string]$securityEnvelope.decision_core_hash
$securityEnvelopeHash = Get-FileSha256 $resolvedSecurityEnvelopePath
$effectEnvelopeId = [string]$securityEnvelope.decision_core.effect_envelope_id
$rollbackBaselineDigest = [string]$quarantineReport.required_pre_interpretation_verification.rollback_baseline_sha256
$supportRecoveryDigest = [string]$quarantineReport.required_pre_interpretation_verification.support_recovery_sha256
$policyVersion = "rc12-canary-target-approval-binding-v1"
$requiredMinimumTargetIdentities = 2
$observedCandidateNodeCount = [int]$rc11ApprovalResult.approval_surface.observed_candidate_node_count
$enrolledTargetIdentityCount = 0
$targetSetEnrolled = $false

foreach ($blocker in @($executionPackageResult.blockers + $agentCorePackage.denied_because + $securityEnvelope.decision_core.blockers + $rc11ApprovalResult.blockers)) {
    Add-UniqueBlocker ([string]$blocker)
}
foreach ($blocker in @(
    "two-target-canary-not-enrolled",
    "fewer-than-two-canary-target-identities",
    "target-identities-missing",
    "target-identity-a-missing",
    "target-identity-b-missing",
    "duplicate-canary-target-identity",
    "stale-canary-target-identity",
    "incompatible-canary-target-identity",
    "broad-target-selector",
    "exact-approval-not-bound",
    "approval-id-not-bound",
    "approval-actor-not-bound",
    "audit-sink-not-bound",
    "nonce-not-bound",
    "approval-expiry-not-bound",
    "approval-stale",
    "approval-replay-detected",
    "broad-approval",
    "approval-release-mismatch",
    "approval-object-digest-mismatch",
    "approval-target-set-mismatch",
    "approval-agentcore-planspec-mismatch",
    "approval-security-envelope-mismatch",
    "approval-rollback-baseline-mismatch",
    "approval-support-recovery-mismatch",
    "approval-audit-sink-mismatch",
    "security-execution-effect-envelope-denied",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized",
    "remote-fleet-execution-not-enabled"
)) {
    Add-UniqueBlocker $blocker
}

$targetSlots = @(
    [ordered]@{
        slot = "canary-a"
        required = $true
        enrollment_state = "identity-missing"
        target_identity = $null
        duplicate_identity = $false
        stale_identity = $false
        compatible = $null
        release_id = $releaseId
        object_digest = $payloadSha256
        audit_sink = $null
        denial_reasons = @("target-identity-a-missing", "target-identities-missing")
    },
    [ordered]@{
        slot = "canary-b"
        required = $true
        enrollment_state = "identity-missing"
        target_identity = $null
        duplicate_identity = $false
        stale_identity = $false
        compatible = $null
        release_id = $releaseId
        object_digest = $payloadSha256
        audit_sink = $null
        denial_reasons = @("target-identity-b-missing", "target-identities-missing")
    }
)
$targetSetCore = [ordered]@{
    release_id = $releaseId
    object_digest = $payloadSha256
    required_minimum_target_identities = $requiredMinimumTargetIdentities
    enrolled_target_identity_count = $enrolledTargetIdentityCount
    targets = $targetSlots
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_envelope_hash = $securityEnvelopeHash
}
$targetSetDigest = Get-StringSha256 (($targetSetCore | ConvertTo-Json -Depth 100 -Compress))

$targetSet = [ordered]@{
    schema = "agentos.rc12-canary-target-set.v1"
    generated_at = $generatedAt
    task = "RC12-030"
    status = "target-identity-set-denied"
    production_ready_claim = $false
    release_id = $releaseId
    ring = "canary"
    activation_authority_prerequisite = "at-least-two-non-duplicate-fresh-compatible-canary-target-identities"
    required_minimum_target_identities = $requiredMinimumTargetIdentities
    observed_candidate_node_count = $observedCandidateNodeCount
    enrolled_target_identity_count = $enrolledTargetIdentityCount
    target_set_enrolled = $targetSetEnrolled
    target_set_digest = $targetSetDigest
    target_selection_policy = "two-or-more-non-duplicate-fresh-compatible-enrolled-canary-target-identities-required"
    duplicate_identity_check = [ordered]@{
        duplicate_target_identities_detected = $false
        evaluated_enrolled_identity_count = $enrolledTargetIdentityCount
        fail_closed_if_duplicate = $true
    }
    stale_identity_check = [ordered]@{
        stale_target_identities_detected = $false
        evaluated_enrolled_identity_count = $enrolledTargetIdentityCount
        fail_closed_if_stale = $true
    }
    required_bindings = [ordered]@{
        release_id = $releaseId
        object_digest = $payloadSha256
        agentcore_planspec_hash = $agentCorePlanSpecHash
        security_execution_policy_id = $securityPolicyId
        security_execution_decision_hash = $securityDecisionHash
        security_execution_envelope_hash = $securityEnvelopeHash
        rollback_baseline_digest = $rollbackBaselineDigest
        support_recovery_digest = $supportRecoveryDigest
    }
    inherited_rc11 = [ordered]@{
        target_set_state = [string]$rc11ApprovalResult.approval_surface.state
        observed_candidate_node_count = [int]$rc11ApprovalResult.approval_surface.observed_candidate_node_count
        enrolled_target_count = [int]$rc11ApprovalResult.approval_surface.enrolled_target_count
        target_set_enrolled = [bool]$rc11ApprovalResult.approval_surface.target_set_enrolled
    }
    targets = $targetSlots
    denial_reasons = @($script:blockers)
}

$approvalBinding = [ordered]@{
    actor = "operator"
    approval_id = $null
    approving_actor = $null
    release_id = $releaseId
    object_digest = $payloadSha256
    target_identities = @()
    target_set_digest = $targetSetDigest
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_policy_id = $securityPolicyId
    security_execution_decision_hash = $securityDecisionHash
    security_execution_envelope_id = $effectEnvelopeId
    security_execution_envelope_hash = $securityEnvelopeHash
    rollback_baseline_digest = $rollbackBaselineDigest
    support_recovery_digest = $supportRecoveryDigest
    audit_sink = $null
    nonce = $null
    expiry = $null
    policy_version = $policyVersion
}
$requiredApprovalFields = @(
    "actor",
    "release_id",
    "object_digest",
    "target_identities",
    "target_set_digest",
    "agentcore_planspec_hash",
    "security_execution_envelope_hash",
    "rollback_baseline_digest",
    "support_recovery_digest",
    "audit_sink",
    "nonce",
    "expiry",
    "policy_version"
)
$missingApprovalFields = @(
    "approval_id",
    "approving_actor",
    "target_identities",
    "audit_sink",
    "nonce",
    "expiry"
)
$approvalBindingDigest = Get-StringSha256 (($approvalBinding | ConvertTo-Json -Depth 100 -Compress))

$approvalPackage = [ordered]@{
    schema = "agentos.rc12-exact-approval-package.v1"
    generated_at = $generatedAt
    task = "RC12-030"
    status = "exact-approval-denied"
    production_ready_claim = $false
    projection_only = $true
    exact_approval_required = $true
    exact_approval_bound = $false
    approval_granted = $false
    executable = $false
    replay_protection_required = $true
    freshness_required = $true
    required_binding_fields = $requiredApprovalFields
    approval_binding = $approvalBinding
    approval_binding_digest = $approvalBindingDigest
    missing_required_fields = $missingApprovalFields
    upstream_gates = [ordered]@{
        execution_package_complete = $executionPackageResult.summary.rc12_021_complete
        object_trust_allowed = $agentCorePackage.planspec_core.frozen_inputs.object_trust_allowed
        quarantine_fetch_allowed = $agentCorePackage.planspec_core.frozen_inputs.quarantine_fetch_allowed
        installer_preflight_verified = $executionPackageResult.package_surface.installer_preflight_verified
        agentcore_planspec_executable = $executionPackageResult.package_surface.agentcore_planspec_executable
        security_execution_allowed = $executionPackageResult.package_surface.security_execution_allowed
        required_target_identity_count = $requiredMinimumTargetIdentities
        enrolled_target_identity_count = $enrolledTargetIdentityCount
        target_set_enrolled = $targetSetEnrolled
        audit_sink_bound = $securityEnvelope.decision_core.audit_sink_bound
        nonce_bound = $securityEnvelope.decision_core.nonce_bound
        expiry_bound = $securityEnvelope.decision_core.expiry_bound
        policy_version_bound = $securityEnvelope.decision_core.policy_version_bound
    }
    denial_reasons = @($script:blockers)
}

$caseBlockers = [ordered]@{
    "missing-approval-denied" = @("exact-approval-not-bound")
    "missing-approval-id-denied" = @("approval-id-not-bound")
    "missing-approval-actor-denied" = @("approval-actor-not-bound")
    "missing-target-identities-denied" = @("target-identities-missing")
    "fewer-than-two-target-identities-denied" = @("fewer-than-two-canary-target-identities")
    "duplicate-target-identity-denied" = @("duplicate-canary-target-identity")
    "stale-target-identity-denied" = @("stale-canary-target-identity")
    "incompatible-target-identity-denied" = @("incompatible-canary-target-identity")
    "broad-target-selector-denied" = @("broad-target-selector")
    "missing-audit-sink-denied" = @("audit-sink-not-bound")
    "missing-nonce-denied" = @("nonce-not-bound")
    "missing-expiry-denied" = @("approval-expiry-not-bound")
    "stale-approval-denied" = @("approval-stale")
    "replayed-approval-denied" = @("approval-replay-detected")
    "broad-approval-denied" = @("broad-approval")
    "mismatched-release-denied" = @("approval-release-mismatch")
    "mismatched-object-digest-denied" = @("approval-object-digest-mismatch")
    "mismatched-target-set-denied" = @("approval-target-set-mismatch")
    "mismatched-agentcore-planspec-denied" = @("approval-agentcore-planspec-mismatch")
    "mismatched-security-envelope-denied" = @("approval-security-envelope-mismatch")
    "mismatched-rollback-baseline-denied" = @("approval-rollback-baseline-mismatch")
    "mismatched-support-recovery-denied" = @("approval-support-recovery-mismatch")
    "mismatched-audit-sink-denied" = @("approval-audit-sink-mismatch")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$failClosedMatrix = [ordered]@{
    schema = "agentos.rc12-approval-fail-closed-matrix.v1"
    generated_at = $generatedAt
    task = "RC12-030"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    broad_stale_missing_mismatched_replayed_approval_fail_closed = $true
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$activationHandoff = [ordered]@{
    schema = "agentos.rc12-controlled-activation-approval-handoff.v1"
    generated_at = $generatedAt
    task = "RC12-030"
    status = "blocked-by-target-identity-and-exact-approval-denial"
    production_ready_claim = $false
    release_id = $releaseId
    target_set_digest = $targetSetDigest
    approval_binding_digest = $approvalBindingDigest
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_decision_hash = $securityDecisionHash
    security_execution_envelope_hash = $securityEnvelopeHash
    rollback_baseline_digest = $rollbackBaselineDigest
    support_recovery_digest = $supportRecoveryDigest
    target_set_enrolled = $false
    exact_approval_bound = $false
    approval_granted = $false
    audit_sink_bound = $false
    nonce_bound = $false
    expiry_bound = $false
    activation_authority_prerequisites_met = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($script:blockers)
    next_task = "RC12-040"
}

$targetSetPath = Join-Path $resolvedArtifactDir "canary-target-set.json"
$approvalPackagePath = Join-Path $resolvedArtifactDir "exact-approval-package.json"
$matrixPath = Join-Path $resolvedArtifactDir "approval-fail-closed-matrix.json"
$activationHandoffPath = Join-Path $resolvedArtifactDir "controlled-activation-approval-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-030-canary-target-approval-binding.json"

Write-Json $targetSet $targetSetPath
Write-Json $approvalPackage $approvalPackagePath
Write-Json $failClosedMatrix $matrixPath
Write-Json $activationHandoff $activationHandoffPath

Add-Check "source.rc12_021.execution_package_complete" ($executionPackageResult.status -eq "passed" -and $executionPackageResult.summary.rc12_021_complete -eq $true) "RC12-030 must consume completed RC12-021 AgentCore/SecurityExecution package evidence." ([ordered]@{ status = $executionPackageResult.status; package_state = $executionPackageResult.summary.package_state; planspec_hash = $agentCorePlanSpecHash; security_decision_hash = $securityDecisionHash })
Add-Check "source.rc11_approval_denial_carried" ($rc11ApprovalResult.status -eq "passed" -and $rc11ApprovalResult.summary.rc11_030_complete -eq $true -and $rc11ApprovalResult.approval_surface.approval_granted -eq $false) "RC12-030 must carry forward RC11 target and approval denial context without granting authority." ([ordered]@{ rc11_state = $rc11ApprovalResult.approval_surface.state; rc11_target_set_enrolled = $rc11ApprovalResult.approval_surface.target_set_enrolled; rc11_approval_granted = $rc11ApprovalResult.approval_surface.approval_granted })
Add-Check "target_set.two_identities_required_before_activation" ($targetSet.required_minimum_target_identities -eq 2 -and @($targetSet.targets).Count -eq 2 -and $targetSet.target_set_enrolled -eq $false -and $targetSet.enrolled_target_identity_count -lt 2) "At least two canary target identities must be required before activation authority." ([ordered]@{ required = $targetSet.required_minimum_target_identities; slots = @($targetSet.targets).Count; enrolled = $targetSet.enrolled_target_identity_count; activation_authority_prerequisite = $targetSet.activation_authority_prerequisite })
Add-Check "target_set.identity_quality_fail_closed" ($targetSet.duplicate_identity_check.fail_closed_if_duplicate -eq $true -and $targetSet.stale_identity_check.fail_closed_if_stale -eq $true -and $targetSet.target_selection_policy -match "non-duplicate") "Target identity enrollment must record non-duplicate, fresh, compatible identity gates." ([ordered]@{ duplicate_fail_closed = $targetSet.duplicate_identity_check.fail_closed_if_duplicate; stale_fail_closed = $targetSet.stale_identity_check.fail_closed_if_stale; policy = $targetSet.target_selection_policy })
Add-Check "approval.required_binding_contract_recorded" (@($approvalPackage.required_binding_fields).Count -eq 13 -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.actor) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.release_id) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.object_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.target_set_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.agentcore_planspec_hash) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.security_execution_envelope_hash) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.rollback_baseline_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.support_recovery_digest)) "Exact approval must bind actor, release, object digest, target set, AgentCore PlanSpec, SecurityExecution envelope, rollback baseline, support/recovery, audit sink, nonce, and expiry." ([ordered]@{ required_fields = $approvalPackage.required_binding_fields; missing = $approvalPackage.missing_required_fields })
Add-Check "approval.denied_until_audit_nonce_expiry_targets_present" ($approvalPackage.exact_approval_bound -eq $false -and $approvalPackage.approval_granted -eq $false -and $approvalPackage.executable -eq $false -and @($approvalPackage.missing_required_fields | Where-Object { $_ -in @("target_identities", "audit_sink", "nonce", "expiry") }).Count -eq 4) "Exact approval must remain denied until target identities, audit sink, nonce, and expiry are bound." ([ordered]@{ status = $approvalPackage.status; missing = $approvalPackage.missing_required_fields })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Broad, stale, missing, mismatched, or replayed approval cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "handoff.side_effects_none" ($activationHandoff.activation_allowed -eq $false -and $activationHandoff.rollback_execution_allowed -eq $false -and $activationHandoff.support_upload_allowed -eq $false -and $activationHandoff.remote_dispatch_enabled -eq $false -and $activationHandoff.production_ring_mutation_allowed -eq $false) "RC12-030 must not authorize activation, rollback, support upload, recovery, remote dispatch, or production mutation." ([ordered]@{ activation_allowed = $activationHandoff.activation_allowed; rollback_execution_allowed = $activationHandoff.rollback_execution_allowed; remote_dispatch_enabled = $activationHandoff.remote_dispatch_enabled; production_ring_mutation_allowed = $activationHandoff.production_ring_mutation_allowed })
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC12-030 must not grant mirror, signer, nginx, frontend, shell, TUI, model, remote dispatch, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; normal_shell_authority = $false; tui_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetSetPath),
    (Get-Content -Raw -LiteralPath $approvalPackagePath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $activationHandoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC12-030 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$source = [ordered]@{
    rc12_execution_package_result = New-ArtifactRef $resolvedExecutionPackageResultPath $executionPackageResult
    agentcore_planspec_package = New-ArtifactRef $resolvedAgentCorePackagePath $agentCorePackage
    security_execution_effect_envelope = New-ArtifactRef $resolvedSecurityEnvelopePath $securityEnvelope
    execution_package_denial = New-ArtifactRef $resolvedExecutionDenialPath $executionDenial
    quarantine_fetch_report = New-ArtifactRef $quarantineReportPath $quarantineReport
    rc11_two_target_approval_result = New-ArtifactRef $resolvedRc11ApprovalResultPath $rc11ApprovalResult
    rc11_target_set = New-ArtifactRef $resolvedRc11TargetSetPath $rc11TargetSet
    rc11_approval_package = New-ArtifactRef $resolvedRc11ApprovalPackagePath $rc11ApprovalPackage
    rc11_activation_handoff = New-ArtifactRef $resolvedRc11ActivationHandoffPath $rc11ActivationHandoff
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-canary-target-approval-binding-result.v1"
    generated_at = $generatedAt
    task = "RC12-030"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    approval_surface = [ordered]@{
        state = "target-identity-and-exact-approval-denied"
        activation_authority_prerequisite = $targetSet.activation_authority_prerequisite
        required_minimum_target_identities = $requiredMinimumTargetIdentities
        observed_candidate_node_count = $observedCandidateNodeCount
        enrolled_target_identity_count = $enrolledTargetIdentityCount
        target_set_enrolled = $targetSetEnrolled
        target_set_digest = $targetSetDigest
        exact_approval_required = $true
        exact_approval_bound = $false
        approval_granted = $false
        approval_binding_digest = $approvalBindingDigest
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
        agentcore_planspec_hash = $agentCorePlanSpecHash
        agentcore_planspec_executable = $executionPackageResult.package_surface.agentcore_planspec_executable
        security_execution_policy_id = $securityPolicyId
        security_execution_envelope_hash = $securityEnvelopeHash
        security_execution_allowed = $executionPackageResult.package_surface.security_execution_allowed
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        canary_target_set = [ordered]@{
            path = Get-StablePath $targetSetPath
            sha256 = Get-FileSha256 $targetSetPath
            target_set_digest = $targetSetDigest
        }
        exact_approval_package = [ordered]@{
            path = Get-StablePath $approvalPackagePath
            sha256 = Get-FileSha256 $approvalPackagePath
            approval_binding_digest = $approvalBindingDigest
        }
        approval_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
        }
        controlled_activation_approval_handoff = [ordered]@{
            path = Get-StablePath $activationHandoffPath
            sha256 = Get-FileSha256 $activationHandoffPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        target_enrollment_fabricated = $false
        exact_approval_fabricated = $false
        approval_granted = $false
        executable_planspec_created = $false
        security_execution_effect_allowed = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        network_probe_performed = $false
        payload_upload_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
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
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        rc12_030_complete = (@($script:failedChecks).Count -eq 0)
        target_set_enrolled = $false
        exact_approval_bound = $false
        approval_granted = $false
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC12-040"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-canary-target-approval-binding-evidence.v1"
    generated_at = $generatedAt
    task = "RC12-030"
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
    approval_surface = $result.approval_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc12_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-040"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC12-030 result."
}

Write-Host "RC12 canary target approval binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Approval state: $($result.approval_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
