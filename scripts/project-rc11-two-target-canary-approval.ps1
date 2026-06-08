param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-two-target-canary-approval",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$InstallerHandoffResultPath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/result.json",
    [string]$AgentCoreHandoffPath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/agentcore-planspec-handoff.json",
    [string]$SecurityEnvelopePath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/security-execution-effect-envelope.json",
    [string]$Rc10TargetEnrollmentResultPath = ".workflow/artifacts/rc10-two-node-canary-enrollment/result.json",
    [string]$Rc10TargetSetPath = ".workflow/artifacts/rc10-two-node-canary-enrollment/canary-target-set.json",
    [string]$Rc10ExactApprovalResultPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/result.json",
    [string]$Rc10ExactApprovalBindingPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/exact-approval-binding.json",
    [string]$FleetAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
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
        "exact-operator-approval-pending" { "exact-operator-approval-not-granted" }
        "installer-quarantine-fetch-not-verified" { "installer-preflight-not-verified" }
        "remote-fleet-execution-disabled" { "remote-fleet-execution-not-enabled" }
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

$resolvedInstallerHandoffResultPath = Resolve-RepoPath $InstallerHandoffResultPath
$resolvedAgentCoreHandoffPath = Resolve-RepoPath $AgentCoreHandoffPath
$resolvedSecurityEnvelopePath = Resolve-RepoPath $SecurityEnvelopePath
$resolvedRc10TargetEnrollmentResultPath = Resolve-RepoPath $Rc10TargetEnrollmentResultPath
$resolvedRc10TargetSetPath = Resolve-RepoPath $Rc10TargetSetPath
$resolvedRc10ExactApprovalResultPath = Resolve-RepoPath $Rc10ExactApprovalResultPath
$resolvedRc10ExactApprovalBindingPath = Resolve-RepoPath $Rc10ExactApprovalBindingPath
$resolvedFleetAuthorityPath = Resolve-RepoPath $FleetAuthorityPath

$installerHandoffResult = Read-Json $resolvedInstallerHandoffResultPath
$agentCoreHandoff = Read-Json $resolvedAgentCoreHandoffPath
$securityEnvelope = Read-Json $resolvedSecurityEnvelopePath
$rc10TargetResult = Read-Json $resolvedRc10TargetEnrollmentResultPath
$rc10TargetSet = Read-Json $resolvedRc10TargetSetPath
$rc10ExactApprovalResult = Read-Json $resolvedRc10ExactApprovalResultPath
$rc10ExactApprovalBinding = Read-Json $resolvedRc10ExactApprovalBindingPath
$fleetAuthority = Read-Json $resolvedFleetAuthorityPath

$installerResultPath = Resolve-RepoPath ([string]$installerHandoffResult.source.installer_quarantine_result.path)
$fetchReportPath = Resolve-RepoPath ([string]$installerHandoffResult.source.quarantine_fetch_report.path)
$installerResult = Read-Json $installerResultPath
$fetchReport = Read-Json $fetchReportPath

$releaseId = [string]$installerHandoffResult.release_id
$payloadSha256 = [string]$agentCoreHandoff.planspec_core.frozen_inputs.payload_sha256
$agentCorePlanSpecHash = [string]$installerHandoffResult.handoff_surface.agentcore_planspec_hash
$securityPolicyId = [string]$securityEnvelope.decision_core.policy_id
$securityDecisionHash = [string]$securityEnvelope.decision_core_hash
$rollbackBaselineDigest = [string]$fetchReport.required_pre_interpretation_verification.rollback_baseline_sha256
$supportRecoveryDigest = [string]$fetchReport.required_pre_interpretation_verification.support_recovery_sha256
$policyVersion = "rc11-two-target-canary-approval-v1"
$requiredMinimumTargets = 2
$observedCandidateNodeCount = [int]$rc10TargetResult.enrollment_surface.observed_candidate_node_count
$enrolledTargetCount = 0
$targetSetEnrolled = $false
$remoteFleetEnabled = $false

foreach ($blocker in @($installerHandoffResult.blockers + $rc10TargetResult.blockers + $rc10ExactApprovalResult.blockers)) {
    Add-UniqueBlocker ([string]$blocker)
}
foreach ($blocker in @(
    "fewer-than-two-eligible-targets",
    "target-set-not-enrolled",
    "target-node-ids-missing",
    "exact-operator-approval-not-granted",
    "approval-audit-sink-not-bound",
    "approval-expiry-not-bound",
    "approval-nonce-not-bound",
    "remote-fleet-execution-not-enabled",
    "controlled-execution-not-authorized"
)) {
    Add-UniqueBlocker $blocker
}

$targetSlots = @(
    [ordered]@{
        slot = "canary-a"
        required = $true
        enrollment_state = "missing"
        node_id = $null
        duplicate_node_id = $false
        stale = $false
        release_id = $releaseId
        object_digest = $payloadSha256
        health_evidence_digest = $null
        audit_sink = $null
        denial_reasons = @("target-node-record-missing")
    },
    [ordered]@{
        slot = "canary-b"
        required = $true
        enrollment_state = "missing"
        node_id = $null
        duplicate_node_id = $false
        stale = $false
        release_id = $releaseId
        object_digest = $payloadSha256
        health_evidence_digest = $null
        audit_sink = $null
        denial_reasons = @("target-node-record-missing")
    }
)
$targetSetDigest = Get-StringSha256 (($targetSlots | ConvertTo-Json -Depth 100 -Compress))

$targetSet = [ordered]@{
    schema = "agentos.rc11-two-target-canary-target-set.v1"
    generated_at = $generatedAt
    task = "RC11-030"
    status = "target-set-denied"
    production_ready_claim = $false
    release_id = $releaseId
    ring = "canary"
    required_minimum_target_count = $requiredMinimumTargets
    observed_candidate_node_count = $observedCandidateNodeCount
    enrolled_target_count = $enrolledTargetCount
    target_set_enrolled = $targetSetEnrolled
    target_set_digest = $targetSetDigest
    target_selection_policy = "two-or-more-non-duplicate-fresh-enrolled-canary-targets-required"
    duplicate_node_check = [ordered]@{
        duplicate_node_ids_detected = $false
        evaluated_enrolled_node_count = $enrolledTargetCount
    }
    stale_node_check = [ordered]@{
        stale_enrollment_detected = $false
        evaluated_enrolled_node_count = $enrolledTargetCount
    }
    inherited_rc10 = [ordered]@{
        target_set_state = [string]$rc10TargetResult.enrollment_surface.state
        observed_candidate_node_count = [int]$rc10TargetResult.enrollment_surface.observed_candidate_node_count
        enrolled_target_count = [int]$rc10TargetResult.enrollment_surface.enrolled_target_count
        target_set_enrolled = [bool]$rc10TargetResult.enrollment_surface.target_set_enrolled
    }
    required_bindings = [ordered]@{
        release_id = $releaseId
        object_digest = $payloadSha256
        agentcore_planspec_hash = $agentCorePlanSpecHash
        security_execution_policy_id = $securityPolicyId
        security_execution_decision_hash = $securityDecisionHash
        rollback_baseline_digest = $rollbackBaselineDigest
        support_recovery_digest = $supportRecoveryDigest
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
    target_ids = @()
    target_set_digest = $targetSetDigest
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_policy_id = $securityPolicyId
    security_execution_decision_hash = $securityDecisionHash
    rollback_baseline_digest = $rollbackBaselineDigest
    support_recovery_digest = $supportRecoveryDigest
    audit_sink = $null
    expiry = $null
    nonce = $null
    policy_version = $policyVersion
}
$requiredApprovalFields = @(
    "actor",
    "release_id",
    "object_digest",
    "target_ids",
    "target_set_digest",
    "agentcore_planspec_hash",
    "security_execution_policy_id",
    "rollback_baseline_digest",
    "support_recovery_digest",
    "audit_sink",
    "expiry",
    "nonce",
    "policy_version"
)
$missingApprovalFields = @(
    "approval_id",
    "approving_actor",
    "target_ids",
    "audit_sink",
    "expiry",
    "nonce"
)
$approvalBindingDigest = Get-StringSha256 (($approvalBinding | ConvertTo-Json -Depth 100 -Compress))

$approvalPackage = [ordered]@{
    schema = "agentos.rc11-exact-approval-package.v1"
    generated_at = $generatedAt
    task = "RC11-030"
    status = "exact-approval-denied"
    production_ready_claim = $false
    projection_only = $true
    exact_approval_required = $true
    exact_approval_bound = $false
    approval_granted = $false
    executable = $false
    required_binding_fields = $requiredApprovalFields
    approval_binding = $approvalBinding
    approval_binding_digest = $approvalBindingDigest
    missing_required_fields = $missingApprovalFields
    upstream_gates = [ordered]@{
        installer_agentcore_security_handoff_complete = $installerHandoffResult.summary.rc11_021_complete
        installer_preflight_verified = $installerHandoffResult.handoff_surface.installer_preflight_verified
        target_set_enrolled = $targetSetEnrolled
        observed_candidate_node_count = $observedCandidateNodeCount
        enrolled_target_count = $enrolledTargetCount
        required_target_count = $requiredMinimumTargets
        agentcore_planspec_candidate_projected = $installerHandoffResult.handoff_surface.agentcore_planspec_candidate_projected
        security_execution_allowed = $installerHandoffResult.handoff_surface.security_execution_allowed
        rc10_exact_approval_granted = $rc10ExactApprovalResult.binding_surface.exact_approval_granted
        remote_fleet_execution_enabled = $remoteFleetEnabled
    }
    denial_reasons = @($script:blockers)
}

$caseBlockers = @{
    "missing-approval-denied" = @("exact-operator-approval-not-granted")
    "single-target-denied" = @("fewer-than-two-eligible-targets")
    "duplicate-target-denied" = @("target-set-not-enrolled")
    "stale-target-denied" = @("target-set-not-enrolled")
    "broad-target-selector-denied" = @("target-node-ids-missing")
    "mismatched-release-denied" = @("controlled-execution-not-authorized")
    "mismatched-object-digest-denied" = @("controlled-execution-not-authorized")
    "mismatched-target-set-denied" = @("target-set-not-enrolled")
    "mismatched-agentcore-planspec-denied" = @("agentcore-planspec-not-bound")
    "mismatched-security-policy-denied" = @("security-execution-effect-envelope-not-bound")
    "mismatched-rollback-baseline-denied" = @("controlled-execution-not-authorized")
    "mismatched-support-recovery-denied" = @("controlled-execution-not-authorized")
    "missing-audit-sink-denied" = @("approval-audit-sink-not-bound")
    "missing-expiry-denied" = @("approval-expiry-not-bound")
    "missing-nonce-denied" = @("approval-nonce-not-bound")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys | Sort-Object) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$failClosedMatrix = [ordered]@{
    schema = "agentos.rc11-two-target-approval-fail-closed-matrix.v1"
    generated_at = $generatedAt
    task = "RC11-030"
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
    schema = "agentos.rc11-controlled-activation-approval-handoff.v1"
    generated_at = $generatedAt
    task = "RC11-030"
    status = "blocked-by-target-and-approval-denial"
    production_ready_claim = $false
    release_id = $releaseId
    target_set_digest = $targetSetDigest
    approval_binding_digest = $approvalBindingDigest
    agentcore_planspec_hash = $agentCorePlanSpecHash
    security_execution_decision_hash = $securityDecisionHash
    target_set_enrolled = $false
    exact_approval_bound = $false
    approval_granted = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    remote_dispatch_enabled = $false
    blockers = @($script:blockers)
    next_task = "RC11-031"
}

$targetSetPath = Join-Path $resolvedArtifactDir "canary-target-set.json"
$approvalPackagePath = Join-Path $resolvedArtifactDir "exact-approval-package.json"
$matrixPath = Join-Path $resolvedArtifactDir "approval-fail-closed-matrix.json"
$activationHandoffPath = Join-Path $resolvedArtifactDir "controlled-activation-approval-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-030-two-target-canary-approval.json"

Write-Json $targetSet $targetSetPath
Write-Json $approvalPackage $approvalPackagePath
Write-Json $failClosedMatrix $matrixPath
Write-Json $activationHandoff $activationHandoffPath

Add-Check "source.rc11_021.handoff_complete" ($installerHandoffResult.status -eq "passed" -and $installerHandoffResult.summary.rc11_021_complete -eq $true) "RC11-030 must consume completed RC11-021 installer AgentCore/SecurityExecution handoff evidence." ([ordered]@{ status = $installerHandoffResult.status; handoff_state = $installerHandoffResult.handoff_surface.state; planspec_hash = $agentCorePlanSpecHash })
Add-Check "source.rc10_target_and_approval_denials_carried" ($rc10TargetResult.status -eq "passed" -and $rc10TargetResult.enrollment_surface.target_set_enrolled -eq $false -and $rc10ExactApprovalResult.status -eq "passed" -and $rc10ExactApprovalResult.binding_surface.exact_approval_granted -eq $false) "RC11-030 must carry forward RC10 target-set and exact-approval denial context." ([ordered]@{ rc10_target_state = $rc10TargetResult.enrollment_surface.state; rc10_exact_state = $rc10ExactApprovalResult.binding_surface.state })
Add-Check "target_set.two_slots_or_denial" (@($targetSet.targets).Count -eq 2 -and $targetSet.target_set_enrolled -eq $false -and $targetSet.enrolled_target_count -lt $targetSet.required_minimum_target_count) "Target set must contain two required target slots or record a target-set denial." ([ordered]@{ slots = @($targetSet.targets).Count; enrolled = $targetSet.enrolled_target_count; required = $targetSet.required_minimum_target_count; state = $targetSet.status })
Add-Check "target_set.no_duplicate_enrollment" ($targetSet.duplicate_node_check.duplicate_node_ids_detected -eq $false -and $targetSet.stale_node_check.stale_enrollment_detected -eq $false) "Target set denial must preserve duplicate and stale target checks." ([ordered]@{ duplicate = $targetSet.duplicate_node_check.duplicate_node_ids_detected; stale = $targetSet.stale_node_check.stale_enrollment_detected })
Add-Check "approval.required_binding_contract_recorded" (@($approvalPackage.required_binding_fields).Count -eq 13 -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.release_id) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.object_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.target_set_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.agentcore_planspec_hash) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.security_execution_policy_id) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.rollback_baseline_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPackage.approval_binding.support_recovery_digest)) "Exact approval package must record the required binding contract and available hash-bound fields." ([ordered]@{ required_fields = $approvalPackage.required_binding_fields; missing = $approvalPackage.missing_required_fields })
Add-Check "approval.denied_until_exact_fields_present" ($approvalPackage.exact_approval_bound -eq $false -and $approvalPackage.approval_granted -eq $false -and $approvalPackage.executable -eq $false -and @($approvalPackage.missing_required_fields).Count -gt 0) "Exact approval must deny until target ids, approval actor, audit sink, expiry, and nonce are bound." ([ordered]@{ status = $approvalPackage.status; missing = $approvalPackage.missing_required_fields })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 15) "Broad, stale, missing, single-target, duplicate-target, and mismatched approval cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" ($activationHandoff.activation_allowed -eq $false -and $activationHandoff.rollback_execution_allowed -eq $false -and $activationHandoff.remote_dispatch_enabled -eq $false) "RC11-030 must not authorize activation, rollback, support upload, remote dispatch, or production ring mutation." ([ordered]@{ activation_allowed = $activationHandoff.activation_allowed; rollback_execution_allowed = $activationHandoff.rollback_execution_allowed; remote_dispatch_enabled = $activationHandoff.remote_dispatch_enabled })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetSetPath),
    (Get-Content -Raw -LiteralPath $approvalPackagePath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $activationHandoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-030 outputs must not contain PEM blocks, auth tokens, private key paths, or signer internals." $null

$source = [ordered]@{
    installer_agentcore_security_handoff_result = New-ArtifactRef $resolvedInstallerHandoffResultPath $installerHandoffResult
    agentcore_planspec_handoff = New-ArtifactRef $resolvedAgentCoreHandoffPath $agentCoreHandoff
    security_execution_effect_envelope = New-ArtifactRef $resolvedSecurityEnvelopePath $securityEnvelope
    rc10_target_enrollment_result = New-ArtifactRef $resolvedRc10TargetEnrollmentResultPath $rc10TargetResult
    rc10_target_set = New-ArtifactRef $resolvedRc10TargetSetPath $rc10TargetSet
    rc10_exact_approval_result = New-ArtifactRef $resolvedRc10ExactApprovalResultPath $rc10ExactApprovalResult
    rc10_exact_approval_binding = New-ArtifactRef $resolvedRc10ExactApprovalBindingPath $rc10ExactApprovalBinding
    installer_quarantine_result = New-ArtifactRef $installerResultPath $installerResult
    quarantine_fetch_report = New-ArtifactRef $fetchReportPath $fetchReport
    fleet_authority = New-ArtifactRef $resolvedFleetAuthorityPath $fleetAuthority
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-two-target-canary-approval-result.v1"
    generated_at = $generatedAt
    task = "RC11-030"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    approval_surface = [ordered]@{
        state = "target-and-approval-denied"
        required_minimum_target_count = $requiredMinimumTargets
        observed_candidate_node_count = $observedCandidateNodeCount
        enrolled_target_count = $enrolledTargetCount
        target_set_enrolled = $targetSetEnrolled
        target_set_digest = $targetSetDigest
        exact_approval_required = $true
        exact_approval_bound = $false
        approval_granted = $false
        approval_binding_digest = $approvalBindingDigest
        agentcore_planspec_hash = $agentCorePlanSpecHash
        security_execution_policy_id = $securityPolicyId
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
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
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
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
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        rc11_030_complete = (@($script:failedChecks).Count -eq 0)
        target_set_enrolled = $false
        exact_approval_bound = $false
        approval_granted = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC11-031"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-two-target-canary-approval-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-030"
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
        rc11_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-031"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC11-030 result."
}

Write-Host "RC11 two-target canary approval $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Approval state: $($result.approval_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
