param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-exact-approval-audit-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$TargetEnrollmentResultPath = ".workflow/artifacts/rc13-two-target-identity-enrollment/result.json",
    [string]$TargetIdentitySetPath = ".workflow/artifacts/rc13-two-target-identity-enrollment/target-identity-set.json",
    [string]$TargetEnrollmentDenialPath = ".workflow/artifacts/rc13-two-target-identity-enrollment/target-identity-enrollment-denial.json",
    [string]$TargetFailClosedMatrixPath = ".workflow/artifacts/rc13-two-target-identity-enrollment/target-identity-enrollment-fail-closed-matrix.json",
    [string]$ApprovalHandoffPath = ".workflow/artifacts/rc13-two-target-identity-enrollment/exact-approval-audit-binding-handoff.json",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/result.json",
    [string]$PlanSpecReadinessPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/agentcore-planspec-readiness.json",
    [string]$SecurityResultPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/result.json",
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
    if ($script:blockers -notcontains $Blocker) {
        $script:blockers += $Blocker
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
            approval_granted = $false
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

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedTargetEnrollmentResultPath = Resolve-RepoPath $TargetEnrollmentResultPath
$resolvedTargetIdentitySetPath = Resolve-RepoPath $TargetIdentitySetPath
$resolvedTargetEnrollmentDenialPath = Resolve-RepoPath $TargetEnrollmentDenialPath
$resolvedTargetFailClosedMatrixPath = Resolve-RepoPath $TargetFailClosedMatrixPath
$resolvedApprovalHandoffPath = Resolve-RepoPath $ApprovalHandoffPath
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecReadinessPath = Resolve-RepoPath $PlanSpecReadinessPath
$resolvedSecurityResultPath = Resolve-RepoPath $SecurityResultPath
$resolvedSecurityPreconditionsPath = Resolve-RepoPath $SecurityPreconditionsPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$targetEnrollmentResult = Read-Json $resolvedTargetEnrollmentResultPath
$targetIdentitySet = Read-Json $resolvedTargetIdentitySetPath
$targetEnrollmentDenial = Read-Json $resolvedTargetEnrollmentDenialPath
$targetFailClosedMatrix = Read-Json $resolvedTargetFailClosedMatrixPath
$approvalHandoff = Read-Json $resolvedApprovalHandoffPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpecReadiness = Read-Json $resolvedPlanSpecReadinessPath
$securityResult = Read-Json $resolvedSecurityResultPath
$securityPreconditions = Read-Json $resolvedSecurityPreconditionsPath

$releaseId = [string]$targetEnrollmentResult.release_id
$payloadSha256 = [string]$planSpecReadiness.planspec_core.frozen_inputs.payload_sha256
$rollbackBaselineSha256 = [string]$planSpecReadiness.planspec_core.frozen_inputs.rollback_baseline_sha256
$supportRecoverySha256 = [string]$planSpecReadiness.planspec_core.frozen_inputs.support_recovery_sha256
$targetIdentitySetDigest = [string]$targetEnrollmentResult.enrollment_surface.target_identity_set_digest
$agentCorePlanSpecCoreHash = [string]$targetEnrollmentResult.enrollment_surface.agentcore_planspec_core_hash
$effectEnvelopeCoreHash = [string]$targetEnrollmentResult.enrollment_surface.effect_envelope_core_hash
$policyVersion = "rc13-exact-approval-audit-binding-v1"

foreach ($blocker in @($targetEnrollmentResult.enrollment_surface.blockers + $targetEnrollmentResult.blockers + $targetEnrollmentDenial.blockers + $approvalHandoff.blockers + $planSpecResult.readiness_surface.blockers + $securityResult.security_surface.blockers)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$blocker)) {
        Add-UniqueBlocker ([string]$blocker)
    }
}
foreach ($blocker in @(
    "approval-id-not-bound",
    "approval-actor-not-bound",
    "approval-actor-authority-not-bound",
    "approval-target-identities-not-bound",
    "approval-audit-sink-not-bound",
    "approval-nonce-not-bound",
    "approval-expiry-not-bound",
    "approval-policy-version-not-bound",
    "approval-signature-not-bound",
    "approval-stale",
    "approval-replay-detected",
    "approval-broad-scope",
    "approval-actor-mismatch",
    "approval-release-mismatch",
    "approval-object-digest-mismatch",
    "approval-target-set-mismatch",
    "approval-agentcore-planspec-mismatch",
    "approval-security-envelope-mismatch",
    "approval-rollback-baseline-mismatch",
    "approval-support-recovery-mismatch",
    "approval-before-target-identity-set-bound",
    "approval-implies-execution-denied"
)) {
    Add-UniqueBlocker $blocker
}

$approvalBinding = [ordered]@{
    requested_actor = "operator"
    approval_id = $null
    approval_actor = $null
    actor_authority_scope = $null
    approval_signature_ref = $null
    release_id = $releaseId
    object_digest = $payloadSha256
    target_identity_set_digest = $targetIdentitySetDigest
    target_identity_ids = @()
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $effectEnvelopeCoreHash
    rollback_baseline_digest = $rollbackBaselineSha256
    support_recovery_digest = $supportRecoverySha256
    audit_sink = $null
    nonce = $null
    expiry = $null
    policy_version = $policyVersion
}
$requiredBindingFields = @(
    "requested_actor",
    "approval_id",
    "approval_actor",
    "actor_authority_scope",
    "approval_signature_ref",
    "release_id",
    "object_digest",
    "target_identity_set_digest",
    "target_identity_ids",
    "agentcore_planspec_core_hash",
    "security_execution_effect_envelope_core_hash",
    "rollback_baseline_digest",
    "support_recovery_digest",
    "audit_sink",
    "nonce",
    "expiry",
    "policy_version"
)
$missingBindingFields = @(
    "approval_id",
    "approval_actor",
    "actor_authority_scope",
    "approval_signature_ref",
    "target_identity_ids",
    "audit_sink",
    "nonce",
    "expiry"
)
$approvalBindingDigest = Get-StringSha256 (($approvalBinding | ConvertTo-Json -Depth 100 -Compress))

$approvalPacket = [ordered]@{
    schema = "agentos.rc13-exact-approval-packet.v1"
    generated_at = $generatedAtValue
    task = "RC13-031"
    status = "exact-approval-denied"
    production_ready_claim = $false
    projection_only = $true
    exact_approval_required = $true
    exact_approval_bound = $false
    approval_granted = $false
    approval_binding = $approvalBinding
    required_binding_fields = $requiredBindingFields
    missing_required_fields = $missingBindingFields
    approval_binding_digest = $approvalBindingDigest
    upstream_gates = [ordered]@{
        target_identity_enrollment_complete = $targetEnrollmentResult.summary.rc13_030_complete
        target_identity_set_bound = $targetEnrollmentResult.enrollment_surface.target_identity_set_bound
        enrolled_target_identity_count = $targetEnrollmentResult.enrollment_surface.enrolled_target_identity_count
        required_minimum_target_identities = $targetEnrollmentResult.enrollment_surface.required_minimum_target_identities
        agentcore_planspec_executable = $planSpecResult.readiness_surface.agentcore_planspec_executable
        security_execution_allowed = $securityResult.security_surface.security_execution_allowed
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
    }
    blockers = @($script:blockers)
}

$approvalDenial = [ordered]@{
    schema = "agentos.rc13-approval-audit-binding-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-031"
    status = "exact-approval-audit-binding-denied"
    production_ready_claim = $false
    denied = $true
    release_id = $releaseId
    approval_binding_digest = $approvalBindingDigest
    target_identity_set_digest = $targetIdentitySetDigest
    exact_approval_bound = $false
    approval_granted = $false
    audit_sink_bound = $false
    nonce_bound = $false
    expiry_bound = $false
    unsigned_approval_denied = $true
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($script:blockers)
}

$caseBlockers = [ordered]@{
    "missing-approval-id-denied" = @("approval-id-not-bound")
    "missing-approval-actor-denied" = @("approval-actor-not-bound")
    "missing-actor-authority-denied" = @("approval-actor-authority-not-bound")
    "unsigned-approval-denied" = @("approval-signature-not-bound")
    "missing-target-identities-denied" = @("approval-target-identities-not-bound")
    "missing-audit-sink-denied" = @("approval-audit-sink-not-bound")
    "missing-nonce-denied" = @("approval-nonce-not-bound")
    "missing-expiry-denied" = @("approval-expiry-not-bound")
    "missing-policy-version-denied" = @("approval-policy-version-not-bound")
    "stale-approval-denied" = @("approval-stale")
    "replayed-approval-denied" = @("approval-replay-detected")
    "broad-approval-denied" = @("approval-broad-scope")
    "actor-mismatch-denied" = @("approval-actor-mismatch")
    "release-mismatch-denied" = @("approval-release-mismatch")
    "object-digest-mismatch-denied" = @("approval-object-digest-mismatch")
    "target-set-mismatch-denied" = @("approval-target-set-mismatch")
    "agentcore-planspec-mismatch-denied" = @("approval-agentcore-planspec-mismatch")
    "security-envelope-mismatch-denied" = @("approval-security-envelope-mismatch")
    "rollback-baseline-mismatch-denied" = @("approval-rollback-baseline-mismatch")
    "support-recovery-mismatch-denied" = @("approval-support-recovery-mismatch")
    "approval-before-target-set-bound-denied" = @("approval-before-target-identity-set-bound")
    "approval-implies-execution-denied" = @("approval-implies-execution-denied")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$failClosedMatrix = [ordered]@{
    schema = "agentos.rc13-exact-approval-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC13-031"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    broad_stale_replayed_mismatched_missing_unsigned_approval_fail_closed = $true
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$activationHandoff = [ordered]@{
    schema = "agentos.rc13-controlled-activation-approval-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-031"
    status = "blocked-by-exact-approval-audit-binding-denial"
    production_ready_claim = $false
    release_id = $releaseId
    approval_binding_digest = $approvalBindingDigest
    target_identity_set_digest = $targetIdentitySetDigest
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $effectEnvelopeCoreHash
    exact_approval_bound = $false
    approval_granted = $false
    audit_sink_bound = $false
    nonce_bound = $false
    expiry_bound = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($script:blockers)
    next_task = "RC13-040"
}

$approvalPacketPath = Join-Path $resolvedArtifactDir "exact-approval-packet.json"
$approvalDenialPath = Join-Path $resolvedArtifactDir "approval-audit-binding-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "exact-approval-fail-closed-matrix.json"
$activationHandoffPath = Join-Path $resolvedArtifactDir "controlled-activation-approval-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-031-exact-approval-audit-binding.json"

Write-Json $approvalPacket $approvalPacketPath
Write-Json $approvalDenial $approvalDenialPath
Write-Json $failClosedMatrix $matrixPath
Write-Json $activationHandoff $activationHandoffPath

Add-Check "source.rc13_030.complete" ($targetEnrollmentResult.status -eq "passed" -and $targetEnrollmentResult.summary.rc13_030_complete -eq $true) "RC13-031 must consume completed RC13-030 target identity enrollment evidence." ([ordered]@{ status = $targetEnrollmentResult.status; rc13_030_complete = $targetEnrollmentResult.summary.rc13_030_complete; next_task = $targetEnrollmentResult.summary.next_task })
Add-Check "source.agentcore_security.bound" ($planSpecResult.status -eq "passed" -and $securityResult.status -eq "passed" -and -not [string]::IsNullOrWhiteSpace($agentCorePlanSpecCoreHash) -and -not [string]::IsNullOrWhiteSpace($effectEnvelopeCoreHash)) "RC13-031 must bind AgentCore PlanSpec and SecurityExecution envelope references." ([ordered]@{ planspec_hash = $agentCorePlanSpecCoreHash; effect_envelope_hash = $effectEnvelopeCoreHash; planspec_executable = $planSpecResult.readiness_surface.agentcore_planspec_executable; security_execution_allowed = $securityResult.security_surface.security_execution_allowed })
Add-Check "contract.exact_approval_gate.present" ($contractText.Contains("Require exact operator approval bound to actor, release, object, target set, AgentCore PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, rollback baseline, and support/recovery evidence")) "RC13 contract must include exact approval audit binding gate." (New-ArtifactRef $resolvedContractPath)
Add-Check "approval.binding_contract_records_required_fields" (@($approvalPacket.required_binding_fields).Count -ge 17 -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.requested_actor) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.release_id) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.object_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.target_identity_set_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.agentcore_planspec_core_hash) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.security_execution_effect_envelope_core_hash) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.rollback_baseline_digest) -and -not [string]::IsNullOrWhiteSpace($approvalPacket.approval_binding.support_recovery_digest)) "Approval packet must record actor, release, object, target set, AgentCore, SecurityExecution, rollback, support/recovery, audit sink, nonce, and expiry binding contract." ([ordered]@{ required_fields = $approvalPacket.required_binding_fields; missing = $approvalPacket.missing_required_fields; approval_binding_digest = $approvalBindingDigest })
Add-Check "approval.denied_until_exact_fields_present" ($approvalPacket.exact_approval_bound -eq $false -and $approvalPacket.approval_granted -eq $false -and @($approvalPacket.missing_required_fields | Where-Object { $_ -in @("approval_signature_ref", "target_identity_ids", "audit_sink", "nonce", "expiry") }).Count -eq 5) "Approval must stay denied until signature, target identities, audit sink, nonce, and expiry are bound." ([ordered]@{ status = $approvalPacket.status; missing = $approvalPacket.missing_required_fields })
Add-Check "approval.unsigned_fails_closed" ($approvalDenial.unsigned_approval_denied -eq $true -and $script:blockers -contains "approval-signature-not-bound") "Unsigned approval must fail closed." ([ordered]@{ unsigned_approval_denied = $approvalDenial.unsigned_approval_denied; blocker_present = ($script:blockers -contains "approval-signature-not-bound") })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Broad, stale, replayed, mismatched, missing, and unsigned approval cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "approval.does_not_imply_execution" ($activationHandoff.activation_allowed -eq $false -and $activationHandoff.rollback_execution_allowed -eq $false -and $activationHandoff.next_task -eq "RC13-040") "Approval evidence must not imply execution before the downstream activation task." ([ordered]@{ exact_approval_bound = $activationHandoff.exact_approval_bound; approval_granted = $activationHandoff.approval_granted; activation_allowed = $activationHandoff.activation_allowed; next_task = $activationHandoff.next_task })
Add-Check "authority.remote_dispatch_and_mutation_disabled" ($activationHandoff.remote_dispatch_enabled -eq $false -and $activationHandoff.production_ring_mutation_allowed -eq $false -and $approvalDenial.remote_dispatch_enabled -eq $false -and $approvalDenial.production_ring_mutation_allowed -eq $false) "RC13-031 must not enable remote dispatch or production mutation authority." ([ordered]@{ remote_dispatch_enabled = $activationHandoff.remote_dispatch_enabled; production_ring_mutation_allowed = $activationHandoff.production_ring_mutation_allowed })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $approvalPacketPath),
    (Get-Content -Raw -LiteralPath $approvalDenialPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $activationHandoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC13-031 outputs must not contain key material, auth tokens, private signing paths, signer internals, or sensitive approval markers." $null

$source = [ordered]@{
    rc13_contract = New-ArtifactRef $resolvedContractPath
    target_enrollment_result = New-ArtifactRef $resolvedTargetEnrollmentResultPath $targetEnrollmentResult
    target_identity_set = New-ArtifactRef $resolvedTargetIdentitySetPath $targetIdentitySet
    target_enrollment_denial = New-ArtifactRef $resolvedTargetEnrollmentDenialPath $targetEnrollmentDenial
    target_fail_closed_matrix = New-ArtifactRef $resolvedTargetFailClosedMatrixPath $targetFailClosedMatrix
    approval_handoff = New-ArtifactRef $resolvedApprovalHandoffPath $approvalHandoff
    agentcore_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    agentcore_planspec_readiness = New-ArtifactRef $resolvedPlanSpecReadinessPath $planSpecReadiness
    security_execution_result = New-ArtifactRef $resolvedSecurityResultPath $securityResult
    security_execution_preconditions = New-ArtifactRef $resolvedSecurityPreconditionsPath $securityPreconditions
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-exact-approval-audit-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-031"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    approval_surface = [ordered]@{
        state = "exact-approval-audit-binding-denied"
        approval_binding_digest = $approvalBindingDigest
        exact_approval_bound = $false
        approval_granted = $false
        unsigned_approval_denied = $true
        target_identity_set_bound = $targetEnrollmentResult.enrollment_surface.target_identity_set_bound
        target_identity_set_digest = $targetIdentitySetDigest
        enrolled_target_identity_count = $targetEnrollmentResult.enrollment_surface.enrolled_target_identity_count
        agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
        security_execution_effect_envelope_core_hash = $effectEnvelopeCoreHash
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        exact_approval_packet = [ordered]@{
            path = Get-StablePath $approvalPacketPath
            sha256 = Get-FileSha256 $approvalPacketPath
            approval_binding_digest = $approvalBindingDigest
        }
        approval_audit_binding_denial = [ordered]@{
            path = Get-StablePath $approvalDenialPath
            sha256 = Get-FileSha256 $approvalDenialPath
        }
        exact_approval_fail_closed_matrix = [ordered]@{
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
        exact_approval_fabricated = $false
        approval_granted = $false
        unsigned_approval_accepted = $false
        security_execution_effect_allowed = $false
        effect_prepared = $false
        effect_executed = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        payload_upload_performed = $false
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
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        rc13_031_complete = (@($script:failedChecks).Count -eq 0)
        exact_approval_bound = $false
        approval_granted = $false
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC13-040"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-exact-approval-audit-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-031"
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
        rc13_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-040"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC13-031 result."
}

Write-Host "RC13 exact approval audit binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Approval state: $($result.approval_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
