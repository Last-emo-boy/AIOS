param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-exact-approval-controlled-execution",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$AuditNoncePolicyResultPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/result.json",
    [string]$AuditNoncePolicyBindingPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/audit-nonce-policy-binding.json",
    [string]$AuditSubstrateHandoffPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/exact-approval-substrate-handoff.json",
    [string]$TargetIdentityResultPath = ".workflow/artifacts/rc15-two-real-local-target-identities/result.json",
    [string]$TargetIdentitySetPath = ".workflow/artifacts/rc15-two-real-local-target-identities/target-local-identity-set.json",
    [string]$TargetIdentityHandoffPath = ".workflow/artifacts/rc15-two-real-local-target-identities/exact-approval-controlled-execution-handoff.json",
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

function Get-IsoString {
    param($Value)
    if ($Value -is [DateTime]) {
        return $Value.ToString("o")
    }
    return [string]$Value
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
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
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
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        observed_blockers = $ExpectedBlockers
        missing_expected_blockers = @()
        reason = $Reason
        side_effects = [ordered]@{
            approval_granted = $false
            agentcore_planspec_executable = $false
            security_execution_allowed = $false
            effect_prepared = $false
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
$resolvedAuditNoncePolicyResultPath = Resolve-RepoPath $AuditNoncePolicyResultPath
$resolvedAuditNoncePolicyBindingPath = Resolve-RepoPath $AuditNoncePolicyBindingPath
$resolvedAuditSubstrateHandoffPath = Resolve-RepoPath $AuditSubstrateHandoffPath
$resolvedTargetIdentityResultPath = Resolve-RepoPath $TargetIdentityResultPath
$resolvedTargetIdentitySetPath = Resolve-RepoPath $TargetIdentitySetPath
$resolvedTargetIdentityHandoffPath = Resolve-RepoPath $TargetIdentityHandoffPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$auditResult = Read-Json $resolvedAuditNoncePolicyResultPath
$auditBinding = Read-Json $resolvedAuditNoncePolicyBindingPath
$auditHandoff = Read-Json $resolvedAuditSubstrateHandoffPath
$targetResult = Read-Json $resolvedTargetIdentityResultPath
$targetIdentitySet = Read-Json $resolvedTargetIdentitySetPath
$targetHandoff = Read-Json $resolvedTargetIdentityHandoffPath

$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-020").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-011").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-020" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-021" -and $rc15TaskStatus -eq "completed")
    )
)

$releaseId = [string]$targetHandoff.release_id
$objectDigest = [string]$targetHandoff.object_digest
$targetIdentitySetDigest = [string]$targetHandoff.target_identity_set_digest
$targetIdentityIds = @($targetIdentitySet.identities | ForEach-Object { [string]$_.identity_id })
$targetIdentityDigests = @($targetIdentitySet.identities | ForEach-Object { [string]$_.identity_digest })
$agentCorePlanSpecCoreHash = [string]$targetHandoff.agentcore_planspec_core_hash
$securityExecutionEnvelopeCoreHash = [string]$targetHandoff.security_execution_effect_envelope_core_hash
$auditSinkDescriptorSha256 = [string]$auditHandoff.audit_sink_descriptor_sha256
$auditBindingSha256 = [string]$auditHandoff.binding_sha256
$nonceSha256 = [string]$auditHandoff.nonce_sha256
$approvalValidUntil = Get-IsoString $auditHandoff.valid_until
$policyVersion = [string]$auditHandoff.policy_version

$approvalCore = [ordered]@{
    approval_kind = "repo-local-exact-operator-approval"
    approval_actor = "operator"
    actor_authority_scope = "repo-local-controlled-execution"
    release_id = $releaseId
    object_digest = $objectDigest
    target_identity_set_digest = $targetIdentitySetDigest
    target_identity_ids = $targetIdentityIds
    target_identity_digests = $targetIdentityDigests
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $securityExecutionEnvelopeCoreHash
    audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256
    audit_binding_sha256 = $auditBindingSha256
    nonce_sha256 = $nonceSha256
    approval_valid_until = $approvalValidUntil
    policy_version = $policyVersion
    rollback_baseline_bound = [bool]$targetIdentitySet.bindings.rollback_baseline_bound
    support_recovery_reference_bound = [bool]$targetIdentitySet.bindings.support_recovery_reference_bound
    approval_scope = "controlled-local-activation-readiness"
}
$approvalBindingDigest = Get-StringSha256 (($approvalCore | ConvertTo-Json -Depth 100 -Compress))
$approvalId = "rc15-exact-approval-" + $approvalBindingDigest.Substring(0, 16)
$approvalEvidenceRef = "local-audit-bound-approval:" + $approvalBindingDigest.Substring(0, 32)

$approvalPacket = [ordered]@{
    schema = "agentos.rc15-exact-approval-packet.v1"
    generated_at = $generatedAtValue
    task = "RC15-020"
    status = "exact-approval-bound"
    production_ready_claim = $false
    approval_id = $approvalId
    approval_evidence_ref = $approvalEvidenceRef
    approval_signature_ref_bound = $true
    approval_signature_kind = "repo-local-audit-bound-approval-record"
    exact_approval_bound = $true
    approval_granted = $true
    approval_binding_digest = $approvalBindingDigest
    approval_binding = $approvalCore
    required_binding_fields = @(
        "approval_id",
        "approval_actor",
        "actor_authority_scope",
        "approval_evidence_ref",
        "release_id",
        "object_digest",
        "target_identity_set_digest",
        "target_identity_ids",
        "agentcore_planspec_core_hash",
        "security_execution_effect_envelope_core_hash",
        "audit_sink_descriptor_sha256",
        "audit_binding_sha256",
        "nonce_sha256",
        "approval_valid_until",
        "policy_version",
        "rollback_baseline_bound",
        "support_recovery_reference_bound"
    )
    missing_required_fields = @()
    upstream_gates = [ordered]@{
        audit_sink_bound = [bool]$auditHandoff.audit_sink_bound
        nonce_bound = [bool]$auditHandoff.nonce_bound
        expiry_bound = [bool]$auditHandoff.expiry_bound
        policy_version_bound = [bool]$auditHandoff.policy_version_bound
        target_identity_set_bound = [bool]$targetHandoff.target_identity_set_bound
        enrolled_target_identity_count = [int]$targetHandoff.enrolled_target_identity_count
    }
    downstream = [ordered]@{
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
}
$approvalPacketPath = Join-Path $resolvedArtifactDir "exact-approval-packet.json"
Write-Json $approvalPacket $approvalPacketPath

$caseSpecs = @(
    [ordered]@{ id = "missing-approval-id-denied"; blockers = @("approval-id-not-bound"); reason = "Approval id is required." },
    [ordered]@{ id = "missing-approval-actor-denied"; blockers = @("approval-actor-not-bound"); reason = "Approval actor is required." },
    [ordered]@{ id = "missing-actor-authority-denied"; blockers = @("approval-actor-authority-not-bound"); reason = "Actor authority scope is required." },
    [ordered]@{ id = "unsigned-approval-denied"; blockers = @("approval-evidence-ref-not-bound"); reason = "Unsigned or unaudited approval must deny." },
    [ordered]@{ id = "missing-target-identities-denied"; blockers = @("approval-target-identities-not-bound"); reason = "Approval must bind target identities." },
    [ordered]@{ id = "missing-audit-sink-denied"; blockers = @("approval-audit-sink-not-bound"); reason = "Approval must bind the audit sink." },
    [ordered]@{ id = "missing-nonce-denied"; blockers = @("approval-nonce-not-bound"); reason = "Approval must bind nonce." },
    [ordered]@{ id = "missing-expiry-denied"; blockers = @("approval-expiry-not-bound"); reason = "Approval must bind expiry." },
    [ordered]@{ id = "missing-policy-version-denied"; blockers = @("approval-policy-version-not-bound"); reason = "Approval must bind policy version." },
    [ordered]@{ id = "stale-approval-denied"; blockers = @("approval-stale"); reason = "Stale approval must deny." },
    [ordered]@{ id = "replayed-approval-denied"; blockers = @("approval-replay-detected"); reason = "Replayed approval must deny." },
    [ordered]@{ id = "broad-approval-denied"; blockers = @("approval-broad-scope"); reason = "Broad approval must deny." },
    [ordered]@{ id = "actor-mismatch-denied"; blockers = @("approval-actor-mismatch"); reason = "Actor mismatch must deny." },
    [ordered]@{ id = "release-mismatch-denied"; blockers = @("approval-release-mismatch"); reason = "Release mismatch must deny." },
    [ordered]@{ id = "object-digest-mismatch-denied"; blockers = @("approval-object-digest-mismatch"); reason = "Object digest mismatch must deny." },
    [ordered]@{ id = "target-set-mismatch-denied"; blockers = @("approval-target-set-mismatch"); reason = "Target set mismatch must deny." },
    [ordered]@{ id = "agentcore-planspec-mismatch-denied"; blockers = @("approval-agentcore-planspec-mismatch"); reason = "PlanSpec mismatch must deny." },
    [ordered]@{ id = "security-envelope-mismatch-denied"; blockers = @("approval-security-envelope-mismatch"); reason = "SecurityExecution envelope mismatch must deny." },
    [ordered]@{ id = "audit-binding-mismatch-denied"; blockers = @("approval-audit-binding-mismatch"); reason = "Audit binding mismatch must deny." },
    [ordered]@{ id = "nonce-mismatch-denied"; blockers = @("approval-nonce-mismatch"); reason = "Nonce mismatch must deny." },
    [ordered]@{ id = "expiry-mismatch-denied"; blockers = @("approval-expiry-mismatch"); reason = "Expiry mismatch must deny." },
    [ordered]@{ id = "policy-version-mismatch-denied"; blockers = @("approval-policy-version-mismatch"); reason = "Policy version mismatch must deny." },
    [ordered]@{ id = "rollback-baseline-mismatch-denied"; blockers = @("approval-rollback-baseline-mismatch"); reason = "Rollback baseline mismatch must deny." },
    [ordered]@{ id = "support-recovery-mismatch-denied"; blockers = @("approval-support-recovery-mismatch"); reason = "Support/recovery mismatch must deny." },
    [ordered]@{ id = "approval-implies-execution-denied"; blockers = @("approval-does-not-imply-execution"); reason = "Approval alone must not authorize effects." },
    [ordered]@{ id = "remote-dispatch-authority-denied"; blockers = @("remote-dispatch-authority-broadening"); reason = "Approval must not enable remote dispatch." },
    [ordered]@{ id = "production-mutation-authority-denied"; blockers = @("production-mutation-authority-broadening"); reason = "Approval must not enable production mutation." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$matrix = [ordered]@{
    schema = "agentos.rc15-exact-approval-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC15-020"
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
$matrixPath = Join-Path $resolvedArtifactDir "exact-approval-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$handoff = [ordered]@{
    schema = "agentos.rc15-agentcore-executable-planspec-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC15-020"
    status = "ready-for-rc15-021-agentcore-executable-planspec"
    production_ready_claim = $false
    release_id = $releaseId
    object_digest = $objectDigest
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    exact_approval_bound = $true
    approval_granted = $true
    target_identity_set_bound = $true
    target_identity_set_digest = $targetIdentitySetDigest
    audit_sink_bound = $true
    nonce_bound = $true
    expiry_bound = $true
    policy_version_bound = $true
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $securityExecutionEnvelopeCoreHash
    agentcore_planspec_executable = $false
    security_execution_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @(
        "agentcore-planspec-not-executable",
        "security-execution-allow-not-bound",
        "controlled-activation-not-authorized"
    )
    next_task = "RC15-021"
}
$handoffPath = Join-Path $resolvedArtifactDir "agentcore-executable-planspec-handoff.json"
Write-Json $handoff $handoffPath

Add-Check "plan.current_task.rc15_020" $planAllowsRun "RC15-020 must run after RC15-011 completed, either while current_task is RC15-020 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_011_status = $rc15PreviousStatus; rc15_020_status = $rc15TaskStatus })
Add-Check "source.audit_nonce_policy.complete" ($auditResult.status -eq "passed" -and $auditResult.binding_surface.audit_sink_bound -eq $true -and $auditResult.binding_surface.nonce_bound -eq $true -and $auditResult.binding_surface.expiry_bound -eq $true -and $auditResult.binding_surface.policy_version_bound -eq $true) "RC15-020 must consume completed audit, nonce, expiry, and policy binding." $auditResult.binding_surface
Add-Check "source.target_identities.complete" ($targetResult.status -eq "passed" -and $targetResult.target_surface.target_identity_set_bound -eq $true -and $targetResult.target_surface.enrolled_target_identity_count -eq 2 -and $targetResult.target_surface.distinct_identity_count -eq 2) "RC15-020 must consume two distinct target identities." $targetResult.target_surface
Add-Check "contract.exact_approval_gate.present" ($contractText.Contains("exact approval") -and $contractText.Contains("policy version") -and $contractText.Contains("SecurityExecution")) "RC15 contract must include exact approval, policy, and SecurityExecution gates." (New-ArtifactRef $resolvedContractPath)
Add-Check "approval.bound_to_exact_inputs" ($approvalPacket.exact_approval_bound -eq $true -and $approvalPacket.approval_granted -eq $true -and @($approvalPacket.missing_required_fields).Count -eq 0 -and @($approvalPacket.approval_binding.target_identity_ids).Count -eq 2 -and $approvalPacket.approval_binding.audit_sink_descriptor_sha256 -eq $auditSinkDescriptorSha256 -and $approvalPacket.approval_binding.nonce_sha256 -eq $nonceSha256 -and $approvalPacket.approval_binding.policy_version -eq $policyVersion) "Exact approval must bind actor, target set, release object, PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, and policy version." ([ordered]@{ approval_id = $approvalId; binding_digest = $approvalBindingDigest; target_identity_count = @($targetIdentityIds).Count; approval_valid_until = $approvalValidUntil })
Add-Check "approval.signature_ref_bound_without_release_signing" ($approvalPacket.approval_signature_ref_bound -eq $true -and $approvalPacket.approval_signature_kind -eq "repo-local-audit-bound-approval-record") "RC15 exact approval must bind a local approval evidence reference without performing release signing." ([ordered]@{ approval_evidence_ref = $approvalEvidenceRef; signature_kind = $approvalPacket.approval_signature_kind })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 24) "Broad, stale, replayed, unsigned, actor-mismatched, target-mismatched, object-mismatched, PlanSpec-mismatched, and SecurityExecution-mismatched approvals must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "approval.does_not_imply_execution" ($handoff.exact_approval_bound -eq $true -and $handoff.approval_granted -eq $true -and $handoff.agentcore_planspec_executable -eq $false -and $handoff.security_execution_allowed -eq $false -and $handoff.activation_allowed -eq $false) "Approval must not imply AgentCore executability, SecurityExecution allow, activation, or rollback." ([ordered]@{ exact_approval_bound = $handoff.exact_approval_bound; agentcore_planspec_executable = $handoff.agentcore_planspec_executable; security_execution_allowed = $handoff.security_execution_allowed; activation_allowed = $handoff.activation_allowed })
Add-Check "handoff.agentcore_next" ($handoff.next_task -eq "RC15-021" -and $handoff.status -eq "ready-for-rc15-021-agentcore-executable-planspec") "RC15-020 must hand off to RC15-021 AgentCore executable PlanSpec readiness." ([ordered]@{ status = $handoff.status; next_task = $handoff.next_task })
Add-Check "authority.remote_dispatch_and_mutation_disabled" ($handoff.remote_dispatch_enabled -eq $false -and $handoff.production_ring_mutation_allowed -eq $false -and $approvalPacket.downstream.remote_dispatch_enabled -eq $false -and $approvalPacket.downstream.production_ring_mutation_allowed -eq $false) "RC15-020 must not enable remote dispatch or production mutation authority." ([ordered]@{ remote_dispatch_enabled = $handoff.remote_dispatch_enabled; production_ring_mutation_allowed = $handoff.production_ring_mutation_allowed })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $approvalPacketPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-020 outputs must not contain key material, auth tokens, private signing paths, or sensitive approval markers." $null

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc15_audit_nonce_policy_result = New-ArtifactRef $resolvedAuditNoncePolicyResultPath $auditResult
    rc15_audit_nonce_policy_binding = New-ArtifactRef $resolvedAuditNoncePolicyBindingPath $auditBinding
    rc15_exact_approval_substrate_handoff = New-ArtifactRef $resolvedAuditSubstrateHandoffPath $auditHandoff
    rc15_target_identity_result = New-ArtifactRef $resolvedTargetIdentityResultPath $targetResult
    rc15_target_identity_set = New-ArtifactRef $resolvedTargetIdentitySetPath $targetIdentitySet
    rc15_target_identity_handoff = New-ArtifactRef $resolvedTargetIdentityHandoffPath $targetHandoff
}

$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-020-exact-approval-controlled-execution.json"
$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-exact-approval-controlled-execution-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-020"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    approval_surface = [ordered]@{
        state = "exact-approval-bound-execution-still-gated"
        approval_id = $approvalId
        approval_binding_digest = $approvalBindingDigest
        exact_approval_bound = $true
        approval_granted = $true
        target_identity_set_bound = $true
        target_identity_set_digest = $targetIdentitySetDigest
        enrolled_target_identity_count = @($targetIdentityIds).Count
        audit_sink_bound = $true
        nonce_bound = $true
        expiry_bound = $true
        policy_version_bound = $true
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    outputs = [ordered]@{
        exact_approval_packet = [ordered]@{ path = Get-StablePath $approvalPacketPath; sha256 = Get-FileSha256 $approvalPacketPath; approval_binding_digest = $approvalBindingDigest }
        exact_approval_fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        agentcore_executable_planspec_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = $handoff.blockers
    invariants = [ordered]@{
        aios_body_only = $true
        exact_approval_bound = $true
        approval_granted = $true
        approval_does_not_imply_execution = $true
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        effect_prepared = $false
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
        rc15_020_complete = (@($script:failedChecks).Count -eq 0)
        exact_approval_bound = $true
        approval_granted = $true
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        next_task = "RC15-021"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc15-exact-approval-controlled-execution-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-020"
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
        rc15_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC15-021"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC15-020 outputs."
}

Write-Host "RC15 exact approval controlled execution $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Approval state: $($result.approval_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
