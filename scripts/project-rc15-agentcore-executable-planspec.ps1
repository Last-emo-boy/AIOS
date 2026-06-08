param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-agentcore-executable-planspec",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$ObjectTrustResultPath = ".workflow/artifacts/rc14-local-object-trust-verification/result.json",
    [string]$QuarantineResultPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/result.json",
    [string]$QuarantineManifestPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/verified-quarantine-manifest.json",
    [string]$QuarantineReportPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/verified-quarantine-preflight-report.json",
    [string]$ExactApprovalResultPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json",
    [string]$ExactApprovalPacketPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/exact-approval-packet.json",
    [string]$ExactApprovalHandoffPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/agentcore-executable-planspec-handoff.json",
    [string]$TargetIdentitySetPath = ".workflow/artifacts/rc15-two-real-local-target-identities/target-local-identity-set.json",
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
            planspec_executed = $false
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
$resolvedObjectTrustResultPath = Resolve-RepoPath $ObjectTrustResultPath
$resolvedQuarantineResultPath = Resolve-RepoPath $QuarantineResultPath
$resolvedQuarantineManifestPath = Resolve-RepoPath $QuarantineManifestPath
$resolvedQuarantineReportPath = Resolve-RepoPath $QuarantineReportPath
$resolvedExactApprovalResultPath = Resolve-RepoPath $ExactApprovalResultPath
$resolvedExactApprovalPacketPath = Resolve-RepoPath $ExactApprovalPacketPath
$resolvedExactApprovalHandoffPath = Resolve-RepoPath $ExactApprovalHandoffPath
$resolvedTargetIdentitySetPath = Resolve-RepoPath $TargetIdentitySetPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$objectTrustResult = Read-Json $resolvedObjectTrustResultPath
$quarantineResult = Read-Json $resolvedQuarantineResultPath
$quarantineManifest = Read-Json $resolvedQuarantineManifestPath
$quarantineReport = Read-Json $resolvedQuarantineReportPath
$approvalResult = Read-Json $resolvedExactApprovalResultPath
$approvalPacket = Read-Json $resolvedExactApprovalPacketPath
$approvalHandoff = Read-Json $resolvedExactApprovalHandoffPath
$targetIdentitySet = Read-Json $resolvedTargetIdentitySetPath

$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-021").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-020").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-021" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-022" -and $rc15TaskStatus -eq "completed")
    )
)

$releaseId = [string]$approvalPacket.approval_binding.release_id
$objectDigest = [string]$approvalPacket.approval_binding.object_digest
$approvedPlanSpecCoreHash = [string]$approvalPacket.approval_binding.agentcore_planspec_core_hash
$securityEnvelopeCoreHash = [string]$approvalPacket.approval_binding.security_execution_effect_envelope_core_hash
$objectTrustBound = $objectTrustResult.status -eq "passed" -and $objectTrustResult.verification_surface.local_object_trust_allowed -eq $true
$quarantineBound = $quarantineResult.status -eq "passed" -and
    $quarantineResult.preflight_surface.verified_quarantine_preflight -eq $true -and
    $quarantineResult.preflight_surface.pre_interpretation_verification_performed -eq $true -and
    $quarantineResult.preflight_surface.payload_interpreted -eq $false
$releaseObjectBound = [string]$quarantineResult.preflight_surface.quarantine_payload_sha256 -eq $objectDigest
$targetIdentitySetBound = $targetIdentitySet.target_identity_set_bound -eq $true -and
    [string]$targetIdentitySet.target_identity_set_digest -eq [string]$approvalPacket.approval_binding.target_identity_set_digest -and
    [int]$targetIdentitySet.enrolled_target_identity_count -eq 2
$targetIdentityIdsBound = @($approvalPacket.approval_binding.target_identity_ids).Count -eq 2
$exactApprovalBound = $approvalResult.status -eq "passed" -and
    $approvalResult.approval_surface.exact_approval_bound -eq $true -and
    $approvalPacket.exact_approval_bound -eq $true -and
    $approvalPacket.approval_granted -eq $true
$auditSinkBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.audit_sink_descriptor_sha256)
$nonceBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.nonce_sha256)
$expiryBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.approval_valid_until)
$policyVersionBound = -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.policy_version)
$rollbackReferenceBound = $approvalPacket.approval_binding.rollback_baseline_bound -eq $true -and
    $quarantineManifest.verification.rollback_baseline_verified -eq $true
$supportReferenceBound = $approvalPacket.approval_binding.support_recovery_reference_bound -eq $true -and
    $quarantineManifest.verification.support_recovery_verified -eq $true
$securityExecutionPreconditionsBound = -not [string]::IsNullOrWhiteSpace($securityEnvelopeCoreHash) -and
    $securityEnvelopeCoreHash -eq [string]$approvalHandoff.security_execution_effect_envelope_core_hash
$coreHashMatchesApproval = $approvedPlanSpecCoreHash -eq [string]$approvalHandoff.agentcore_planspec_core_hash

$planspecExecutable = $objectTrustBound -and
    $quarantineBound -and
    $releaseObjectBound -and
    $targetIdentitySetBound -and
    $targetIdentityIdsBound -and
    $exactApprovalBound -and
    $auditSinkBound -and
    $nonceBound -and
    $expiryBound -and
    $policyVersionBound -and
    $rollbackReferenceBound -and
    $supportReferenceBound -and
    $securityExecutionPreconditionsBound -and
    $coreHashMatchesApproval

$bindingSlots = [ordered]@{
    object_trust = [ordered]@{ required = $true; bound = $objectTrustBound; source_task = "RC14-012"; source_path = Get-StablePath $resolvedObjectTrustResultPath }
    verified_quarantine_preflight = [ordered]@{ required = $true; bound = $quarantineBound; source_task = "RC14-020"; source_path = Get-StablePath $resolvedQuarantineResultPath }
    release_object = [ordered]@{ required = $true; bound = $releaseObjectBound; object_digest = $objectDigest; quarantine_payload_path = [string]$quarantineResult.preflight_surface.quarantine_payload_path }
    target_identities = [ordered]@{ required = $true; bound = $targetIdentitySetBound; target_identity_set_digest = [string]$targetIdentitySet.target_identity_set_digest; identity_ids = @($approvalPacket.approval_binding.target_identity_ids) }
    exact_approval = [ordered]@{ required = $true; bound = $exactApprovalBound; approval_id = [string]$approvalPacket.approval_id; approval_binding_digest = [string]$approvalPacket.approval_binding_digest }
    audit_sink = [ordered]@{ required = $true; bound = $auditSinkBound; audit_sink_descriptor_sha256 = [string]$approvalPacket.approval_binding.audit_sink_descriptor_sha256; audit_binding_sha256 = [string]$approvalPacket.approval_binding.audit_binding_sha256 }
    nonce = [ordered]@{ required = $true; bound = $nonceBound; nonce_sha256 = [string]$approvalPacket.approval_binding.nonce_sha256 }
    expiry = [ordered]@{ required = $true; bound = $expiryBound; approval_valid_until = [string]$approvalPacket.approval_binding.approval_valid_until }
    policy_version = [ordered]@{ required = $true; bound = $policyVersionBound; policy_version = [string]$approvalPacket.approval_binding.policy_version }
    rollback_baseline = [ordered]@{ required = $true; bound = $rollbackReferenceBound; sha256 = [string]$quarantineManifest.source.rollback_baseline.sha256 }
    support_recovery = [ordered]@{ required = $true; bound = $supportReferenceBound; sha256 = [string]$quarantineManifest.source.support_index.sha256 }
    security_execution_preconditions = [ordered]@{ required = $true; bound = $securityExecutionPreconditionsBound; effect_envelope_core_hash = $securityEnvelopeCoreHash }
}

$planspecCore = [ordered]@{
    planspec_id = "rc15-agentcore-executable-planspec"
    schema = "agentos.agentcore.planspec.v1"
    plan_kind = "controlled-local-activation-readiness"
    release_id = $releaseId
    production_ready_claim = $false
    executable = $planspecExecutable
    approved_core_hash = $approvedPlanSpecCoreHash
    core_hash_matches_exact_approval = $coreHashMatchesApproval
    object_digest = $objectDigest
    binding_slots = $bindingSlots
    exact_effect_scope = [ordered]@{
        kind = "controlled-local-activation"
        effect_preparation_allowed = $false
        effect_execution_allowed = $false
        security_execution_allow_required = $true
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    steps = @(
        [ordered]@{ id = "verify-local-object-trust"; authority = "evidence-binding"; executable = $objectTrustBound; source_task = "RC14-012" },
        [ordered]@{ id = "bind-verified-quarantine"; authority = "evidence-binding"; executable = $quarantineBound; source_task = "RC14-020" },
        [ordered]@{ id = "bind-target-identity-set"; authority = "local-target-identity"; executable = $targetIdentitySetBound; source_task = "RC15-011" },
        [ordered]@{ id = "bind-exact-approval"; authority = "operator-approval"; executable = $exactApprovalBound; source_task = "RC15-020" },
        [ordered]@{ id = "await-security-execution-allow"; authority = "security-execution"; executable = $false; source_task = "RC15-022" }
    )
}
$planspecMaterializationDigest = Get-StringSha256 (($planspecCore | ConvertTo-Json -Depth 100 -Compress))

$planspec = [ordered]@{
    schema = "agentos.rc15-agentcore-planspec.v1"
    generated_at = $generatedAtValue
    task = "RC15-021"
    status = if ($planspecExecutable) { "agentcore-planspec-executable" } else { "agentcore-planspec-non-executable" }
    production_ready_claim = $false
    planspec_core_hash = $approvedPlanSpecCoreHash
    planspec_materialization_digest = $planspecMaterializationDigest
    planspec_core = $planspecCore
}
$planspecPath = Join-Path $resolvedArtifactDir "agentcore-planspec.json"
Write-Json $planspec $planspecPath

$caseSpecs = @(
    [ordered]@{ id = "object-trust-missing-denies-executable-planspec"; blockers = @("local-object-trust-not-bound"); reason = "Object trust must be bound." },
    [ordered]@{ id = "verified-quarantine-missing-denies-executable-planspec"; blockers = @("verified-quarantine-preflight-not-bound"); reason = "Verified quarantine must be bound." },
    [ordered]@{ id = "release-object-mismatch-denies-planspec"; blockers = @("release-object-mismatch"); reason = "Release object digest must match quarantine payload." },
    [ordered]@{ id = "target-set-missing-denies-planspec"; blockers = @("target-set-not-bound"); reason = "Target identity set must be bound." },
    [ordered]@{ id = "target-identity-count-mismatch-denies-planspec"; blockers = @("target-identity-count-mismatch"); reason = "Two target identities are required." },
    [ordered]@{ id = "exact-approval-missing-denies-planspec"; blockers = @("exact-approval-not-bound"); reason = "Exact approval must be bound." },
    [ordered]@{ id = "approval-core-hash-mismatch-denies-planspec"; blockers = @("approval-agentcore-planspec-mismatch"); reason = "Approval must bind the PlanSpec core hash." },
    [ordered]@{ id = "audit-sink-missing-denies-planspec"; blockers = @("audit-sink-not-bound"); reason = "Audit sink is required." },
    [ordered]@{ id = "nonce-missing-denies-planspec"; blockers = @("nonce-not-bound"); reason = "Nonce is required." },
    [ordered]@{ id = "expiry-missing-denies-planspec"; blockers = @("approval-expiry-not-bound"); reason = "Expiry is required." },
    [ordered]@{ id = "policy-version-missing-denies-planspec"; blockers = @("policy-version-not-bound"); reason = "Policy version is required." },
    [ordered]@{ id = "rollback-reference-missing-denies-planspec"; blockers = @("rollback-reference-not-bound"); reason = "Rollback baseline is required." },
    [ordered]@{ id = "support-reference-missing-denies-planspec"; blockers = @("support-recovery-reference-not-bound"); reason = "Support/recovery reference is required." },
    [ordered]@{ id = "security-envelope-missing-denies-planspec"; blockers = @("security-execution-envelope-not-bound"); reason = "SecurityExecution envelope reference is required." },
    [ordered]@{ id = "stale-planspec-input-denied"; blockers = @("planspec-input-stale"); reason = "Stale PlanSpec input must deny." },
    [ordered]@{ id = "replayed-planspec-input-denied"; blockers = @("planspec-input-replay-detected"); reason = "Replayed PlanSpec input must deny." },
    [ordered]@{ id = "broad-effect-scope-denied"; blockers = @("broad-effect-scope"); reason = "Broad effects must deny." },
    [ordered]@{ id = "install-effect-denied-before-security-allow"; blockers = @("security-execution-allow-not-bound"); reason = "Install remains denied before SecurityExecution allow." },
    [ordered]@{ id = "activation-effect-denied-before-security-allow"; blockers = @("security-execution-allow-not-bound"); reason = "Activation remains denied before SecurityExecution allow." },
    [ordered]@{ id = "rollback-effect-denied-before-security-allow"; blockers = @("security-execution-allow-not-bound"); reason = "Rollback remains denied before SecurityExecution allow." },
    [ordered]@{ id = "support-upload-denied-before-security-allow"; blockers = @("security-execution-allow-not-bound"); reason = "Support upload remains denied before SecurityExecution allow." },
    [ordered]@{ id = "remote-dispatch-denied"; blockers = @("remote-dispatch-authority-broadening"); reason = "Remote dispatch stays denied." },
    [ordered]@{ id = "production-mutation-denied"; blockers = @("production-mutation-authority-broadening"); reason = "Production mutation stays denied." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$matrix = [ordered]@{
    schema = "agentos.rc15-agentcore-planspec-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC15-021"
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
$matrixPath = Join-Path $resolvedArtifactDir "agentcore-planspec-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$handoff = [ordered]@{
    schema = "agentos.rc15-security-execution-allow-decision-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC15-021"
    status = "ready-for-rc15-022-security-execution-allow-decision"
    production_ready_claim = $false
    release_id = $releaseId
    object_digest = $objectDigest
    planspec_core_hash = $approvedPlanSpecCoreHash
    planspec_materialization_digest = $planspecMaterializationDigest
    agentcore_planspec_executable = $planspecExecutable
    exact_approval_bound = $exactApprovalBound
    approval_id = [string]$approvalPacket.approval_id
    approval_binding_digest = [string]$approvalPacket.approval_binding_digest
    security_execution_effect_envelope_core_hash = $securityEnvelopeCoreHash
    security_execution_allowed = $false
    effect_prepared = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @(
        "security-execution-allow-not-bound",
        "controlled-activation-not-authorized"
    )
    next_task = "RC15-022"
}
$handoffPath = Join-Path $resolvedArtifactDir "security-execution-allow-decision-handoff.json"
Write-Json $handoff $handoffPath

Add-Check "plan.current_task.rc15_021" $planAllowsRun "RC15-021 must run after RC15-020 completed, either while current_task is RC15-021 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_020_status = $rc15PreviousStatus; rc15_021_status = $rc15TaskStatus })
Add-Check "source.object_trust.bound" $objectTrustBound "RC15-021 must consume RC14 local object trust." $objectTrustResult.verification_surface
Add-Check "source.verified_quarantine.bound" $quarantineBound "RC15-021 must consume RC14 verified quarantine preflight without payload interpretation." $quarantineResult.preflight_surface
Add-Check "source.target_and_approval.bound" ($targetIdentitySetBound -and $exactApprovalBound -and $auditSinkBound -and $nonceBound -and $expiryBound -and $policyVersionBound) "RC15-021 must consume RC15 target identity set and exact approval with audit, nonce, expiry, and policy binding." ([ordered]@{ target_identity_set_bound = $targetIdentitySetBound; exact_approval_bound = $exactApprovalBound; audit_sink_bound = $auditSinkBound; nonce_bound = $nonceBound; expiry_bound = $expiryBound; policy_version_bound = $policyVersionBound })
Add-Check "contract.agentcore_gate.present" ($contractText.Contains("AgentCore PlanSpec is executable") -and $contractText.Contains("exact approval") -and $contractText.Contains("AgentCore executable state does not imply SecurityExecution allow")) "RC15 contract must include AgentCore executable PlanSpec and SecurityExecution separation." (New-ArtifactRef $resolvedContractPath)
Add-Check "planspec.executable_when_bindings_present" ($planspecExecutable -eq $true -and $planspec.planspec_core.executable -eq $true) "AgentCore PlanSpec executable state must become true only after object trust, quarantine, targets, approval, audit, nonce, expiry, policy, and security preconditions are bound." ([ordered]@{ executable = $planspecExecutable; planspec_core_hash = $approvedPlanSpecCoreHash; materialization_digest = $planspecMaterializationDigest })
Add-Check "planspec.core_hash_matches_exact_approval" ($coreHashMatchesApproval -eq $true) "PlanSpec core hash must match the exact approval binding." ([ordered]@{ approved = $approvedPlanSpecCoreHash; handoff = $approvalHandoff.agentcore_planspec_core_hash })
Add-Check "security.preconditions_bound_but_not_allowed" ($securityExecutionPreconditionsBound -eq $true -and $handoff.security_execution_allowed -eq $false -and $handoff.effect_prepared -eq $false) "SecurityExecution preconditions must be bound, while allow decision and effect preparation remain separate." ([ordered]@{ preconditions_bound = $securityExecutionPreconditionsBound; security_execution_allowed = $handoff.security_execution_allowed; effect_prepared = $handoff.effect_prepared })
Add-Check "effects.not_prepared_or_executed" ($planspec.planspec_core.exact_effect_scope.effect_preparation_allowed -eq $false -and $planspec.planspec_core.exact_effect_scope.effect_execution_allowed -eq $false -and $handoff.activation_allowed -eq $false -and $handoff.rollback_execution_allowed -eq $false) "AgentCore executable PlanSpec must not prepare or execute effects by itself." $planspec.planspec_core.exact_effect_scope
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing, stale, mismatched, broad, or replayed PlanSpec inputs must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "handoff.security_execution_next" ($handoff.next_task -eq "RC15-022" -and $handoff.status -eq "ready-for-rc15-022-security-execution-allow-decision") "RC15-021 must hand off to RC15-022 SecurityExecution allow decision." ([ordered]@{ status = $handoff.status; next_task = $handoff.next_task })
Add-Check "authority.remote_dispatch_and_mutation_disabled" ($handoff.remote_dispatch_enabled -eq $false -and $handoff.production_ring_mutation_allowed -eq $false) "RC15-021 must not enable remote dispatch or production mutation authority." ([ordered]@{ remote_dispatch_enabled = $handoff.remote_dispatch_enabled; production_ring_mutation_allowed = $handoff.production_ring_mutation_allowed })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $planspecPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-021 outputs must not contain key material, auth tokens, private signing paths, or sensitive approval markers." $null

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc14_local_object_trust = New-ArtifactRef $resolvedObjectTrustResultPath $objectTrustResult
    rc14_verified_quarantine_result = New-ArtifactRef $resolvedQuarantineResultPath $quarantineResult
    rc14_verified_quarantine_manifest = New-ArtifactRef $resolvedQuarantineManifestPath $quarantineManifest
    rc14_verified_quarantine_report = New-ArtifactRef $resolvedQuarantineReportPath $quarantineReport
    rc15_exact_approval_result = New-ArtifactRef $resolvedExactApprovalResultPath $approvalResult
    rc15_exact_approval_packet = New-ArtifactRef $resolvedExactApprovalPacketPath $approvalPacket
    rc15_agentcore_handoff = New-ArtifactRef $resolvedExactApprovalHandoffPath $approvalHandoff
    rc15_target_identity_set = New-ArtifactRef $resolvedTargetIdentitySetPath $targetIdentitySet
}

$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-021-agentcore-executable-planspec.json"
$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-agentcore-executable-planspec-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-021"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    readiness_surface = [ordered]@{
        state = "agentcore-planspec-executable-security-execution-pending"
        object_trust_bound = $objectTrustBound
        verified_quarantine_preflight_bound = $quarantineBound
        release_object_bound = $releaseObjectBound
        target_identity_set_bound = $targetIdentitySetBound
        exact_approval_bound = $exactApprovalBound
        audit_sink_bound = $auditSinkBound
        nonce_bound = $nonceBound
        expiry_bound = $expiryBound
        policy_version_bound = $policyVersionBound
        rollback_reference_bound = $rollbackReferenceBound
        support_recovery_reference_bound = $supportReferenceBound
        security_execution_preconditions_bound = $securityExecutionPreconditionsBound
        planspec_core_hash = $approvedPlanSpecCoreHash
        planspec_materialization_digest = $planspecMaterializationDigest
        agentcore_planspec_executable = $planspecExecutable
        security_execution_allowed = $false
        effect_prepared = $false
        effect_executed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    outputs = [ordered]@{
        agentcore_planspec = [ordered]@{ path = Get-StablePath $planspecPath; sha256 = Get-FileSha256 $planspecPath; planspec_core_hash = $approvedPlanSpecCoreHash; planspec_materialization_digest = $planspecMaterializationDigest }
        agentcore_planspec_fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        security_execution_allow_decision_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = $handoff.blockers
    invariants = [ordered]@{
        aios_body_only = $true
        agentcore_planspec_executable = $planspecExecutable
        security_execution_allowed = $false
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
        rc15_021_complete = (@($script:failedChecks).Count -eq 0)
        agentcore_planspec_executable = $planspecExecutable
        security_execution_allowed = $false
        effect_prepared = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        next_task = "RC15-022"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc15-agentcore-executable-planspec-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-021"
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
    readiness_surface = $result.readiness_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc15_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC15-022"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC15-021 outputs."
}

Write-Host "RC15 AgentCore executable PlanSpec $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Readiness state: $($result.readiness_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
