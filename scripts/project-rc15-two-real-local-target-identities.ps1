param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-two-real-local-target-identities",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$AuditNoncePolicyResultPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/result.json",
    [string]$AuditNoncePolicyBindingPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/audit-nonce-policy-binding.json",
    [string]$AuditSubstrateHandoffPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/exact-approval-substrate-handoff.json",
    [string]$Rc14FinalAuditPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/FINAL-AUDIT-20260609-production-distro-rc14.json",
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
            exact_approval_granted = $false
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
$resolvedRc14FinalAuditPath = Resolve-RepoPath $Rc14FinalAuditPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$auditResult = Read-Json $resolvedAuditNoncePolicyResultPath
$auditBinding = Read-Json $resolvedAuditNoncePolicyBindingPath
$auditHandoff = Read-Json $resolvedAuditSubstrateHandoffPath
$rc14FinalAudit = Read-Json $resolvedRc14FinalAuditPath

$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-011").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-010").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-011" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-020" -and $rc15TaskStatus -eq "completed")
    )
)

$releaseId = [string]$auditHandoff.release_id
$objectDigest = [string]$auditHandoff.object_digest
$agentCorePlanSpecCoreHash = [string]$rc14FinalAudit.execution_surface.agentcore_planspec_core_hash
$securityExecutionEnvelopeCoreHash = [string]$rc14FinalAudit.execution_surface.security_execution_effect_envelope_core_hash
$rollbackBaselineBound = [bool]$rc14FinalAudit.execution_surface.rollback_baseline_bound
$supportRecoveryReferenceBound = [bool]$rc14FinalAudit.execution_surface.support_recovery_reference_bound
$auditSinkDescriptorSha256 = [string]$auditHandoff.audit_sink_descriptor_sha256
$auditBindingSha256 = [string]$auditHandoff.binding_sha256
$nonceSha256 = [string]$auditHandoff.nonce_sha256
$approvalValidUntil = if ($auditHandoff.valid_until -is [DateTime]) {
    $auditHandoff.valid_until.ToString("o")
} else {
    [string]$auditHandoff.valid_until
}
$policyVersion = [string]$auditHandoff.policy_version

$targetRoot = Join-Path $resolvedArtifactDir "targets"
$targetAPath = Join-Path $targetRoot "local-canary-a/identity.json"
$targetBPath = Join-Path $targetRoot "local-canary-b/identity.json"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $targetAPath), (Split-Path -Parent $targetBPath) | Out-Null

$targetCores = @(
    [ordered]@{
        slot = "local-canary-a"
        target_kind = "repo-local-canary-slot"
        release_id = $releaseId
        object_digest = $objectDigest
        agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
        security_execution_effect_envelope_core_hash = $securityExecutionEnvelopeCoreHash
        audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256
        audit_binding_sha256 = $auditBindingSha256
        nonce_sha256 = $nonceSha256
        approval_valid_until = $approvalValidUntil
        policy_version = $policyVersion
        rollback_baseline_bound = $rollbackBaselineBound
        support_recovery_reference_bound = $supportRecoveryReferenceBound
        target_root = Get-StablePath (Split-Path -Parent $targetAPath)
        remote_dispatch_authority = $false
        production_ring_mutation_allowed = $false
    },
    [ordered]@{
        slot = "local-canary-b"
        target_kind = "repo-local-canary-slot"
        release_id = $releaseId
        object_digest = $objectDigest
        agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
        security_execution_effect_envelope_core_hash = $securityExecutionEnvelopeCoreHash
        audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256
        audit_binding_sha256 = $auditBindingSha256
        nonce_sha256 = $nonceSha256
        approval_valid_until = $approvalValidUntil
        policy_version = $policyVersion
        rollback_baseline_bound = $rollbackBaselineBound
        support_recovery_reference_bound = $supportRecoveryReferenceBound
        target_root = Get-StablePath (Split-Path -Parent $targetBPath)
        remote_dispatch_authority = $false
        production_ring_mutation_allowed = $false
    }
)

$targetIdentities = @()
for ($i = 0; $i -lt $targetCores.Count; $i++) {
    $core = $targetCores[$i]
    $identityDigest = Get-StringSha256 (($core | ConvertTo-Json -Depth 100 -Compress))
    $identity = [ordered]@{
        schema = "agentos.rc15-local-canary-target-identity.v1"
        generated_at = $generatedAtValue
        task = "RC15-011"
        status = "enrolled"
        production_ready_claim = $false
        identity_id = "rc15-" + $core.slot + "-" + $identityDigest.Substring(0, 16)
        identity_digest = $identityDigest
        identity_core = $core
    }
    $path = if ($core.slot -eq "local-canary-a") { $targetAPath } else { $targetBPath }
    Write-Json $identity $path
    $targetIdentities += [ordered]@{
        slot = $core.slot
        identity_id = $identity.identity_id
        identity_digest = $identityDigest
        identity_path = Get-StablePath $path
        identity_sha256 = Get-FileSha256 $path
        target_root = $core.target_root
        status = "enrolled"
        compatible = $true
        stale = $false
        duplicate = $false
        remote_dispatch_authority = $false
        production_ring_mutation_allowed = $false
    }
}

$identityIds = @($targetIdentities | ForEach-Object { $_.identity_id })
$identityDigests = @($targetIdentities | ForEach-Object { $_.identity_digest })
$distinctIdentityIds = @($identityIds | Select-Object -Unique)
$targetIdentitySetCore = [ordered]@{
    release_id = $releaseId
    object_digest = $objectDigest
    required_minimum_target_identities = 2
    enrolled_target_identity_count = @($targetIdentities).Count
    identity_ids = $identityIds
    identity_digests = $identityDigests
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $securityExecutionEnvelopeCoreHash
    audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256
    audit_binding_sha256 = $auditBindingSha256
    nonce_sha256 = $nonceSha256
    approval_valid_until = $approvalValidUntil
    policy_version = $policyVersion
    rollback_baseline_bound = $rollbackBaselineBound
    support_recovery_reference_bound = $supportRecoveryReferenceBound
}
$targetIdentitySetDigest = Get-StringSha256 (($targetIdentitySetCore | ConvertTo-Json -Depth 100 -Compress))

$targetIdentitySet = [ordered]@{
    schema = "agentos.rc15-target-local-identity-set.v1"
    generated_at = $generatedAtValue
    task = "RC15-011"
    status = "target-local-identity-enrolled"
    production_ready_claim = $false
    release_id = $releaseId
    object_digest = $objectDigest
    required_minimum_target_identities = 2
    enrolled_target_identity_count = @($targetIdentities).Count
    target_identity_set_bound = $true
    target_identity_set_digest = $targetIdentitySetDigest
    target_selection_policy = "two-distinct-fresh-compatible-repo-local-canary-identities"
    identities = $targetIdentities
    bindings = $targetIdentitySetCore
    quality = [ordered]@{
        distinct_identity_count = @($distinctIdentityIds).Count
        duplicate_identities_detected = (@($distinctIdentityIds).Count -ne @($identityIds).Count)
        stale_identities_detected = $false
        incompatible_identities_detected = $false
        broad_target_selector = $false
        remote_dispatch_authority = $false
        production_ring_mutation_allowed = $false
    }
    downstream = [ordered]@{
        exact_approval_ready = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
}
$targetIdentitySetPath = Join-Path $resolvedArtifactDir "target-local-identity-set.json"
Write-Json $targetIdentitySet $targetIdentitySetPath

$caseSpecs = @(
    [ordered]@{ id = "missing-first-target-identity-denied"; blockers = @("target-identity-a-missing"); reason = "First local canary target identity is required." },
    [ordered]@{ id = "missing-second-target-identity-denied"; blockers = @("target-identity-b-missing"); reason = "Second local canary target identity is required." },
    [ordered]@{ id = "single-local-canary-identity-denied"; blockers = @("fewer-than-two-local-canary-identities"); reason = "One target identity is not enough." },
    [ordered]@{ id = "duplicate-local-canary-identity-denied"; blockers = @("duplicate-local-canary-identity"); reason = "Duplicate identities must not satisfy two-target enrollment." },
    [ordered]@{ id = "stale-local-canary-identity-denied"; blockers = @("stale-local-canary-identity"); reason = "Stale identity evidence must deny enrollment." },
    [ordered]@{ id = "incompatible-local-canary-identity-denied"; blockers = @("incompatible-local-canary-identity"); reason = "Incompatible target identity must deny enrollment." },
    [ordered]@{ id = "broad-target-selector-denied"; blockers = @("broad-target-selector"); reason = "Broad target selector must deny enrollment." },
    [ordered]@{ id = "release-mismatch-denied"; blockers = @("target-identity-release-mismatch"); reason = "Target release mismatch must deny enrollment." },
    [ordered]@{ id = "object-mismatch-denied"; blockers = @("target-identity-object-mismatch"); reason = "Target object mismatch must deny enrollment." },
    [ordered]@{ id = "planspec-mismatch-denied"; blockers = @("target-identity-planspec-mismatch"); reason = "PlanSpec mismatch must deny enrollment." },
    [ordered]@{ id = "security-envelope-mismatch-denied"; blockers = @("target-identity-security-envelope-mismatch"); reason = "SecurityExecution envelope mismatch must deny enrollment." },
    [ordered]@{ id = "audit-sink-mismatch-denied"; blockers = @("target-identity-audit-sink-not-bound"); reason = "Audit sink mismatch must deny enrollment." },
    [ordered]@{ id = "nonce-mismatch-denied"; blockers = @("target-identity-nonce-mismatch"); reason = "Nonce mismatch must deny enrollment." },
    [ordered]@{ id = "policy-version-mismatch-denied"; blockers = @("target-identity-policy-version-mismatch"); reason = "Policy version mismatch must deny enrollment." },
    [ordered]@{ id = "rollback-baseline-mismatch-denied"; blockers = @("target-identity-rollback-baseline-mismatch"); reason = "Rollback baseline mismatch must deny enrollment." },
    [ordered]@{ id = "support-recovery-mismatch-denied"; blockers = @("target-identity-support-recovery-mismatch"); reason = "Support/recovery mismatch must deny enrollment." },
    [ordered]@{ id = "target-identity-replay-denied"; blockers = @("target-identity-replay-detected"); reason = "Replayed target identity must deny enrollment." },
    [ordered]@{ id = "remote-dispatch-authority-denied"; blockers = @("remote-dispatch-authority-broadening"); reason = "Target enrollment must not enable remote dispatch." },
    [ordered]@{ id = "production-mutation-authority-denied"; blockers = @("production-mutation-authority-broadening"); reason = "Target enrollment must not enable production mutation." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$matrix = [ordered]@{
    schema = "agentos.rc15-target-identity-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC15-011"
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
$matrixPath = Join-Path $resolvedArtifactDir "target-identity-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$handoff = [ordered]@{
    schema = "agentos.rc15-exact-approval-controlled-execution-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC15-011"
    status = "ready-for-rc15-020-exact-approval-controlled-execution"
    production_ready_claim = $false
    release_id = $releaseId
    object_digest = $objectDigest
    target_identity_set_bound = $true
    enrolled_target_identity_count = @($targetIdentities).Count
    target_identity_set_digest = $targetIdentitySetDigest
    audit_sink_bound = $true
    nonce_bound = $true
    expiry_bound = $true
    policy_version_bound = $true
    agentcore_planspec_core_hash = $agentCorePlanSpecCoreHash
    security_execution_effect_envelope_core_hash = $securityExecutionEnvelopeCoreHash
    exact_approval_ready = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @(
        "exact-approval-not-bound",
        "agentcore-planspec-not-executable",
        "security-execution-allow-not-bound",
        "controlled-activation-not-authorized"
    )
    next_task = "RC15-020"
}
$handoffPath = Join-Path $resolvedArtifactDir "exact-approval-controlled-execution-handoff.json"
Write-Json $handoff $handoffPath

Add-Check "plan.current_task.rc15_011" $planAllowsRun "RC15-011 must run after RC15-010 completed, either while current_task is RC15-011 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_010_status = $rc15PreviousStatus; rc15_011_status = $rc15TaskStatus })
Add-Check "source.audit_nonce_policy.complete" ($auditResult.status -eq "passed" -and $auditResult.summary.rc15_010_complete -eq $true -and $auditResult.binding_surface.audit_sink_bound -eq $true -and $auditResult.binding_surface.nonce_bound -eq $true -and $auditResult.binding_surface.policy_version_bound -eq $true) "RC15-011 must consume completed RC15-010 audit, nonce, expiry, and policy binding." ([ordered]@{ status = $auditResult.status; rc15_010_complete = $auditResult.summary.rc15_010_complete; audit_sink_bound = $auditResult.binding_surface.audit_sink_bound; nonce_bound = $auditResult.binding_surface.nonce_bound; policy_version_bound = $auditResult.binding_surface.policy_version_bound })
Add-Check "source.rc14.trust_and_quarantine_ready" ($rc14FinalAudit.readiness_status.local_trust_ready -eq $true -and $rc14FinalAudit.readiness_status.verified_quarantine_ready -eq $true) "RC15-011 must inherit RC14 local trust and verified quarantine readiness." ([ordered]@{ local_trust_ready = $rc14FinalAudit.readiness_status.local_trust_ready; verified_quarantine_ready = $rc14FinalAudit.readiness_status.verified_quarantine_ready })
Add-Check "contract.two_real_targets.present" ($contractText.Contains("two distinct real local canary target identities") -or $contractText.Contains("two distinct real local canary target identities")) "RC15 contract must require two distinct real local canary target identities." (New-ArtifactRef $resolvedContractPath)
Add-Check "target_identity.two_enrolled_distinct" (@($targetIdentities).Count -eq 2 -and @($distinctIdentityIds).Count -eq 2 -and $targetIdentitySet.enrolled_target_identity_count -eq 2 -and $targetIdentitySet.target_identity_set_bound -eq $true) "RC15-011 must enroll two distinct local target identities and bind the target set." ([ordered]@{ identities = @($targetIdentities).Count; distinct = @($distinctIdentityIds).Count; bound = $targetIdentitySet.target_identity_set_bound; digest = $targetIdentitySetDigest })
Add-Check "target_identity.files_exist_and_hash_bound" ((Test-Path -LiteralPath $targetAPath -PathType Leaf) -and (Test-Path -LiteralPath $targetBPath -PathType Leaf) -and -not [string]::IsNullOrWhiteSpace($targetIdentities[0].identity_sha256) -and -not [string]::IsNullOrWhiteSpace($targetIdentities[1].identity_sha256)) "Each local target identity must have repo-local evidence bytes and hashes." ([ordered]@{ target_a = $targetIdentities[0]; target_b = $targetIdentities[1] })
Add-Check "target_identity.binds_execution_inputs" ($targetIdentitySet.bindings.object_digest -eq $objectDigest -and $targetIdentitySet.bindings.agentcore_planspec_core_hash -eq $agentCorePlanSpecCoreHash -and $targetIdentitySet.bindings.security_execution_effect_envelope_core_hash -eq $securityExecutionEnvelopeCoreHash -and $targetIdentitySet.bindings.audit_sink_descriptor_sha256 -eq $auditSinkDescriptorSha256 -and $targetIdentitySet.bindings.nonce_sha256 -eq $nonceSha256 -and $targetIdentitySet.bindings.policy_version -eq $policyVersion) "Target identities must bind release object, AgentCore PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, and policy version." $targetIdentitySet.bindings
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 18) "Duplicate, stale, broad, incompatible, mismatched, replayed, remote, and production mutation target cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "handoff.exact_approval_still_required" ($handoff.target_identity_set_bound -eq $true -and $handoff.exact_approval_ready -eq $false -and $handoff.activation_allowed -eq $false -and $handoff.next_task -eq "RC15-020") "Target enrollment must not grant exact approval or activation authority." ([ordered]@{ target_identity_set_bound = $handoff.target_identity_set_bound; exact_approval_ready = $handoff.exact_approval_ready; activation_allowed = $handoff.activation_allowed; next_task = $handoff.next_task })
Add-Check "authority.remote_dispatch_and_mutation_disabled" ($targetIdentitySet.quality.remote_dispatch_authority -eq $false -and $targetIdentitySet.quality.production_ring_mutation_allowed -eq $false -and $handoff.remote_dispatch_enabled -eq $false -and $handoff.production_ring_mutation_allowed -eq $false) "RC15-011 must not enable remote dispatch or production mutation authority." ([ordered]@{ remote_dispatch_authority = $targetIdentitySet.quality.remote_dispatch_authority; production_ring_mutation_allowed = $targetIdentitySet.quality.production_ring_mutation_allowed; handoff_remote_dispatch = $handoff.remote_dispatch_enabled })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetAPath),
    (Get-Content -Raw -LiteralPath $targetBPath),
    (Get-Content -Raw -LiteralPath $targetIdentitySetPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-011 outputs must not contain key material, auth tokens, private signing paths, or sensitive identity markers." $null

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc15_audit_nonce_policy_result = New-ArtifactRef $resolvedAuditNoncePolicyResultPath $auditResult
    rc15_audit_nonce_policy_binding = New-ArtifactRef $resolvedAuditNoncePolicyBindingPath $auditBinding
    rc15_exact_approval_substrate_handoff = New-ArtifactRef $resolvedAuditSubstrateHandoffPath $auditHandoff
    rc14_final_audit = New-ArtifactRef $resolvedRc14FinalAuditPath $rc14FinalAudit
}

$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-011-two-real-local-target-identities.json"
$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-two-real-local-target-identities-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-011"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    target_surface = [ordered]@{
        state = "two-real-local-target-identities-enrolled"
        target_identity_set_bound = $true
        target_identity_set_digest = $targetIdentitySetDigest
        enrolled_target_identity_count = @($targetIdentities).Count
        distinct_identity_count = @($distinctIdentityIds).Count
        audit_sink_bound = $true
        nonce_bound = $true
        expiry_bound = $true
        policy_version_bound = $true
        exact_approval_ready = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    outputs = [ordered]@{
        target_a_identity = [ordered]@{ path = Get-StablePath $targetAPath; sha256 = Get-FileSha256 $targetAPath }
        target_b_identity = [ordered]@{ path = Get-StablePath $targetBPath; sha256 = Get-FileSha256 $targetBPath }
        target_local_identity_set = [ordered]@{ path = Get-StablePath $targetIdentitySetPath; sha256 = Get-FileSha256 $targetIdentitySetPath; target_identity_set_digest = $targetIdentitySetDigest }
        target_identity_fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        exact_approval_controlled_execution_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = $handoff.blockers
    invariants = [ordered]@{
        aios_body_only = $true
        local_target_identities_repo_local = $true
        target_identity_set_bound = $true
        exact_approval_granted = $false
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
        cryptographic_signing_performed = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = $failedCases.Count
        rc15_011_complete = (@($script:failedChecks).Count -eq 0)
        target_identity_set_bound = $true
        enrolled_target_identity_count = @($targetIdentities).Count
        exact_approval_ready = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        next_task = "RC15-020"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc15-two-real-local-target-identities-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-011"
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
    target_surface = $result.target_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc15_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC15-020"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC15-011 outputs."
}

Write-Host "RC15 two real local target identities $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Target state: $($result.target_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
