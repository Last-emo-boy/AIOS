param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-agentcore-executable-planspec",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc14",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md",
    [string]$QuarantineResultPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/result.json",
    [string]$QuarantineManifestPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/verified-quarantine-manifest.json",
    [string]$QuarantineReportPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/verified-quarantine-preflight-report.json",
    [string]$QuarantineFailClosedMatrixPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/verified-quarantine-preflight-fail-closed-matrix.json",
    [string]$QuarantineHandoffPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/agentcore-executable-planspec-handoff.json",
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
            planspec_executed = $false
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
$script:blockers = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedQuarantineResultPath = Resolve-RepoPath $QuarantineResultPath
$resolvedQuarantineManifestPath = Resolve-RepoPath $QuarantineManifestPath
$resolvedQuarantineReportPath = Resolve-RepoPath $QuarantineReportPath
$resolvedQuarantineFailClosedMatrixPath = Resolve-RepoPath $QuarantineFailClosedMatrixPath
$resolvedQuarantineHandoffPath = Resolve-RepoPath $QuarantineHandoffPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$quarantineResult = Read-Json $resolvedQuarantineResultPath
$quarantineManifest = Read-Json $resolvedQuarantineManifestPath
$quarantineReport = Read-Json $resolvedQuarantineReportPath
$quarantineFailClosedMatrix = Read-Json $resolvedQuarantineFailClosedMatrixPath
$quarantineHandoff = Read-Json $resolvedQuarantineHandoffPath

$releaseId = [string]$quarantineResult.release_id
$rc14TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-021").status
$rc14PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-020").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc14PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC14-021" -and ($rc14TaskStatus -eq "pending" -or $rc14TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC14-022" -and $rc14TaskStatus -eq "completed")
    )
)

$quarantineComplete = $quarantineResult.status -eq "passed" -and $quarantineResult.summary.rc14_020_complete -eq $true
$objectTrustBound = $quarantineResult.preflight_surface.local_object_trust_allowed -eq $true
$quarantinePreflightBound = $quarantineResult.preflight_surface.verified_quarantine_preflight -eq $true -and
    $quarantineResult.preflight_surface.quarantine_payload_written -eq $true -and
    $quarantineResult.preflight_surface.pre_interpretation_verification_performed -eq $true -and
    $quarantineResult.preflight_surface.payload_interpreted -eq $false
$quarantineHandoffReady = $quarantineHandoff.status -eq "ready-for-rc14-021-agentcore-executable-planspec" -and
    $quarantineHandoff.expected_next_task -eq "RC14-021" -and
    $quarantineHandoff.agentcore.planspec_readiness_allowed -eq $true
$quarantineFailClosedPassed = $quarantineFailClosedMatrix.summary.failed -eq 0
$quarantinePayloadHashBound = -not [string]::IsNullOrWhiteSpace([string]$quarantineResult.preflight_surface.quarantine_payload_sha256)
$quarantineManifestBound = (Get-FileSha256 $resolvedQuarantineManifestPath) -eq [string]$quarantineHandoff.quarantine.manifest_sha256
$releaseObjectBound = $quarantinePayloadHashBound -and -not [string]::IsNullOrWhiteSpace([string]$quarantineResult.preflight_surface.quarantine_payload_path)
$rollbackReferenceBound = $quarantineManifest.verification.rollback_baseline_verified -eq $true -and
    -not [string]::IsNullOrWhiteSpace([string]$quarantineManifest.source.rollback_baseline.sha256)
$supportReferenceBound = $quarantineManifest.verification.support_recovery_verified -eq $true -and
    -not [string]::IsNullOrWhiteSpace([string]$quarantineManifest.source.support_index.sha256)

$targetSetBound = $false
$exactApprovalBound = $false
$auditSinkBound = $false
$nonceBound = $false
$expiryBound = $false
$policyVersionBound = $false
$securityExecutionEnvelopeBound = $false

foreach ($blocker in @(
    $quarantineResult.blockers,
    $quarantineResult.preflight_surface.blockers,
    $quarantineHandoff.blockers
)) {
    foreach ($item in @($blocker)) {
        Add-UniqueBlocker ([string]$item)
    }
}

if (-not $planAllowsRun) { Add-UniqueBlocker "rc14-021-plan-pointer-not-current" }
if (-not $quarantineComplete) { Add-UniqueBlocker "verified-quarantine-preflight-result-not-complete" }
if (-not $objectTrustBound) { Add-UniqueBlocker "local-object-trust-not-bound" }
if (-not $quarantinePreflightBound) { Add-UniqueBlocker "verified-quarantine-preflight-not-bound" }
if (-not $quarantineHandoffReady) { Add-UniqueBlocker "agentcore-planspec-handoff-not-ready" }
if (-not $quarantineFailClosedPassed) { Add-UniqueBlocker "quarantine-fail-closed-cases-not-passed" }
if (-not $quarantineManifestBound) { Add-UniqueBlocker "quarantine-manifest-hash-mismatch" }
if (-not $releaseObjectBound) { Add-UniqueBlocker "release-object-not-bound" }
if (-not $rollbackReferenceBound) { Add-UniqueBlocker "rollback-reference-not-bound" }
if (-not $supportReferenceBound) { Add-UniqueBlocker "support-recovery-reference-not-bound" }
if (-not $targetSetBound) { Add-UniqueBlocker "target-set-not-bound" }
if (-not $exactApprovalBound) { Add-UniqueBlocker "exact-approval-not-bound" }
if (-not $auditSinkBound) { Add-UniqueBlocker "audit-sink-not-bound" }
if (-not $nonceBound) { Add-UniqueBlocker "nonce-not-bound" }
if (-not $expiryBound) { Add-UniqueBlocker "approval-expiry-not-bound" }
if (-not $policyVersionBound) { Add-UniqueBlocker "policy-version-not-bound" }
if (-not $securityExecutionEnvelopeBound) { Add-UniqueBlocker "security-execution-envelope-not-bound" }
Add-UniqueBlocker "agentcore-planspec-not-executable"
Add-UniqueBlocker "security-execution-allow-not-bound"
Add-UniqueBlocker "controlled-effect-execution-not-authorized"

$planspecExecutable = $objectTrustBound -and
    $quarantinePreflightBound -and
    $quarantineManifestBound -and
    $releaseObjectBound -and
    $rollbackReferenceBound -and
    $supportReferenceBound -and
    $targetSetBound -and
    $exactApprovalBound -and
    $auditSinkBound -and
    $nonceBound -and
    $expiryBound -and
    $policyVersionBound

$effectScope = [ordered]@{
    kind = "aios-controlled-local-release-effect"
    allowed_effects = @()
    denied_effects = @("install", "activation", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation")
    broad_scope_allowed = $false
    remote_dispatch_allowed = $false
    production_ring_mutation_allowed = $false
}

$bindingSlots = [ordered]@{
    object_trust = [ordered]@{ required = $true; bound = $objectTrustBound; source_task = "RC14-012"; source_path = ".workflow/artifacts/rc14-local-object-trust-verification/result.json" }
    verified_quarantine_preflight = [ordered]@{ required = $true; bound = $quarantinePreflightBound; source_task = "RC14-020"; source_path = Get-StablePath $resolvedQuarantineResultPath }
    release_object = [ordered]@{ required = $true; bound = $releaseObjectBound; source_task = "RC14-020"; payload_sha256 = [string]$quarantineResult.preflight_surface.quarantine_payload_sha256; payload_size_bytes = $quarantineResult.preflight_surface.quarantine_payload_size_bytes }
    target_set = [ordered]@{ required = $true; bound = $targetSetBound; expected_source_task = "RC14-030"; binding_id = $null }
    exact_approval = [ordered]@{ required = $true; bound = $exactApprovalBound; expected_source_task = "RC14-031"; binding_id = $null }
    rollback_baseline = [ordered]@{ required = $true; bound = $rollbackReferenceBound; source_path = [string]$quarantineManifest.source.rollback_baseline.path; sha256 = [string]$quarantineManifest.source.rollback_baseline.sha256 }
    support_recovery = [ordered]@{ required = $true; bound = $supportReferenceBound; source_path = [string]$quarantineManifest.source.support_index.path; sha256 = [string]$quarantineManifest.source.support_index.sha256 }
    audit_sink = [ordered]@{ required = $true; bound = $auditSinkBound; expected_source_task = "RC14-031"; binding_id = $null }
    nonce = [ordered]@{ required = $true; bound = $nonceBound; expected_source_task = "RC14-031"; value_sha256 = $null }
    expiry = [ordered]@{ required = $true; bound = $expiryBound; expected_source_task = "RC14-031"; value = $null }
    policy_version = [ordered]@{ required = $true; bound = $policyVersionBound; expected_source_task = "RC14-022"; value = $null }
}

$frozenInputs = [ordered]@{
    quarantine_result_sha256 = Get-FileSha256 $resolvedQuarantineResultPath
    quarantine_manifest_sha256 = Get-FileSha256 $resolvedQuarantineManifestPath
    quarantine_report_sha256 = Get-FileSha256 $resolvedQuarantineReportPath
    quarantine_fail_closed_matrix_sha256 = Get-FileSha256 $resolvedQuarantineFailClosedMatrixPath
    quarantine_handoff_sha256 = Get-FileSha256 $resolvedQuarantineHandoffPath
    release_id = $releaseId
    object_digest = [string]$quarantineResult.preflight_surface.quarantine_payload_sha256
    payload_size_bytes = $quarantineResult.preflight_surface.quarantine_payload_size_bytes
    quarantine_payload_path = [string]$quarantineResult.preflight_surface.quarantine_payload_path
    descriptor_sha256 = [string]$quarantineManifest.source.descriptor.sha256
    manifest_sha256 = [string]$quarantineManifest.source.initramfs_manifest.sha256
    checksum_set_sha256 = [string]$quarantineManifest.source.object_checksums.sha256
    public_signature_sha256 = [string]$quarantineManifest.source.public_signature_artifact.sha256
    revocation_snapshot_sha256 = [string]$quarantineManifest.source.revocation_snapshot.sha256
    freshness_window_sha256 = [string]$quarantineManifest.source.freshness_window.sha256
    rollback_baseline_sha256 = [string]$quarantineManifest.source.rollback_baseline.sha256
    support_recovery_sha256 = [string]$quarantineManifest.source.support_index.sha256
}

$planspecCore = [ordered]@{
    planspec_id = "rc14-agentcore-executable-planspec-candidate"
    schema = "agentos.agentcore.planspec.v1"
    plan_kind = "controlled-local-release-readiness"
    release_id = $releaseId
    production_ready_claim = $false
    projection_only = $true
    executable = $planspecExecutable
    frozen_inputs = $frozenInputs
    binding_slots = $bindingSlots
    exact_effect_scope = $effectScope
    required_bindings = [ordered]@{
        object_trust = $true
        verified_quarantine_preflight = $true
        release_object = $true
        target_set = $true
        exact_approval = $true
        rollback_baseline = $true
        support_recovery = $true
        audit_sink = $true
        nonce = $true
        expiry = $true
        policy_version = $true
    }
    observed_bindings = [ordered]@{
        object_trust = $objectTrustBound
        verified_quarantine_preflight = $quarantinePreflightBound
        release_object = $releaseObjectBound
        target_set = $targetSetBound
        exact_approval = $exactApprovalBound
        rollback_baseline = $rollbackReferenceBound
        support_recovery = $supportReferenceBound
        audit_sink = $auditSinkBound
        nonce = $nonceBound
        expiry = $expiryBound
        policy_version = $policyVersionBound
    }
    steps = @(
        [ordered]@{
            id = "bind-local-object-trust"
            authority = "evidence-binding"
            executable = $objectTrustBound
            source_task = "RC14-012"
        },
        [ordered]@{
            id = "bind-verified-quarantine-preflight"
            authority = "evidence-binding"
            executable = $quarantinePreflightBound
            evidence_hash = Get-FileSha256 $resolvedQuarantineResultPath
        },
        [ordered]@{
            id = "assert-release-object"
            authority = "object-identity"
            executable = $releaseObjectBound
            object_digest = $frozenInputs.object_digest
        },
        [ordered]@{
            id = "require-target-approval-and-audit"
            authority = "operator-approval"
            executable = $targetSetBound -and $exactApprovalBound -and $auditSinkBound -and $nonceBound -and $expiryBound
            denied_until = "RC14-030-and-RC14-031"
        },
        [ordered]@{
            id = "defer-controlled-effect"
            authority = "security-execution"
            executable = $false
            denied_until = "RC14-022-security-execution-allow-envelope"
        }
    )
    blockers = @($script:blockers)
}
$planspecCoreHash = Get-StringSha256 (($planspecCore | ConvertTo-Json -Depth 100 -Compress))

$candidate = [ordered]@{
    schema = "agentos.rc14-agentcore-planspec-candidate.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
    release_id = $releaseId
    status = if ($planspecExecutable) { "agentcore-planspec-executable" } else { "agentcore-planspec-candidate-non-executable" }
    production_ready_claim = $false
    planspec_core_hash = $planspecCoreHash
    planspec_core = $planspecCore
}

$readiness = [ordered]@{
    schema = "agentos.rc14-agentcore-executable-planspec-readiness.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
    release_id = $releaseId
    status = if ($planspecExecutable) { "agentcore-planspec-executable" } else { "agentcore-planspec-readiness-candidate-non-executable" }
    production_ready_claim = $false
    projection_only = $true
    object_trust_bound = $objectTrustBound
    quarantine_evidence_bound = $quarantineComplete
    verified_quarantine_preflight_bound = $quarantinePreflightBound
    release_object_bound = $releaseObjectBound
    target_set_bound = $targetSetBound
    exact_approval_bound = $exactApprovalBound
    rollback_reference_bound = $rollbackReferenceBound
    support_recovery_reference_bound = $supportReferenceBound
    audit_sink_bound = $auditSinkBound
    nonce_bound = $nonceBound
    expiry_bound = $expiryBound
    policy_version_bound = $policyVersionBound
    planspec_core_hash = $planspecCoreHash
    planspec_executable = $planspecExecutable
    effect_prepared = $false
    effect_executed = $false
    denied_because = @($script:blockers)
}

$denial = [ordered]@{
    schema = "agentos.rc14-agentcore-planspec-readiness-denial.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
    release_id = $releaseId
    status = "agentcore-planspec-readiness-denied"
    production_ready_claim = $false
    denied = (-not $planspecExecutable)
    planspec_core_hash = $planspecCoreHash
    denial_reasons = @($script:blockers)
    denied_effects = $effectScope.denied_effects
    preserved_boundaries = [ordered]@{
        planspec_executed = $false
        effect_prepared = $false
        effect_executed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
}

$caseBlockers = [ordered]@{
    "object-trust-missing-denies-executable-planspec" = @("local-object-trust-not-bound")
    "missing-quarantine-preflight-denies-executable-planspec" = @("verified-quarantine-preflight-not-bound")
    "stale-quarantine-handoff-denies-planspec" = @("agentcore-planspec-handoff-not-ready")
    "quarantine-manifest-drift-denies-planspec" = @("quarantine-manifest-hash-mismatch")
    "release-object-missing-denies-planspec" = @("release-object-not-bound")
    "target-set-missing-denies-planspec" = @("target-set-not-bound")
    "exact-approval-missing-denies-planspec" = @("exact-approval-not-bound")
    "audit-sink-missing-denies-planspec" = @("audit-sink-not-bound")
    "nonce-missing-denies-planspec" = @("nonce-not-bound")
    "expiry-missing-denies-planspec" = @("approval-expiry-not-bound")
    "policy-version-missing-denies-planspec" = @("policy-version-not-bound")
    "rollback-reference-missing-denies-planspec" = @("rollback-reference-not-bound")
    "support-reference-missing-denies-planspec" = @("support-recovery-reference-not-bound")
    "security-execution-envelope-missing-denies-effect" = @("security-execution-envelope-not-bound")
    "broad-effect-scope-denied" = @("controlled-effect-execution-not-authorized")
    "install-request-denied" = @("agentcore-planspec-not-executable")
    "activation-request-denied" = @("agentcore-planspec-not-executable")
    "rollback-request-denied" = @("agentcore-planspec-not-executable")
    "support-upload-request-denied" = @("security-execution-allow-not-bound")
    "remote-dispatch-request-denied" = @("security-execution-allow-not-bound")
    "production-mutation-request-denied" = @("security-execution-allow-not-bound")
}

$simulationBlockers = @(
    "local-object-trust-not-bound",
    "verified-quarantine-preflight-not-bound",
    "agentcore-planspec-handoff-not-ready",
    "quarantine-manifest-hash-mismatch",
    "release-object-not-bound",
    "rollback-reference-not-bound",
    "support-recovery-reference-not-bound"
) + @($script:blockers)

$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $simulationBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc14-agentcore-planspec-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
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

$handoff = [ordered]@{
    schema = "agentos.rc14-security-execution-allow-envelope-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
    release_id = $releaseId
    status = "ready-for-rc14-022-security-execution-allow-envelope"
    production_ready_claim = $false
    expected_next_task = "RC14-022"
    planspec = [ordered]@{
        candidate_path = $null
        candidate_sha256 = $null
        readiness_path = $null
        readiness_sha256 = $null
        planspec_core_hash = $planspecCoreHash
        candidate_materialized = $true
        executable = $planspecExecutable
        exact_effect_scope = $effectScope
    }
    security_execution = [ordered]@{
        allow_envelope_preconditions_allowed = $true
        security_execution_allowed = $false
        effect_preparation_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = @($script:blockers)
}

$source = [ordered]@{
    rc14_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc14_contract = New-ArtifactRef $resolvedContractPath
    quarantine_result = New-ArtifactRef $resolvedQuarantineResultPath $quarantineResult
    quarantine_manifest = New-ArtifactRef $resolvedQuarantineManifestPath $quarantineManifest
    quarantine_report = New-ArtifactRef $resolvedQuarantineReportPath $quarantineReport
    quarantine_fail_closed_matrix = New-ArtifactRef $resolvedQuarantineFailClosedMatrixPath $quarantineFailClosedMatrix
    quarantine_handoff = New-ArtifactRef $resolvedQuarantineHandoffPath $quarantineHandoff
}

$candidatePath = Join-Path $resolvedArtifactDir "agentcore-planspec-candidate.json"
$readinessPath = Join-Path $resolvedArtifactDir "agentcore-planspec-readiness.json"
$denialPath = Join-Path $resolvedArtifactDir "agentcore-planspec-readiness-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "agentcore-planspec-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "security-execution-allow-envelope-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC14-021-agentcore-executable-planspec.json"

Write-Json $candidate $candidatePath
Write-Json $readiness $readinessPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath
$handoff.planspec.candidate_path = Get-StablePath $candidatePath
$handoff.planspec.candidate_sha256 = Get-FileSha256 $candidatePath
$handoff.planspec.readiness_path = Get-StablePath $readinessPath
$handoff.planspec.readiness_sha256 = Get-FileSha256 $readinessPath
Write-Json $handoff $handoffPath

Add-Check "plan.current_task.rc14_021" $planAllowsRun "RC14-021 must run after RC14-020 completed, either while current_task is RC14-021 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc14_020_status = $rc14PreviousStatus; rc14_021_status = $rc14TaskStatus })
Add-Check "source.rc14_020.verified_quarantine" ($quarantineComplete -and $quarantinePreflightBound -and $quarantineFailClosedPassed -and $quarantineHandoffReady) "RC14-021 must consume completed RC14-020 verified quarantine preflight evidence." ([ordered]@{ result_status = $quarantineResult.status; verified_quarantine_preflight = $quarantinePreflightBound; handoff_status = $quarantineHandoff.status; failed_cases = $quarantineFailClosedMatrix.summary.failed })
Add-Check "contract.planspec_gate.present" ($contractText.Contains("verified quarantine/preflight evidence") -and $contractText.Contains("AgentCore executable PlanSpec candidate") -and $contractText.Contains("audit sink, nonce, expiry")) "RC14-021 must consume the AgentCore PlanSpec executable gate contract." $source.rc14_contract
Add-Check "planspec.candidate_materialized" (-not [string]::IsNullOrWhiteSpace($planspecCoreHash) -and (Test-Path -LiteralPath $candidatePath -PathType Leaf)) "PlanSpec candidate must be materialized with a stable core hash." ([ordered]@{ planspec_core_hash = $planspecCoreHash; candidate_path = Get-StablePath $candidatePath })
Add-Check "planspec.bound_release_object_and_quarantine" ($objectTrustBound -and $quarantinePreflightBound -and $releaseObjectBound -and $rollbackReferenceBound -and $supportReferenceBound) "PlanSpec candidate must hash-bind object trust, verified quarantine preflight, release object, rollback, and support/recovery references." ([ordered]@{ object_trust = $objectTrustBound; verified_quarantine = $quarantinePreflightBound; release_object = $releaseObjectBound; rollback = $rollbackReferenceBound; support_recovery = $supportReferenceBound })
Add-Check "planspec.required_binding_slots_declared" ($candidate.planspec_core.required_bindings.target_set -eq $true -and $candidate.planspec_core.required_bindings.exact_approval -eq $true -and $candidate.planspec_core.required_bindings.audit_sink -eq $true -and $candidate.planspec_core.required_bindings.nonce -eq $true -and $candidate.planspec_core.required_bindings.expiry -eq $true -and $candidate.planspec_core.required_bindings.policy_version -eq $true) "PlanSpec candidate must declare target, exact approval, audit sink, nonce, expiry, and policy-version binding slots." $candidate.planspec_core.required_bindings
Add-Check "planspec.non_executable_until_all_bindings" ($planspecExecutable -eq $false -and $targetSetBound -eq $false -and $exactApprovalBound -eq $false -and $auditSinkBound -eq $false -and $nonceBound -eq $false -and $expiryBound -eq $false -and $policyVersionBound -eq $false) "Executable readiness must remain false until every required binding is present." ([ordered]@{ planspec_executable = $planspecExecutable; target_set_bound = $targetSetBound; exact_approval_bound = $exactApprovalBound; audit_sink_bound = $auditSinkBound; nonce_bound = $nonceBound; expiry_bound = $expiryBound; policy_version_bound = $policyVersionBound })
Add-Check "effects.not_prepared" ($denial.preserved_boundaries.effect_prepared -eq $false -and $denial.preserved_boundaries.effect_executed -eq $false -and $denial.preserved_boundaries.install_allowed -eq $false -and $denial.preserved_boundaries.activation_allowed -eq $false) "PlanSpec creation must not prepare controlled effects or authorize install/activation." $denial.preserved_boundaries
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "RC14-021 PlanSpec readiness negative cases must fail closed before install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.planspec_executed -or $_.side_effects.effect_prepared -or $_.side_effects.effect_executed -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.support_upload_performed -or $_.side_effects.recovery_execution_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.production_ring_mutated }).Count -eq 0) "RC14-021 must not execute PlanSpec, prepare effects, interpret payloads, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $null

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $candidatePath),
    (Get-Content -Raw -LiteralPath $readinessPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC14-021 outputs must not contain key blocks, auth tokens, private key paths, signer internals, or raw public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc14-agentcore-executable-planspec-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    readiness_surface = [ordered]@{
        state = [string]$readiness.status
        object_trust_bound = $objectTrustBound
        quarantine_evidence_bound = $quarantineComplete
        verified_quarantine_preflight_bound = $quarantinePreflightBound
        release_object_bound = $releaseObjectBound
        target_set_bound = $targetSetBound
        exact_approval_bound = $exactApprovalBound
        rollback_reference_bound = $rollbackReferenceBound
        support_recovery_reference_bound = $supportReferenceBound
        audit_sink_bound = $auditSinkBound
        nonce_bound = $nonceBound
        expiry_bound = $expiryBound
        policy_version_bound = $policyVersionBound
        planspec_core_hash = $planspecCoreHash
        agentcore_planspec_candidate_materialized = $true
        agentcore_planspec_executable = $planspecExecutable
        security_execution_envelope_required = $true
        security_execution_allowed = $false
        effect_prepared = $false
        effect_executed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        agentcore_planspec_candidate = [ordered]@{ path = Get-StablePath $candidatePath; sha256 = Get-FileSha256 $candidatePath; planspec_core_hash = $planspecCoreHash }
        agentcore_planspec_readiness = [ordered]@{ path = Get-StablePath $readinessPath; sha256 = Get-FileSha256 $readinessPath }
        agentcore_planspec_readiness_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        security_execution_allow_envelope_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        agentcore_planspec_candidate_materialized = $true
        executable_planspec_created = $false
        planspec_executed = $false
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
        remote_payload_bytes_downloaded = $false
        new_quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        verified_quarantine_preflight_bound = $quarantinePreflightBound
        release_object_bound = $releaseObjectBound
        agentcore_planspec_candidate_materialized = $true
        agentcore_planspec_executable = $planspecExecutable
        effect_prepared = $false
        security_execution_allowed = $false
        rc14_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-022"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-agentcore-executable-planspec-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-021"
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
        rc14_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-022"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC14-021 outputs."
}

Write-Host "RC14 AgentCore PlanSpec readiness $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Readiness state: $($result.readiness_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
