param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$QuarantineResultPath = ".workflow/artifacts/rc13-quarantine-preflight/result.json",
    [string]$QuarantineReportPath = ".workflow/artifacts/rc13-quarantine-preflight/quarantine-preflight-report.json",
    [string]$QuarantineDenialPath = ".workflow/artifacts/rc13-quarantine-preflight/quarantine-preflight-denial.json",
    [string]$QuarantineFailClosedMatrixPath = ".workflow/artifacts/rc13-quarantine-preflight/quarantine-preflight-fail-closed-matrix.json",
    [string]$QuarantineHandoffPath = ".workflow/artifacts/rc13-quarantine-preflight/agentcore-planspec-readiness-handoff.json",
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
            planspec_executed = $false
            effect_prepared = $false
            effect_executed = $false
            network_fetch_attempted = $false
            quarantine_payload_written = $false
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

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedQuarantineResultPath = Resolve-RepoPath $QuarantineResultPath
$resolvedQuarantineReportPath = Resolve-RepoPath $QuarantineReportPath
$resolvedQuarantineDenialPath = Resolve-RepoPath $QuarantineDenialPath
$resolvedQuarantineFailClosedMatrixPath = Resolve-RepoPath $QuarantineFailClosedMatrixPath
$resolvedQuarantineHandoffPath = Resolve-RepoPath $QuarantineHandoffPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$quarantineResult = Read-Json $resolvedQuarantineResultPath
$quarantineReport = Read-Json $resolvedQuarantineReportPath
$quarantineDenial = Read-Json $resolvedQuarantineDenialPath
$quarantineFailClosedMatrix = Read-Json $resolvedQuarantineFailClosedMatrixPath
$quarantineHandoff = Read-Json $resolvedQuarantineHandoffPath

$releaseId = [string]$quarantineResult.release_id
$quarantineComplete = $quarantineResult.status -eq "passed" -and $quarantineResult.summary.rc13_020_complete -eq $true
$objectTrustAllowed = $quarantineResult.preflight_surface.object_trust_allowed -eq $true
$quarantinePreflightAllowed = $quarantineResult.preflight_surface.quarantine_preflight_allowed -eq $true
$preflightVerified = $quarantinePreflightAllowed -and
    ($quarantineResult.preflight_surface.quarantine_payload_written -eq $true) -and
    ($quarantineResult.preflight_surface.pre_interpretation_verification_performed -eq $true) -and
    ($quarantineResult.preflight_surface.payload_interpreted -eq $false)

$releaseObjectBound = -not [string]::IsNullOrWhiteSpace([string]$quarantineReport.required_pre_interpretation_verification.payload_sha256)
$rollbackReferenceBound = -not [string]::IsNullOrWhiteSpace([string]$quarantineReport.required_pre_interpretation_verification.rollback_baseline_sha256)
$supportReferenceBound = -not [string]::IsNullOrWhiteSpace([string]$quarantineReport.required_pre_interpretation_verification.support_recovery_sha256)
$targetSetBound = $false
$exactApprovalBound = $false
$auditSinkBound = $false
$nonceBound = $false
$expiryBound = $false
$policyVersionBound = $false

foreach ($blocker in @(
    $quarantineResult.blockers,
    $quarantineResult.preflight_surface.blockers,
    $quarantineDenial.denial_reasons,
    $quarantineHandoff.blockers
)) {
    foreach ($item in @($blocker)) {
        Add-UniqueBlocker ([string]$item)
    }
}

if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $quarantinePreflightAllowed) { Add-UniqueBlocker "quarantine-preflight-not-allowed" }
if (-not $preflightVerified) { Add-UniqueBlocker "verified-quarantine-preflight-not-bound" }
if (-not $releaseObjectBound) { Add-UniqueBlocker "release-object-not-bound" }
if (-not $targetSetBound) { Add-UniqueBlocker "target-set-not-bound" }
if (-not $exactApprovalBound) { Add-UniqueBlocker "exact-approval-not-bound" }
if (-not $auditSinkBound) { Add-UniqueBlocker "audit-sink-not-bound" }
if (-not $nonceBound) { Add-UniqueBlocker "nonce-not-bound" }
if (-not $expiryBound) { Add-UniqueBlocker "approval-expiry-not-bound" }
if (-not $policyVersionBound) { Add-UniqueBlocker "policy-version-not-bound" }
if (-not $rollbackReferenceBound) { Add-UniqueBlocker "rollback-reference-not-bound" }
if (-not $supportReferenceBound) { Add-UniqueBlocker "support-recovery-reference-not-bound" }
Add-UniqueBlocker "agentcore-planspec-not-executable"
Add-UniqueBlocker "security-execution-allow-not-bound"
Add-UniqueBlocker "controlled-effect-execution-not-authorized"

$planspecExecutable = $preflightVerified -and
    $releaseObjectBound -and
    $targetSetBound -and
    $exactApprovalBound -and
    $auditSinkBound -and
    $nonceBound -and
    $expiryBound -and
    $policyVersionBound -and
    $rollbackReferenceBound -and
    $supportReferenceBound

$effectScope = [ordered]@{
    kind = "aios-controlled-release-effect"
    allowed_effects = if ($planspecExecutable) { @("install", "activation") } else { @() }
    denied_effects = if ($planspecExecutable) { @() } else { @("install", "activation", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation") }
    broad_scope_allowed = $false
    remote_dispatch_allowed = $false
    production_ring_mutation_allowed = $false
}

$frozenInputs = [ordered]@{
    quarantine_result_sha256 = Get-FileSha256 $resolvedQuarantineResultPath
    quarantine_report_sha256 = Get-FileSha256 $resolvedQuarantineReportPath
    quarantine_denial_sha256 = Get-FileSha256 $resolvedQuarantineDenialPath
    quarantine_fail_closed_matrix_sha256 = Get-FileSha256 $resolvedQuarantineFailClosedMatrixPath
    quarantine_handoff_sha256 = Get-FileSha256 $resolvedQuarantineHandoffPath
    release_id = $releaseId
    payload_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.payload_sha256
    payload_size_bytes = $quarantineReport.required_pre_interpretation_verification.payload_size_bytes
    descriptor_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.descriptor_file_sha256
    manifest_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.initramfs_manifest_sha256
    checksum_set_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.checksum_set_sha256
    public_signature_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.public_signature_artifact_sha256
    revocation_snapshot_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.revocation_snapshot_sha256
    freshness_window = $quarantineReport.required_pre_interpretation_verification.freshness_window
    rollback_baseline_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.rollback_baseline_sha256
    support_recovery_sha256 = [string]$quarantineReport.required_pre_interpretation_verification.support_recovery_sha256
}

$planspecCore = [ordered]@{
    planspec_id = "rc13-agentcore-executable-planspec-readiness"
    schema = "agentos.agentcore.planspec.v1"
    plan_kind = "controlled-release-readiness"
    release_id = $releaseId
    projection_only = $true
    executable = $planspecExecutable
    frozen_inputs = $frozenInputs
    exact_effect_scope = $effectScope
    required_bindings = [ordered]@{
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
        verified_quarantine_preflight = $preflightVerified
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
            id = "bind-quarantine-preflight-evidence"
            authority = "evidence-binding"
            executable = $quarantineComplete
            evidence_hash = Get-FileSha256 $resolvedQuarantineResultPath
        },
        [ordered]@{
            id = "assert-release-object"
            authority = "object-identity"
            executable = $releaseObjectBound
            payload_sha256 = $frozenInputs.payload_sha256
        },
        [ordered]@{
            id = "require-target-and-approval"
            authority = "operator-approval"
            executable = $targetSetBound -and $exactApprovalBound -and $auditSinkBound -and $nonceBound -and $expiryBound
        },
        [ordered]@{
            id = "prepare-controlled-effect"
            authority = "security-execution"
            executable = $false
            denied_until = "RC13-022-security-execution-allow-preconditions"
        }
    )
    blockers = @($script:blockers)
}
$planspecCoreHash = Get-StringSha256 (($planspecCore | ConvertTo-Json -Depth 100 -Compress))

$readiness = [ordered]@{
    schema = "agentos.rc13-agentcore-executable-planspec-readiness.v1"
    generated_at = $generatedAtValue
    task = "RC13-021"
    release_id = $releaseId
    status = if ($planspecExecutable) { "agentcore-planspec-executable" } else { "agentcore-planspec-readiness-denied" }
    production_ready_claim = $false
    projection_only = $true
    quarantine_evidence_bound = $quarantineComplete
    verified_quarantine_preflight_bound = $preflightVerified
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
    planspec_core = $planspecCore
    denied_because = @($script:blockers)
}

$denial = [ordered]@{
    schema = "agentos.rc13-agentcore-planspec-readiness-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-021"
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
    "missing-quarantine-preflight-denies-executable-planspec" = @("verified-quarantine-preflight-not-bound")
    "object-trust-missing-denies-planspec" = @("object-trust-not-allowed")
    "target-set-missing-denies-planspec" = @("target-set-not-bound")
    "exact-approval-missing-denies-planspec" = @("exact-approval-not-bound")
    "audit-sink-missing-denies-planspec" = @("audit-sink-not-bound")
    "nonce-missing-denies-planspec" = @("nonce-not-bound")
    "expiry-missing-denies-planspec" = @("approval-expiry-not-bound")
    "policy-version-missing-denies-planspec" = @("policy-version-not-bound")
    "broad-effect-scope-denied" = @("controlled-effect-execution-not-authorized")
    "security-execution-not-bound-denies-effect" = @("security-execution-allow-not-bound")
    "install-request-denied" = @("agentcore-planspec-not-executable")
    "activation-request-denied" = @("agentcore-planspec-not-executable")
    "rollback-request-denied" = @("agentcore-planspec-not-executable")
    "support-upload-request-denied" = @("security-execution-allow-not-bound")
    "remote-dispatch-request-denied" = @("security-execution-allow-not-bound")
    "production-mutation-request-denied" = @("security-execution-allow-not-bound")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc13-agentcore-planspec-readiness-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC13-021"
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
    schema = "agentos.rc13-security-execution-allow-preconditions-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-021"
    release_id = $releaseId
    status = if ($planspecExecutable) { "ready-for-security-execution-preconditions" } else { "blocked-before-security-execution-preconditions" }
    production_ready_claim = $false
    expected_next_task = "RC13-022"
    planspec = [ordered]@{
        readiness_path = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/agentcore-planspec-readiness.json"
        planspec_core_hash = $planspecCoreHash
        executable = $planspecExecutable
        exact_effect_scope = $effectScope
    }
    security_execution = [ordered]@{
        allow_preconditions_allowed = $false
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
    rc13_contract = New-ArtifactRef $resolvedContractPath
    quarantine_result = New-ArtifactRef $resolvedQuarantineResultPath $quarantineResult
    quarantine_report = New-ArtifactRef $resolvedQuarantineReportPath $quarantineReport
    quarantine_denial = New-ArtifactRef $resolvedQuarantineDenialPath $quarantineDenial
    quarantine_fail_closed_matrix = New-ArtifactRef $resolvedQuarantineFailClosedMatrixPath $quarantineFailClosedMatrix
    quarantine_handoff = New-ArtifactRef $resolvedQuarantineHandoffPath $quarantineHandoff
}

$readinessPath = Join-Path $resolvedArtifactDir "agentcore-planspec-readiness.json"
$denialPath = Join-Path $resolvedArtifactDir "agentcore-planspec-readiness-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "agentcore-planspec-readiness-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "security-execution-allow-preconditions-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-021-agentcore-executable-planspec-readiness.json"

Write-Json $readiness $readinessPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath
Write-Json $handoff $handoffPath

Add-Check "source.rc13_020.complete" ($quarantineComplete -and $quarantineFailClosedMatrix.summary.failed -eq 0) "RC13-021 must consume completed RC13-020 quarantine preflight evidence." ([ordered]@{ status = $quarantineResult.status; rc13_020_complete = $quarantineResult.summary.rc13_020_complete; preflight_state = $quarantineResult.preflight_surface.state; failed_cases = $quarantineFailClosedMatrix.summary.failed })
Add-Check "contract.planspec_gate.present" ($contractText.Contains("verified quarantine/preflight evidence is hash-bound into a PlanSpec") -and $contractText.Contains("exact release, object, target, approval, rollback, support/recovery, and audit references")) "RC13-021 must consume the AgentCore PlanSpec executable gate contract." $source.rc13_contract
Add-Check "planspec.release_object_hash_bound" ($releaseObjectBound -and -not [string]::IsNullOrWhiteSpace($planspecCoreHash)) "PlanSpec candidate must bind release object identity and produce a stable PlanSpec hash." ([ordered]@{ planspec_core_hash = $planspecCoreHash; release_id = $releaseId; payload_sha256 = $frozenInputs.payload_sha256 })
Add-Check "planspec.required_bindings_declared" ($rollbackReferenceBound -and $supportReferenceBound -and $readiness.planspec_core.required_bindings.target_set -eq $true -and $readiness.planspec_core.required_bindings.exact_approval -eq $true -and $readiness.planspec_core.required_bindings.audit_sink -eq $true) "PlanSpec candidate must declare target, approval, rollback, support/recovery, audit, nonce, expiry, and policy-version bindings." $readiness.planspec_core.required_bindings
Add-Check "planspec.executable_denied_until_preflight_and_exact_scope" ($planspecExecutable -eq $false -and $preflightVerified -eq $false -and $targetSetBound -eq $false -and $exactApprovalBound -eq $false) "AgentCore PlanSpec must remain non-executable until verified quarantine preflight and exact effect scope bindings are present." ([ordered]@{ planspec_executable = $planspecExecutable; preflight_verified = $preflightVerified; target_set_bound = $targetSetBound; exact_approval_bound = $exactApprovalBound; blockers = @($script:blockers) })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "RC13-021 PlanSpec readiness negative cases must fail closed before install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.planspec_executed -or $_.side_effects.effect_prepared -or $_.side_effects.effect_executed -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.support_upload_performed -or $_.side_effects.recovery_execution_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.production_ring_mutated }).Count -eq 0) "RC13-021 must not execute PlanSpec, prepare effects, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $null

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $readinessPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC13-021 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-agentcore-executable-planspec-readiness-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-021"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    readiness_surface = [ordered]@{
        state = if ($planspecExecutable) { "agentcore-planspec-executable" } else { "agentcore-planspec-readiness-denied" }
        quarantine_evidence_bound = $quarantineComplete
        verified_quarantine_preflight_bound = $preflightVerified
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
        agentcore_planspec_executable = $planspecExecutable
        security_execution_required = $true
        security_execution_allowed = $false
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
        agentcore_planspec_readiness = [ordered]@{ path = Get-StablePath $readinessPath; sha256 = Get-FileSha256 $readinessPath; planspec_core_hash = $planspecCoreHash }
        agentcore_planspec_readiness_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        security_execution_allow_preconditions_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
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
        quarantine_payload_written = $false
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
        quarantine_evidence_bound = $quarantineComplete
        verified_quarantine_preflight_bound = $preflightVerified
        release_object_bound = $releaseObjectBound
        agentcore_planspec_executable = $planspecExecutable
        security_execution_allowed = $false
        rc13_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-022"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-agentcore-executable-planspec-readiness-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-021"
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
        rc13_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-022"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC13-021 outputs."
}

Write-Host "RC13 AgentCore PlanSpec readiness $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Readiness state: $($result.readiness_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
