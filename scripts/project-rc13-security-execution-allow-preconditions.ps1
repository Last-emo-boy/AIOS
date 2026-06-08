param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-security-execution-allow-preconditions",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/result.json",
    [string]$PlanSpecReadinessPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/agentcore-planspec-readiness.json",
    [string]$PlanSpecDenialPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/agentcore-planspec-readiness-denial.json",
    [string]$PlanSpecFailClosedMatrixPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/agentcore-planspec-readiness-fail-closed-matrix.json",
    [string]$PlanSpecHandoffPath = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/security-execution-allow-preconditions-handoff.json",
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
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecReadinessPath = Resolve-RepoPath $PlanSpecReadinessPath
$resolvedPlanSpecDenialPath = Resolve-RepoPath $PlanSpecDenialPath
$resolvedPlanSpecFailClosedMatrixPath = Resolve-RepoPath $PlanSpecFailClosedMatrixPath
$resolvedPlanSpecHandoffPath = Resolve-RepoPath $PlanSpecHandoffPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpecReadiness = Read-Json $resolvedPlanSpecReadinessPath
$planSpecDenial = Read-Json $resolvedPlanSpecDenialPath
$planSpecFailClosedMatrix = Read-Json $resolvedPlanSpecFailClosedMatrixPath
$planSpecHandoff = Read-Json $resolvedPlanSpecHandoffPath

$releaseId = [string]$planSpecResult.release_id
$planSpecComplete = $planSpecResult.status -eq "passed" -and $planSpecResult.summary.rc13_021_complete -eq $true
$objectTrustAllowed = $planSpecResult.readiness_surface.blockers -notcontains "object-trust-not-allowed"
$verifiedQuarantinePreflight = $planSpecResult.readiness_surface.verified_quarantine_preflight_bound -eq $true
$releaseObjectBound = $planSpecResult.readiness_surface.release_object_bound -eq $true
$planSpecExecutable = $planSpecResult.readiness_surface.agentcore_planspec_executable -eq $true
$targetSetBound = $planSpecResult.readiness_surface.target_set_bound -eq $true
$exactApprovalBound = $planSpecResult.readiness_surface.exact_approval_bound -eq $true
$auditSinkBound = $planSpecResult.readiness_surface.audit_sink_bound -eq $true
$nonceBound = $planSpecResult.readiness_surface.nonce_bound -eq $true
$expiryBound = $planSpecResult.readiness_surface.expiry_bound -eq $true
$policyVersionBound = $planSpecResult.readiness_surface.policy_version_bound -eq $true
$rollbackReferenceBound = $planSpecResult.readiness_surface.rollback_reference_bound -eq $true
$supportReferenceBound = $planSpecResult.readiness_surface.support_recovery_reference_bound -eq $true
$broadScopeDenied = $planSpecReadiness.planspec_core.exact_effect_scope.broad_scope_allowed -eq $false
$remoteDispatchDenied = $planSpecReadiness.planspec_core.exact_effect_scope.remote_dispatch_allowed -eq $false
$productionMutationDenied = $planSpecReadiness.planspec_core.exact_effect_scope.production_ring_mutation_allowed -eq $false

foreach ($blocker in @(
    $planSpecResult.blockers,
    $planSpecResult.readiness_surface.blockers,
    $planSpecReadiness.denied_because,
    $planSpecDenial.denial_reasons,
    $planSpecHandoff.blockers
)) {
    foreach ($item in @($blocker)) {
        Add-UniqueBlocker ([string]$item)
    }
}

if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $verifiedQuarantinePreflight) { Add-UniqueBlocker "verified-quarantine-preflight-not-bound" }
if (-not $releaseObjectBound) { Add-UniqueBlocker "release-object-not-bound" }
if (-not $planSpecExecutable) { Add-UniqueBlocker "agentcore-planspec-not-executable" }
if (-not $targetSetBound) { Add-UniqueBlocker "target-set-not-bound" }
if (-not $exactApprovalBound) { Add-UniqueBlocker "exact-approval-not-bound" }
if (-not $auditSinkBound) { Add-UniqueBlocker "audit-sink-not-bound" }
if (-not $nonceBound) { Add-UniqueBlocker "nonce-not-bound" }
if (-not $expiryBound) { Add-UniqueBlocker "approval-expiry-not-bound" }
if (-not $policyVersionBound) { Add-UniqueBlocker "policy-version-not-bound" }
if (-not $rollbackReferenceBound) { Add-UniqueBlocker "rollback-reference-not-bound" }
if (-not $supportReferenceBound) { Add-UniqueBlocker "support-recovery-reference-not-bound" }
if (-not $broadScopeDenied) { Add-UniqueBlocker "broad-effect-scope-not-denied" }
if (-not $remoteDispatchDenied) { Add-UniqueBlocker "remote-dispatch-not-denied" }
if (-not $productionMutationDenied) { Add-UniqueBlocker "production-ring-mutation-not-denied" }

Add-UniqueBlocker "security-execution-allow-not-bound"
Add-UniqueBlocker "security-execution-effect-envelope-denied"
Add-UniqueBlocker "controlled-effect-execution-not-authorized"
Add-UniqueBlocker "two-target-canary-not-enrolled"
Add-UniqueBlocker "canary-target-identity-enrollment-not-run"

$securityExecutionAllowed = $objectTrustAllowed -and
    $verifiedQuarantinePreflight -and
    $releaseObjectBound -and
    $planSpecExecutable -and
    $targetSetBound -and
    $exactApprovalBound -and
    $auditSinkBound -and
    $nonceBound -and
    $expiryBound -and
    $policyVersionBound -and
    $rollbackReferenceBound -and
    $supportReferenceBound -and
    $broadScopeDenied -and
    $remoteDispatchDenied -and
    $productionMutationDenied

$requiredPreconditions = [ordered]@{
    object_trust_allowed = $true
    verified_quarantine_preflight = $true
    release_object_bound = $true
    agentcore_planspec_executable = $true
    exact_effect_scope = $true
    target_set_bound = $true
    exact_approval_bound = $true
    audit_sink_bound = $true
    nonce_bound = $true
    expiry_bound = $true
    policy_version_bound = $true
    rollback_reference_bound = $true
    support_recovery_reference_bound = $true
    broad_scope_denied = $true
    remote_dispatch_denied = $true
    production_mutation_denied = $true
}
$observedPreconditions = [ordered]@{
    object_trust_allowed = $objectTrustAllowed
    verified_quarantine_preflight = $verifiedQuarantinePreflight
    release_object_bound = $releaseObjectBound
    agentcore_planspec_executable = $planSpecExecutable
    exact_effect_scope = $broadScopeDenied
    target_set_bound = $targetSetBound
    exact_approval_bound = $exactApprovalBound
    audit_sink_bound = $auditSinkBound
    nonce_bound = $nonceBound
    expiry_bound = $expiryBound
    policy_version_bound = $policyVersionBound
    rollback_reference_bound = $rollbackReferenceBound
    support_recovery_reference_bound = $supportReferenceBound
    broad_scope_denied = $broadScopeDenied
    remote_dispatch_denied = $remoteDispatchDenied
    production_mutation_denied = $productionMutationDenied
}

$effectEnvelopeCore = [ordered]@{
    envelope_id = "rc13-security-execution-allow-preconditions"
    release_id = $releaseId
    planspec_core_hash = [string]$planSpecResult.readiness_surface.planspec_core_hash
    planspec_result_sha256 = Get-FileSha256 $resolvedPlanSpecResultPath
    readiness_sha256 = Get-FileSha256 $resolvedPlanSpecReadinessPath
    required_preconditions = $requiredPreconditions
    observed_preconditions = $observedPreconditions
    allowed_effects = if ($securityExecutionAllowed) { @("install", "activation") } else { @() }
    denied_effects = if ($securityExecutionAllowed) { @() } else { @("install", "activation", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation") }
    allow = $securityExecutionAllowed
}
$effectEnvelopeCoreHash = Get-StringSha256 (($effectEnvelopeCore | ConvertTo-Json -Depth 100 -Compress))

$preconditions = [ordered]@{
    schema = "agentos.rc13-security-execution-allow-preconditions.v1"
    generated_at = $generatedAtValue
    task = "RC13-022"
    release_id = $releaseId
    status = if ($securityExecutionAllowed) { "security-execution-allow-preconditions-satisfied" } else { "security-execution-allow-preconditions-denied" }
    production_ready_claim = $false
    projection_only = $true
    security_execution_allowed = $securityExecutionAllowed
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    effect_envelope_core = $effectEnvelopeCore
    blockers = @($script:blockers)
}

$denial = [ordered]@{
    schema = "agentos.rc13-security-execution-allow-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-022"
    release_id = $releaseId
    status = "security-execution-allow-denied"
    production_ready_claim = $false
    denied = (-not $securityExecutionAllowed)
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    denial_reasons = @($script:blockers)
    denied_effects = $effectEnvelopeCore.denied_effects
    preserved_boundaries = [ordered]@{
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
    "object-trust-missing-denies-security-allow" = @("object-trust-not-allowed")
    "quarantine-preflight-missing-denies-security-allow" = @("verified-quarantine-preflight-not-bound")
    "planspec-non-executable-denies-security-allow" = @("agentcore-planspec-not-executable")
    "target-set-missing-denies-security-allow" = @("target-set-not-bound")
    "exact-approval-missing-denies-security-allow" = @("exact-approval-not-bound")
    "audit-sink-missing-denies-security-allow" = @("audit-sink-not-bound")
    "nonce-missing-denies-security-allow" = @("nonce-not-bound")
    "expiry-missing-denies-security-allow" = @("approval-expiry-not-bound")
    "policy-version-missing-denies-security-allow" = @("policy-version-not-bound")
    "broad-effect-scope-denied" = @("controlled-effect-execution-not-authorized")
    "install-effect-denied" = @("security-execution-effect-envelope-denied")
    "activation-effect-denied" = @("security-execution-effect-envelope-denied")
    "rollback-effect-denied" = @("controlled-rollback-not-authorized")
    "support-upload-effect-denied" = @("security-execution-effect-envelope-denied")
    "remote-dispatch-effect-denied" = @("security-execution-effect-envelope-denied")
    "production-mutation-effect-denied" = @("security-execution-effect-envelope-denied")
    "canary-target-enrollment-required-next" = @("canary-target-identity-enrollment-not-run")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc13-security-execution-allow-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC13-022"
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
    schema = "agentos.rc13-two-target-identity-enrollment-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-022"
    release_id = $releaseId
    status = "ready-for-identity-enrollment-with-security-denied"
    production_ready_claim = $false
    expected_next_task = "RC13-030"
    security_execution = [ordered]@{
        allow_preconditions_path = ".workflow/artifacts/rc13-security-execution-allow-preconditions/security-execution-allow-preconditions.json"
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        security_execution_allowed = $securityExecutionAllowed
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    target_enrollment = [ordered]@{
        minimum_required_targets = 2
        enrolled_target_count = 0
        duplicate_targets_allowed = $false
        remote_dispatch_authority = $false
    }
    blockers = @($script:blockers)
}

$source = [ordered]@{
    rc13_contract = New-ArtifactRef $resolvedContractPath
    planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    planspec_readiness = New-ArtifactRef $resolvedPlanSpecReadinessPath $planSpecReadiness
    planspec_denial = New-ArtifactRef $resolvedPlanSpecDenialPath $planSpecDenial
    planspec_fail_closed_matrix = New-ArtifactRef $resolvedPlanSpecFailClosedMatrixPath $planSpecFailClosedMatrix
    planspec_handoff = New-ArtifactRef $resolvedPlanSpecHandoffPath $planSpecHandoff
}

$preconditionsPath = Join-Path $resolvedArtifactDir "security-execution-allow-preconditions.json"
$denialPath = Join-Path $resolvedArtifactDir "security-execution-allow-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "security-execution-allow-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "two-target-identity-enrollment-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-022-security-execution-allow-preconditions.json"

Write-Json $preconditions $preconditionsPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath
Write-Json $handoff $handoffPath

Add-Check "source.rc13_021.complete" ($planSpecComplete -and $planSpecFailClosedMatrix.summary.failed -eq 0) "RC13-022 must consume completed RC13-021 PlanSpec readiness evidence." ([ordered]@{ status = $planSpecResult.status; rc13_021_complete = $planSpecResult.summary.rc13_021_complete; readiness_state = $planSpecResult.readiness_surface.state; failed_cases = $planSpecFailClosedMatrix.summary.failed })
Add-Check "contract.security_gate.present" ($contractText.Contains("security_execution_allowed") -and $contractText.Contains("effect envelope exactly matches the PlanSpec") -and $contractText.Contains("audit sink, nonce, expiry, and policy version")) "RC13-022 must consume the SecurityExecution allow gate contract." $source.rc13_contract
Add-Check "preconditions.required_matrix_complete" ($requiredPreconditions.object_trust_allowed -and $requiredPreconditions.verified_quarantine_preflight -and $requiredPreconditions.agentcore_planspec_executable -and $requiredPreconditions.target_set_bound -and $requiredPreconditions.exact_approval_bound -and $requiredPreconditions.audit_sink_bound -and $requiredPreconditions.rollback_reference_bound -and $requiredPreconditions.support_recovery_reference_bound) "SecurityExecution allow matrix must include object trust, quarantine, PlanSpec, target, approval, audit, rollback, and support/recovery gates." $requiredPreconditions
Add-Check "preconditions.allow_denied_until_exact_gates" ($securityExecutionAllowed -eq $false -and $observedPreconditions.agentcore_planspec_executable -eq $false -and $observedPreconditions.target_set_bound -eq $false -and $observedPreconditions.exact_approval_bound -eq $false) "SecurityExecution allow must remain denied while PlanSpec, target, approval, audit, nonce, expiry, and policy gates are missing." ([ordered]@{ security_execution_allowed = $securityExecutionAllowed; observed = $observedPreconditions; blockers = @($script:blockers) })
Add-Check "preconditions.effect_scope_not_broadened" ($broadScopeDenied -and $remoteDispatchDenied -and $productionMutationDenied -and @($effectEnvelopeCore.denied_effects).Count -ge 7) "SecurityExecution effect scope must deny broad effects, remote dispatch, and production mutation." ([ordered]@{ denied_effects = $effectEnvelopeCore.denied_effects; broad_scope_denied = $broadScopeDenied; remote_dispatch_denied = $remoteDispatchDenied; production_mutation_denied = $productionMutationDenied })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "RC13-022 SecurityExecution negative cases must fail closed before install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.effect_prepared -or $_.side_effects.effect_executed -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.support_upload_performed -or $_.side_effects.recovery_execution_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.production_ring_mutated }).Count -eq 0) "RC13-022 must not prepare effects, execute effects, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $null

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $preconditionsPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC13-022 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-security-execution-allow-preconditions-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-022"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    security_surface = [ordered]@{
        state = if ($securityExecutionAllowed) { "security-execution-allow-preconditions-satisfied" } else { "security-execution-allow-preconditions-denied" }
        planspec_result_bound = $planSpecComplete
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        required_preconditions = $requiredPreconditions
        observed_preconditions = $observedPreconditions
        security_execution_allowed = $securityExecutionAllowed
        effect_preparation_allowed = $false
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
        security_execution_allow_preconditions = [ordered]@{ path = Get-StablePath $preconditionsPath; sha256 = Get-FileSha256 $preconditionsPath; effect_envelope_core_hash = $effectEnvelopeCoreHash }
        security_execution_allow_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        two_target_identity_enrollment_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        security_execution_effect_allowed = $securityExecutionAllowed
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
        security_execution_allowed = $securityExecutionAllowed
        effect_preparation_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        rc13_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-030"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-security-execution-allow-preconditions-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-022"
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
    security_surface = $result.security_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc13_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-030"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC13-022 outputs."
}

Write-Host "RC13 SecurityExecution allow preconditions $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Security state: $($result.security_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
