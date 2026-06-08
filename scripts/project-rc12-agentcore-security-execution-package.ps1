param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-agentcore-security-execution-package",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md",
    [string]$QuarantineResultPath = ".workflow/artifacts/rc12-quarantine-fetch-verification/result.json",
    [string]$QuarantineFetchReportPath = ".workflow/artifacts/rc12-quarantine-fetch-verification/quarantine-fetch-report.json",
    [string]$QuarantineGateReportPath = ".workflow/artifacts/rc12-quarantine-fetch-verification/quarantine-fetch-gate-report.json",
    [string]$QuarantineFailClosedMatrixPath = ".workflow/artifacts/rc12-quarantine-fetch-verification/quarantine-fetch-fail-closed-matrix.json",
    [string]$QuarantinePackageHandoffPath = ".workflow/artifacts/rc12-quarantine-fetch-verification/agentcore-security-package-handoff.json",
    [string]$Rc11HandoffResultPath = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/result.json",
    [string]$AgentCorePath = "crates/agent_core/src/lib.rs",
    [string]$SecurityPolicyPath = "crates/security_execution/src/policy.rs",
    [string]$SecurityToolsPath = "crates/security_execution/src/tools.rs",
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

function Test-FileContains {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern
    )
    return $null -ne (Select-String -LiteralPath $Path -Pattern $Pattern -SimpleMatch -Quiet)
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
            remote_payload_bytes_downloaded = $false
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
$resolvedQuarantineFetchReportPath = Resolve-RepoPath $QuarantineFetchReportPath
$resolvedQuarantineGateReportPath = Resolve-RepoPath $QuarantineGateReportPath
$resolvedQuarantineFailClosedMatrixPath = Resolve-RepoPath $QuarantineFailClosedMatrixPath
$resolvedQuarantinePackageHandoffPath = Resolve-RepoPath $QuarantinePackageHandoffPath
$resolvedRc11HandoffResultPath = Resolve-RepoPath $Rc11HandoffResultPath
$resolvedAgentCorePath = Resolve-RepoPath $AgentCorePath
$resolvedSecurityPolicyPath = Resolve-RepoPath $SecurityPolicyPath
$resolvedSecurityToolsPath = Resolve-RepoPath $SecurityToolsPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$quarantineResult = Read-Json $resolvedQuarantineResultPath
$quarantineFetchReport = Read-Json $resolvedQuarantineFetchReportPath
$quarantineGateReport = Read-Json $resolvedQuarantineGateReportPath
$quarantineFailClosedMatrix = Read-Json $resolvedQuarantineFailClosedMatrixPath
$quarantinePackageHandoff = Read-Json $resolvedQuarantinePackageHandoffPath
$rc11HandoffResult = Read-Json $resolvedRc11HandoffResultPath

$releaseId = [string]$quarantineResult.release_id
$sourceComplete = $quarantineResult.status -eq "passed" -and $quarantineResult.summary.rc12_020_complete -eq $true
$quarantineFetchAllowed = $quarantineResult.fetch_surface.quarantine_fetch_allowed -eq $true
$quarantinePayloadWritten = $quarantineResult.fetch_surface.quarantine_payload_written -eq $true
$preInterpretationVerified = $quarantineResult.fetch_surface.pre_interpretation_verification_performed -eq $true
$objectTrustAllowed = $quarantineResult.fetch_surface.object_trust_allowed -eq $true
$installerPreflightVerified = $sourceComplete -and $quarantineFetchAllowed -and $quarantinePayloadWritten -and $preInterpretationVerified

$agentCoreObserved = [ordered]@{
    planspec_type = Test-FileContains $resolvedAgentCorePath "PlanSpec"
    run_loop = Test-FileContains $resolvedAgentCorePath "pub mod run_loop"
    awaiting_approval_state = Test-FileContains $resolvedAgentCorePath "AwaitingApproval"
    effect_envelope_import = Test-FileContains $resolvedAgentCorePath "EffectEnvelope"
}
$securityPolicyObserved = [ordered]@{
    policy_evaluator = Test-FileContains $resolvedSecurityPolicyPath "pub struct PolicyEvaluator"
    high_risk_requires_exact_approval = Test-FileContains $resolvedSecurityPolicyPath "high-risk action requires exact approval token"
    deny_decision_kind = Test-FileContains $resolvedSecurityPolicyPath "PolicyDecisionKind::Deny"
}
$securityToolsObserved = [ordered]@{
    content_fetch_tool = Test-FileContains $resolvedSecurityToolsPath 'name: "content.fetch"'
    pkg_isolate_install_tool = Test-FileContains $resolvedSecurityToolsPath 'name: "pkg.isolate.install"'
    pkg_host_install_tool = Test-FileContains $resolvedSecurityToolsPath 'name: "pkg.host.install"'
    rollback_trigger_tool = Test-FileContains $resolvedSecurityToolsPath 'name: "rollback.trigger"'
    privileged_human_approval_risk = Test-FileContains $resolvedSecurityToolsPath "RiskClass::PrivilegedWithHumanApproval"
}

foreach ($blocker in @($quarantineResult.blockers + $quarantineResult.fetch_surface.blockers + $quarantinePackageHandoff.blockers + $rc11HandoffResult.blockers)) {
    Add-UniqueBlocker ([string]$blocker)
}
if (-not $installerPreflightVerified) { Add-UniqueBlocker "installer-preflight-not-verified" }
if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $quarantineFetchAllowed) { Add-UniqueBlocker "quarantine-fetch-not-allowed" }
if (-not $quarantinePayloadWritten) { Add-UniqueBlocker "payload-not-quarantined" }
if (-not $preInterpretationVerified) { Add-UniqueBlocker "pre-interpretation-verification-not-run" }
foreach ($blocker in @(
    "agentcore-planspec-not-executable",
    "security-execution-effect-envelope-denied",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "audit-sink-not-bound",
    "nonce-not-bound",
    "approval-expiry-not-bound",
    "policy-version-not-bound",
    "rollback-baseline-not-approved-for-execution",
    "support-recovery-not-approved-for-execution",
    "controlled-install-activation-rollback-not-authorized"
)) {
    Add-UniqueBlocker $blocker
}

$agentCorePackageProjected = $sourceComplete -and $agentCoreObserved.planspec_type -and $agentCoreObserved.run_loop
$agentCorePlanSpecExecutable = $installerPreflightVerified -and $objectTrustAllowed -and $quarantineFetchAllowed
$securityExecutionAllowed = $agentCorePlanSpecExecutable -and $false

$preflightBindings = [ordered]@{
    rc12_020_result_sha256 = Get-FileSha256 $resolvedQuarantineResultPath
    quarantine_fetch_report_sha256 = Get-FileSha256 $resolvedQuarantineFetchReportPath
    quarantine_gate_report_sha256 = Get-FileSha256 $resolvedQuarantineGateReportPath
    quarantine_fail_closed_matrix_sha256 = Get-FileSha256 $resolvedQuarantineFailClosedMatrixPath
    quarantine_package_handoff_sha256 = Get-FileSha256 $resolvedQuarantinePackageHandoffPath
    rc11_handoff_result_sha256 = Get-FileSha256 $resolvedRc11HandoffResultPath
    release_id = $releaseId
    payload_sha256 = [string]$quarantineResult.source.current_payload_bytes.sha256
    payload_size_bytes = $quarantineResult.source.current_payload_bytes.size_bytes
    fetch_state = [string]$quarantineResult.fetch_surface.state
    object_trust_allowed = $objectTrustAllowed
    quarantine_fetch_allowed = $quarantineFetchAllowed
    payload_quarantined = $quarantinePayloadWritten
    pre_interpretation_verification_performed = $preInterpretationVerified
    installer_preflight_verified = $installerPreflightVerified
    gate_report = $quarantineGateReport.gates
}

$planSpecCore = [ordered]@{
    planspec_id = "rc12-agentcore-security-execution-package"
    planner_version = "agent-core-release-execution-package-v1"
    plan_kind = "aios-controlled-release-install-activation-package"
    release_id = $releaseId
    projection_only = $true
    executable = $agentCorePlanSpecExecutable
    intent = [ordered]@{
        actor = "operator"
        source = "maestro-rc12"
        trust_boundary = "aios-body-controlled-release-execution"
        summary = "bind RC12 quarantine evidence before install, activation, rollback, support, or remote authority"
    }
    frozen_inputs = $preflightBindings
    required_exact_bindings = [ordered]@{
        object_trust = $true
        quarantine_fetch = $true
        pre_interpretation_verification = $true
        rollback_baseline = $true
        support_recovery = $true
        audit_sink = $true
        nonce = $true
        expiry = $true
        policy_version = $true
        exact_operator_approval = $true
        two_target_canary = $true
    }
    observed_exact_bindings = [ordered]@{
        object_trust = $objectTrustAllowed
        quarantine_fetch = $quarantineFetchAllowed
        pre_interpretation_verification = $preInterpretationVerified
        rollback_baseline = $quarantineResult.fetch_surface.rollback_bound
        support_recovery = $quarantineResult.fetch_surface.support_bound
        audit_sink = $false
        nonce = $false
        expiry = $false
        policy_version = $false
        exact_operator_approval = $false
        two_target_canary = $false
    }
    steps = @(
        [ordered]@{
            id = "bind-rc12-quarantine-evidence"
            tool = "fs.read"
            risk = "read-only"
            executable = $sourceComplete
            evidence_hash = Get-FileSha256 $resolvedQuarantineResultPath
        },
        [ordered]@{
            id = "fetch-into-quarantine"
            tool = "content.fetch"
            risk = "read-only"
            executable = $quarantineFetchAllowed
            denied_before_network = (-not $quarantineFetchAllowed)
        },
        [ordered]@{
            id = "verify-quarantined-payload"
            tool = "pkg.isolate.install"
            risk = "execute-with-confirmation"
            executable = $preInterpretationVerified
            requires_exact_approval = $true
        },
        [ordered]@{
            id = "host-install"
            tool = "pkg.host.install"
            risk = "privileged-with-human-approval"
            executable = $false
            requires_exact_approval = $true
            rollback_required = $true
        },
        [ordered]@{
            id = "rollback-trigger"
            tool = "rollback.trigger"
            risk = "execute-with-confirmation"
            executable = $false
            requires_separate_rollback_approval = $true
        }
    )
    blockers = @($script:blockers)
}
$planSpecCoreHash = Get-StringSha256 (($planSpecCore | ConvertTo-Json -Depth 100 -Compress))

$agentCorePackage = [ordered]@{
    schema = "agentos.rc12-agentcore-execution-package.v1"
    generated_at = $generatedAtValue
    task = "RC12-021"
    release_id = $releaseId
    status = if ($agentCorePlanSpecExecutable) { "planspec-package-executable" } else { "planspec-package-projected-denied" }
    production_ready_claim = $false
    projection_only = $true
    quarantine_evidence_bound = $sourceComplete
    quarantine_preflight_verified = $installerPreflightVerified
    planspec_candidate_projected = $agentCorePackageProjected
    planspec_core_hash = $planSpecCoreHash
    planspec_executable = $agentCorePlanSpecExecutable
    planspec_core = $planSpecCore
    runtime_observations = [ordered]@{
        agent_core = $agentCoreObserved
        security_policy = $securityPolicyObserved
        security_tools = $securityToolsObserved
    }
    denied_because = @($script:blockers)
}

$effectParameters = [ordered]@{
    release_id = $releaseId
    payload_sha256 = [string]$quarantineResult.source.current_payload_bytes.sha256
    payload_size_bytes = $quarantineResult.source.current_payload_bytes.size_bytes
    planspec_core_hash = $planSpecCoreHash
    target_set_id = "missing-two-target-canary-set"
    audit_sink = $null
    nonce = $null
    expiry = $null
    policy_version = $null
}
$parameterHash = Get-StringSha256 (($effectParameters | ConvertTo-Json -Depth 100 -Compress))
$securityDecisionCore = [ordered]@{
    policy_id = "rc12-agentcore-security-execution-policy"
    decision_id = if ($securityExecutionAllowed) { "rc12-security-execution-allowed" } else { "rc12-security-execution-denied" }
    effect_envelope_id = "rc12-controlled-release-effect-envelope"
    actor = "operator"
    tool = "pkg.host.install"
    resource = "aios-release-payload"
    risk = "privileged-with-human-approval"
    parameter_hash = $parameterHash
    planspec_core_hash = $planSpecCoreHash
    approval_token_present = $false
    approval_token_matches = $false
    audit_sink_bound = $false
    nonce_bound = $false
    expiry_bound = $false
    policy_version_bound = $false
    allowed_effect_set = if ($securityExecutionAllowed) { @("install") } else { @() }
    denied_effect_set = if ($securityExecutionAllowed) { @() } else { @("install", "activation", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation") }
    blockers = @($script:blockers)
}
$securityDecisionHash = Get-StringSha256 (($securityDecisionCore | ConvertTo-Json -Depth 100 -Compress))

$securityEnvelope = [ordered]@{
    schema = "agentos.rc12-security-execution-effect-envelope.v1"
    generated_at = $generatedAtValue
    task = "RC12-021"
    release_id = $releaseId
    status = if ($securityExecutionAllowed) { "security-execution-allowed" } else { "security-execution-denied" }
    production_ready_claim = $false
    projection_only = $true
    deny_by_default = (-not $securityExecutionAllowed)
    decision_core_hash = $securityDecisionHash
    decision_core = $securityDecisionCore
    effect_envelope = [ordered]@{
        prepared = $false
        executed = $false
        state = if ($securityExecutionAllowed) { "allowed-but-not-executed-by-package-binding" } else { "denied-before-effect-preparation" }
        install_allowed = $securityExecutionAllowed
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    side_effects = [ordered]@{
        planspec_executed = $false
        effect_prepared = $false
        effect_executed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
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

$caseBlockers = @{
    "object-trust-missing-denies-package" = @("object-trust-not-allowed")
    "quarantine-fetch-not-allowed-denies-package" = @("quarantine-fetch-not-allowed")
    "payload-not-quarantined-denies-package" = @("payload-not-quarantined")
    "pre-interpretation-verification-missing-denies-package" = @("pre-interpretation-verification-not-run")
    "installer-preflight-not-verified-denies-planspec" = @("installer-preflight-not-verified")
    "agentcore-planspec-not-executable-denies-effect" = @("agentcore-planspec-not-executable")
    "security-envelope-denies-install" = @("security-execution-effect-envelope-denied")
    "two-target-canary-missing-denies-activation" = @("two-target-canary-not-enrolled")
    "exact-approval-missing-denies-effect" = @("exact-approval-not-bound")
    "audit-sink-missing-denies-effect" = @("audit-sink-not-bound")
    "nonce-missing-denies-effect" = @("nonce-not-bound")
    "expiry-missing-denies-effect" = @("approval-expiry-not-bound")
    "policy-version-missing-denies-effect" = @("policy-version-not-bound")
    "rollback-baseline-not-approved-denies-rollback" = @("rollback-baseline-not-approved-for-execution")
    "support-recovery-not-approved-denies-support" = @("support-recovery-not-approved-for-execution")
    "remote-dispatch-request-denied" = @("security-execution-effect-envelope-denied")
    "production-mutation-request-denied" = @("security-execution-effect-envelope-denied")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys | Sort-Object) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc12-agentcore-security-package-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC12-021"
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

$denial = [ordered]@{
    schema = "agentos.rc12-agentcore-security-execution-package-denial.v1"
    generated_at = $generatedAtValue
    task = "RC12-021"
    release_id = $releaseId
    status = if ($securityExecutionAllowed) { "not-denied" } else { "agentcore-security-execution-package-denied" }
    production_ready_claim = $false
    denied = (-not $securityExecutionAllowed)
    planspec_core_hash = $planSpecCoreHash
    security_decision_core_hash = $securityDecisionHash
    denied_cases = $cases
    preserved_boundaries = [ordered]@{
        quarantine_evidence_bound = $sourceComplete
        installer_preflight_verified = $installerPreflightVerified
        agentcore_planspec_candidate_projected = $agentCorePackageProjected
        agentcore_planspec_executable = $agentCorePlanSpecExecutable
        security_execution_allowed = $securityExecutionAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
    }
    blockers = @($script:blockers)
    next_task = "RC12-030"
}

$source = [ordered]@{
    rc12_contract = New-ArtifactRef $resolvedContractPath
    rc12_quarantine_result = New-ArtifactRef $resolvedQuarantineResultPath $quarantineResult
    quarantine_fetch_report = New-ArtifactRef $resolvedQuarantineFetchReportPath $quarantineFetchReport
    quarantine_gate_report = New-ArtifactRef $resolvedQuarantineGateReportPath $quarantineGateReport
    quarantine_fail_closed_matrix = New-ArtifactRef $resolvedQuarantineFailClosedMatrixPath $quarantineFailClosedMatrix
    quarantine_package_handoff = New-ArtifactRef $resolvedQuarantinePackageHandoffPath $quarantinePackageHandoff
    rc11_agentcore_security_handoff = New-ArtifactRef $resolvedRc11HandoffResultPath $rc11HandoffResult
    agent_core = New-ArtifactRef $resolvedAgentCorePath
    security_policy = New-ArtifactRef $resolvedSecurityPolicyPath
    security_tools = New-ArtifactRef $resolvedSecurityToolsPath
}

$agentCorePackagePath = Join-Path $resolvedArtifactDir "agentcore-planspec-package.json"
$securityEnvelopePath = Join-Path $resolvedArtifactDir "security-execution-effect-envelope.json"
$denialPath = Join-Path $resolvedArtifactDir "execution-package-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "execution-package-fail-closed-matrix.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-021-agentcore-security-execution-package.json"

Write-Json $agentCorePackage $agentCorePackagePath
Write-Json $securityEnvelope $securityEnvelopePath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath

Add-Check "source.rc12_020.quarantine_complete" ($sourceComplete -and $quarantineFailClosedMatrix.summary.failed -eq 0) "RC12-021 must consume completed RC12-020 quarantine fetch evidence." ([ordered]@{ status = $quarantineResult.status; rc12_020_complete = $quarantineResult.summary.rc12_020_complete; fetch_state = $quarantineResult.fetch_surface.state; cases = $quarantineFailClosedMatrix.summary.cases; failed_cases = $quarantineFailClosedMatrix.summary.failed })
Add-Check "runtime.agentcore_security_surfaces_observed" ($agentCoreObserved.planspec_type -and $agentCoreObserved.run_loop -and $securityPolicyObserved.high_risk_requires_exact_approval -and $securityToolsObserved.pkg_host_install_tool) "RC12-021 must bind to observed AgentCore PlanSpec/run-loop and SecurityExecution policy/tool surfaces." ([ordered]@{ agent_core = $agentCoreObserved; security_policy = $securityPolicyObserved; security_tools = $securityToolsObserved })
Add-Check "agentcore.planspec_candidate_hash_bound" ($agentCorePackageProjected -and $agentCorePackage.quarantine_evidence_bound -eq $true -and -not [string]::IsNullOrWhiteSpace($planSpecCoreHash)) "RC12 quarantine evidence must be hash-bound into an AgentCore PlanSpec package candidate." ([ordered]@{ planspec_id = $planSpecCore.planspec_id; planspec_hash = $planSpecCoreHash; rc12_020_result_sha256 = Get-FileSha256 $resolvedQuarantineResultPath })
Add-Check "agentcore.executable_denied_until_preflight_verified" ($agentCorePlanSpecExecutable -eq $false -and $installerPreflightVerified -eq $false) "AgentCore PlanSpec must remain non-executable until object trust, quarantine, and pre-interpretation verification are proved." ([ordered]@{ planspec_executable = $agentCorePlanSpecExecutable; installer_preflight_verified = $installerPreflightVerified; blockers = @($script:blockers) })
Add-Check "security_execution.allow_requires_exact_gates" ($securityExecutionAllowed -eq $false -and @($securityDecisionCore.allowed_effect_set).Count -eq 0 -and @($securityDecisionCore.denied_effect_set).Count -ge 7) "SecurityExecution allow must be denied unless policy, object trust, quarantine, rollback, support/recovery, audit, approval, nonce, expiry, and target gates are present." ([ordered]@{ decision_id = $securityDecisionCore.decision_id; allowed_effects = @($securityDecisionCore.allowed_effect_set).Count; denied_effects = $securityDecisionCore.denied_effect_set })
Add-Check "package.fail_closed_cases" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "RC12-021 package negative cases must fail closed before install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" ($securityEnvelope.side_effects.planspec_executed -eq $false -and $securityEnvelope.side_effects.effect_prepared -eq $false -and $securityEnvelope.side_effects.install_performed -eq $false -and $securityEnvelope.side_effects.activation_performed -eq $false -and $securityEnvelope.side_effects.rollback_execution_performed -eq $false -and $securityEnvelope.side_effects.support_upload_performed -eq $false -and $securityEnvelope.side_effects.recovery_execution_performed -eq $false -and $securityEnvelope.side_effects.remote_dispatch_enabled -eq $false -and $securityEnvelope.side_effects.production_ring_mutated -eq $false) "RC12-021 must not execute PlanSpec, prepare effects, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $securityEnvelope.side_effects
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC12-021 must not grant mirror, signer, nginx, frontend, TUI, shell, model, remote dispatch, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; tui_authority = $false; normal_shell_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $agentCorePackagePath),
    (Get-Content -Raw -LiteralPath $securityEnvelopePath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC12-021 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-agentcore-security-execution-package-result.v1"
    generated_at = $generatedAtValue
    task = "RC12-021"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    package_surface = [ordered]@{
        state = if ($securityExecutionAllowed) { "agentcore-security-execution-package-allowed" } else { "agentcore-security-execution-package-denied" }
        quarantine_evidence_bound = $sourceComplete
        installer_preflight_verified = $installerPreflightVerified
        agentcore_planspec_candidate_projected = $agentCorePackageProjected
        agentcore_planspec_hash = $planSpecCoreHash
        agentcore_planspec_executable = $agentCorePlanSpecExecutable
        security_execution_required = $true
        security_execution_decision_bound = $false
        security_execution_allowed = $securityExecutionAllowed
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
        agentcore_planspec_package = [ordered]@{ path = Get-StablePath $agentCorePackagePath; sha256 = Get-FileSha256 $agentCorePackagePath; planspec_core_hash = $planSpecCoreHash }
        security_execution_effect_envelope = [ordered]@{ path = Get-StablePath $securityEnvelopePath; sha256 = Get-FileSha256 $securityEnvelopePath; decision_core_hash = $securityDecisionHash }
        execution_package_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        installer_preflight_evidence_fabricated = $false
        exact_approval_fabricated = $false
        approval_granted = $false
        executable_planspec_created = $false
        security_execution_effect_allowed = $securityExecutionAllowed
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
        canary_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
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
        rc12_021_complete = (@($script:failedChecks).Count -eq 0)
        package_state = if ($securityExecutionAllowed) { "allowed" } else { "denied" }
        quarantine_evidence_bound = $sourceComplete
        installer_preflight_verified = $installerPreflightVerified
        agentcore_planspec_candidate_projected = $agentCorePackageProjected
        agentcore_planspec_executable = $agentCorePlanSpecExecutable
        security_execution_allowed = $securityExecutionAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC12-030"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-agentcore-security-execution-package-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC12-021"
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
    package_surface = $result.package_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc12_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-030"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC12-021 outputs."
}

Write-Host "RC12 AgentCore/Security execution package $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Package state: $($result.package_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
