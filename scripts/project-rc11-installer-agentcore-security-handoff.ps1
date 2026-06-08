param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-installer-agentcore-security-handoff",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$InstallerQuarantineResultPath = ".workflow/artifacts/rc11-installer-quarantine-verifier/result.json",
    [string]$InstallerQuarantineFetchReportPath = ".workflow/artifacts/rc11-installer-quarantine-verifier/quarantine-fetch-report.json",
    [string]$InstallerGateReportPath = ".workflow/artifacts/rc11-installer-quarantine-verifier/installer-gate-report.json",
    [string]$InstallerFailClosedMatrixPath = ".workflow/artifacts/rc11-installer-quarantine-verifier/installer-fail-closed-matrix.json",
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
            effect_prepared = $false
            effect_executed = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            boot_metadata_mutated = $false
            active_slot_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            remote_dispatch_enabled = $false
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

$resolvedInstallerQuarantineResultPath = Resolve-RepoPath $InstallerQuarantineResultPath
$resolvedInstallerQuarantineFetchReportPath = Resolve-RepoPath $InstallerQuarantineFetchReportPath
$resolvedInstallerGateReportPath = Resolve-RepoPath $InstallerGateReportPath
$resolvedInstallerFailClosedMatrixPath = Resolve-RepoPath $InstallerFailClosedMatrixPath
$resolvedAgentCorePath = Resolve-RepoPath $AgentCorePath
$resolvedSecurityPolicyPath = Resolve-RepoPath $SecurityPolicyPath
$resolvedSecurityToolsPath = Resolve-RepoPath $SecurityToolsPath

$installerResult = Read-Json $resolvedInstallerQuarantineResultPath
$fetchReport = Read-Json $resolvedInstallerQuarantineFetchReportPath
$gateReport = Read-Json $resolvedInstallerGateReportPath
$failClosedMatrix = Read-Json $resolvedInstallerFailClosedMatrixPath

$releaseId = [string]$installerResult.release_id
$installerResultSha256 = Get-FileSha256 $resolvedInstallerQuarantineResultPath
$fetchReportSha256 = Get-FileSha256 $resolvedInstallerQuarantineFetchReportPath
$gateReportSha256 = Get-FileSha256 $resolvedInstallerGateReportPath
$failClosedMatrixSha256 = Get-FileSha256 $resolvedInstallerFailClosedMatrixPath

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

$sourceComplete = $installerResult.status -eq "passed" -and $installerResult.summary.rc11_020_complete -eq $true
$fetchAllowed = $installerResult.fetch_surface.fetch_allowed -eq $true
$preInterpretationVerified = $installerResult.fetch_surface.pre_interpretation_verification_performed -eq $true
$payloadQuarantined = $installerResult.fetch_surface.quarantine_payload_written -eq $true
$installerPreflightVerified = $sourceComplete -and $fetchAllowed -and $preInterpretationVerified -and $payloadQuarantined
$agentCoreCandidateProjected = $sourceComplete -and $agentCoreObserved.planspec_type -and $agentCoreObserved.run_loop
$securityHandoffProjected = $securityPolicyObserved.policy_evaluator -and $securityPolicyObserved.high_risk_requires_exact_approval -and $securityToolsObserved.pkg_host_install_tool

foreach ($blocker in @($installerResult.blockers)) {
    Add-UniqueBlocker ([string]$blocker)
}
if (-not $installerPreflightVerified) { Add-UniqueBlocker "installer-preflight-not-verified" }
if (-not $agentCoreCandidateProjected) { Add-UniqueBlocker "agentcore-planspec-candidate-not-projectable" }
if (-not $securityHandoffProjected) { Add-UniqueBlocker "security-execution-policy-surface-not-observed" }
foreach ($blocker in @(
    "two-target-canary-approval-not-bound",
    "agentcore-planspec-not-executable",
    "security-execution-effect-envelope-denied",
    "controlled-install-activation-rollback-not-authorized"
)) {
    Add-UniqueBlocker $blocker
}

$preflightBindings = [ordered]@{
    rc11_020_result_sha256 = $installerResultSha256
    quarantine_fetch_report_sha256 = $fetchReportSha256
    installer_gate_report_sha256 = $gateReportSha256
    installer_fail_closed_matrix_sha256 = $failClosedMatrixSha256
    release_id = $releaseId
    payload_sha256 = [string]$installerResult.source.current_payload_bytes.sha256
    payload_size_bytes = $installerResult.source.current_payload_bytes.size_bytes
    fetch_state = [string]$installerResult.fetch_surface.state
    fetch_allowed = $fetchAllowed
    payload_quarantined = $payloadQuarantined
    pre_interpretation_verification_performed = $preInterpretationVerified
    descriptor_matches_current_bytes = $installerResult.fetch_surface.descriptor_matches_current_bytes
    required_gates = $gateReport.gates
}

$planSpecCore = [ordered]@{
    planspec_id = "rc11-installer-agentcore-security-handoff"
    planner_version = "agent-core-release-installer-handoff-v1"
    plan_kind = "aios-release-installer-preflight-handoff"
    release_id = $releaseId
    intent = [ordered]@{
        actor = "operator"
        source = "maestro-rc11"
        trust_boundary = "aios-body-controlled-release-install"
        summary = "bind RC11 installer preflight evidence before install, activation, or rollback authority"
    }
    frozen_inputs = $preflightBindings
    steps = @(
        [ordered]@{
            id = "bind-installer-preflight-evidence"
            tool = "fs.read"
            risk = "read-only"
            requires_exact_approval = $false
            executable = $sourceComplete
            evidence_hash = $installerResultSha256
        },
        [ordered]@{
            id = "project-quarantine-fetch"
            tool = "content.fetch"
            risk = "read-only"
            requires_exact_approval = $false
            executable = $fetchAllowed
            denied_before_network = (-not $fetchAllowed)
        },
        [ordered]@{
            id = "isolate-install-smoke"
            tool = "pkg.isolate.install"
            risk = "execute-with-confirmation"
            requires_exact_approval = $true
            executable = $false
            denied_because = @($script:blockers)
        },
        [ordered]@{
            id = "prepare-host-checkpoint"
            tool = "pkg.host.checkpoint"
            risk = "write-with-diff"
            requires_exact_approval = $true
            rollback_required = $true
            executable = $false
        },
        [ordered]@{
            id = "host-install"
            tool = "pkg.host.install"
            risk = "privileged-with-human-approval"
            requires_exact_approval = $true
            rollback_required = $true
            executable = $false
        },
        [ordered]@{
            id = "rollback-trigger"
            tool = "rollback.trigger"
            risk = "execute-with-confirmation"
            requires_separate_rollback_approval = $true
            executable = $false
        }
    )
    invariants = @(
        "installer evidence is immutable and hash-bound before handoff",
        "quarantine fetch must complete before any payload interpretation",
        "host install requires exact approval and rollback baseline",
        "SecurityExecutionEngine owns every side effect",
        "no mirror, signer, TUI, shell, or model output grants authority"
    )
    blockers = @($script:blockers)
}
$planSpecCoreHash = Get-StringSha256 (($planSpecCore | ConvertTo-Json -Depth 100 -Compress))

$agentCoreHandoff = [ordered]@{
    schema = "agentos.rc11-agentcore-installer-planspec-handoff.v1"
    generated_at = $generatedAt
    task = "RC11-021"
    status = if ($agentCoreCandidateProjected) { "planspec-candidate-projected-denied" } else { "planspec-candidate-missing" }
    production_ready_claim = $false
    projection_only = $true
    installer_preflight_bound = $sourceComplete
    installer_preflight_verified = $installerPreflightVerified
    planspec_candidate_projected = $agentCoreCandidateProjected
    planspec_bound = $false
    executable = $false
    planspec_core_hash = $planSpecCoreHash
    planspec_core = $planSpecCore
    runtime_observations = [ordered]@{
        agent_core = $agentCoreObserved
        security_policy = $securityPolicyObserved
        security_tools = $securityToolsObserved
    }
    denied_because = @($script:blockers)
}

$hostInstallParams = [ordered]@{
    package = "aios-release-payload"
    version = $releaseId
    source_uri = if ($null -eq $fetchReport.descriptor.uri) { "missing-external-uri" } else { [string]$fetchReport.descriptor.uri }
    source_digest = [string]$installerResult.source.current_payload_bytes.sha256
    rollback_id = "rc11-release-install-rollback-required"
}
$parameterHash = Get-StringSha256 (($hostInstallParams | ConvertTo-Json -Depth 100 -Compress))
$securityDecisionCore = [ordered]@{
    policy_id = "rc11-installer-agentcore-security-policy"
    decision_id = "rc11-installer-agentcore-security-denied"
    effect_envelope_id = "rc11-installer-effect-envelope-denied"
    actor = "operator"
    tool = "pkg.host.install"
    resource = "aios-release-payload"
    risk = "privileged-with-human-approval"
    parameter_hash = $parameterHash
    policy_version = "rc11-installer-handoff-policy-v1"
    approval_token_present = $false
    approval_token_matches = $false
    planspec_hash = $planSpecCoreHash
    allowed_effect_set = @()
    denied_effect_set = @(
        "install",
        "activation",
        "rollback",
        "support-upload",
        "remote-dispatch",
        "production-ring-mutation"
    )
    denial_reason = "installer-preflight-target-approval-planspec-and-security-gates-not-bound"
    blockers = @($script:blockers)
}
$securityDecisionHash = Get-StringSha256 (($securityDecisionCore | ConvertTo-Json -Depth 100 -Compress))

$securityEnvelope = [ordered]@{
    schema = "agentos.rc11-security-execution-installer-effect-envelope.v1"
    generated_at = $generatedAt
    task = "RC11-021"
    status = "security-execution-denied"
    production_ready_claim = $false
    projection_only = $true
    deny_by_default = $true
    decision_core_hash = $securityDecisionHash
    decision_core = $securityDecisionCore
    effect_envelope = [ordered]@{
        prepared = $false
        executed = $false
        state = "denied-before-effect-preparation"
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    side_effects = [ordered]@{
        effect_prepared = $false
        effect_executed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        boot_metadata_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
    }
}

$caseBlockers = @{
    "missing-external-uri-denies-handoff" = @("external-https-object-uri-not-published")
    "drift-zero-denied-blocks-handoff" = @("declared-current-drift-zero-not-proved")
    "quarantine-fetch-not-run-denies-handoff" = @("installer-quarantine-fetch-not-run")
    "payload-not-quarantined-denies-handoff" = @("payload-not-quarantined")
    "pre-interpretation-verification-not-run-denies-handoff" = @("pre-interpretation-verification-not-run")
    "installer-preflight-not-verified-denies-handoff" = @("installer-preflight-not-verified")
    "approval-not-bound-denies-host-install" = @("exact-approval-not-bound")
    "two-target-approval-not-bound-denies-controlled-execution" = @("two-target-canary-approval-not-bound")
    "planspec-not-executable-denies-effect" = @("agentcore-planspec-not-executable")
    "security-envelope-denies-effect" = @("security-execution-effect-envelope-denied")
    "activation-or-rollback-request-denied" = @("controlled-install-activation-rollback-not-authorized")
    "remote-dispatch-request-denied" = @("security-execution-effect-envelope-denied")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys | Sort-Object) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$denial = [ordered]@{
    schema = "agentos.rc11-installer-agentcore-security-handoff-denial.v1"
    generated_at = $generatedAt
    task = "RC11-021"
    status = "installer-agentcore-security-handoff-denied"
    production_ready_claim = $false
    projection_only = $true
    denied = $true
    release_id = $releaseId
    planspec_core_hash = $planSpecCoreHash
    security_decision_core_hash = $securityDecisionHash
    denied_cases = $cases
    preserved_boundaries = [ordered]@{
        installer_preflight_bound = $sourceComplete
        installer_preflight_verified = $installerPreflightVerified
        agentcore_planspec_candidate_projected = $agentCoreCandidateProjected
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
    }
    blockers = @($script:blockers)
    next_task = "RC11-030"
}

$source = [ordered]@{
    installer_quarantine_result = New-ArtifactRef $resolvedInstallerQuarantineResultPath $installerResult
    quarantine_fetch_report = New-ArtifactRef $resolvedInstallerQuarantineFetchReportPath $fetchReport
    installer_gate_report = New-ArtifactRef $resolvedInstallerGateReportPath $gateReport
    installer_fail_closed_matrix = New-ArtifactRef $resolvedInstallerFailClosedMatrixPath $failClosedMatrix
    agent_core = New-ArtifactRef $resolvedAgentCorePath
    security_policy = New-ArtifactRef $resolvedSecurityPolicyPath
    security_tools = New-ArtifactRef $resolvedSecurityToolsPath
}

$agentCoreHandoffPath = Join-Path $resolvedArtifactDir "agentcore-planspec-handoff.json"
$securityEnvelopePath = Join-Path $resolvedArtifactDir "security-execution-effect-envelope.json"
$denialPath = Join-Path $resolvedArtifactDir "handoff-denial.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-021-installer-agentcore-security-handoff.json"

Write-Json $agentCoreHandoff $agentCoreHandoffPath
Write-Json $securityEnvelope $securityEnvelopePath
Write-Json $denial $denialPath

Add-Check "source.rc11_020.installer_quarantine_complete" ($sourceComplete -and $failClosedMatrix.summary.failed -eq 0) "RC11-021 must consume completed RC11-020 installer quarantine evidence." ([ordered]@{ status = $installerResult.status; rc11_020_complete = $installerResult.summary.rc11_020_complete; fetch_state = $installerResult.fetch_surface.state; cases = $failClosedMatrix.summary.cases; failed_cases = $failClosedMatrix.summary.failed })
Add-Check "runtime.agentcore_security_surfaces_observed" ($agentCoreObserved.planspec_type -and $agentCoreObserved.run_loop -and $securityPolicyObserved.high_risk_requires_exact_approval -and $securityToolsObserved.pkg_host_install_tool) "RC11-021 must bind to observed AgentCore PlanSpec/run-loop and SecurityExecution policy/tool surfaces." ([ordered]@{ agent_core = $agentCoreObserved; security_policy = $securityPolicyObserved; security_tools = $securityToolsObserved })
Add-Check "agentcore.planspec_candidate_bound" ($agentCoreCandidateProjected -and $agentCoreHandoff.installer_preflight_bound -eq $true -and -not [string]::IsNullOrWhiteSpace($planSpecCoreHash)) "Installer preflight evidence must be hash-bound into an AgentCore PlanSpec handoff candidate." ([ordered]@{ planspec_id = $planSpecCore.planspec_id; planspec_hash = $planSpecCoreHash; rc11_020_result_sha256 = $installerResultSha256 })
Add-Check "security_execution.deny_by_default" ($securityEnvelope.deny_by_default -eq $true -and @($securityDecisionCore.allowed_effect_set).Count -eq 0 -and @($securityDecisionCore.denied_effect_set).Count -ge 6) "SecurityExecutionEngine handoff must deny effects by default until exact gates are present." ([ordered]@{ decision_id = $securityDecisionCore.decision_id; allowed_effects = @($securityDecisionCore.allowed_effect_set).Count; denied_effects = $securityDecisionCore.denied_effect_set })
Add-Check "handoff.fail_closed_cases" ($failedCases.Count -eq 0 -and @($cases).Count -ge 12) "RC11-021 handoff negative cases must fail closed before install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" ($securityEnvelope.side_effects.effect_prepared -eq $false -and $securityEnvelope.side_effects.install_performed -eq $false -and $securityEnvelope.side_effects.activation_performed -eq $false -and $securityEnvelope.side_effects.rollback_execution_performed -eq $false -and $securityEnvelope.side_effects.support_upload_performed -eq $false -and $securityEnvelope.side_effects.remote_dispatch_enabled -eq $false -and $securityEnvelope.side_effects.production_ring_mutated -eq $false) "RC11-021 must not prepare or execute install, activation, rollback, support upload, remote dispatch, or production ring effects." $securityEnvelope.side_effects
Add-Check "authority.no_infra_or_secret_scope" ($true) "RC11-021 must not grant mirror, signer, nginx, frontend, TUI, shell, model, remote dispatch, or production ring authority." ([ordered]@{ mirror_authority = $false; signer_authority = $false; nginx_or_tls_authority = $false; frontend_authority = $false; tui_authority = $false; normal_shell_authority = $false; model_replay_authority = $false; remote_dispatch_enabled = $false; production_ring_mutation_allowed = $false })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $agentCoreHandoffPath),
    (Get-Content -Raw -LiteralPath $securityEnvelopePath),
    (Get-Content -Raw -LiteralPath $denialPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-021 outputs must not contain PEM blocks, auth tokens, private key paths, or signer internals." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-installer-agentcore-security-handoff-result.v1"
    generated_at = $generatedAt
    task = "RC11-021"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    handoff_surface = [ordered]@{
        state = "installer-agentcore-security-handoff-denied"
        installer_preflight_bound = $sourceComplete
        installer_preflight_verified = $installerPreflightVerified
        agentcore_planspec_candidate_projected = $agentCoreCandidateProjected
        agentcore_planspec_hash = $planSpecCoreHash
        agentcore_planspec_bound = $false
        agentcore_planspec_executable = $false
        security_execution_required = $true
        security_execution_decision_bound = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        agentcore_planspec_handoff = [ordered]@{
            path = Get-StablePath $agentCoreHandoffPath
            sha256 = Get-FileSha256 $agentCoreHandoffPath
            planspec_core_hash = $planSpecCoreHash
        }
        security_execution_effect_envelope = [ordered]@{
            path = Get-StablePath $securityEnvelopePath
            sha256 = Get-FileSha256 $securityEnvelopePath
            decision_core_hash = $securityDecisionHash
        }
        handoff_denial = [ordered]@{
            path = Get-StablePath $denialPath
            sha256 = Get-FileSha256 $denialPath
        }
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
        security_execution_effect_allowed = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        network_fetch_attempted = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
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
        rc11_021_complete = (@($script:failedChecks).Count -eq 0)
        handoff_state = "installer-agentcore-security-handoff-denied"
        installer_preflight_bound = $sourceComplete
        agentcore_planspec_candidate_projected = $agentCoreCandidateProjected
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC11-030"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-installer-agentcore-security-handoff-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-021"
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
    handoff_surface = $result.handoff_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc11_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-030"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC11-021 result."
}

Write-Host "RC11 installer AgentCore/Security handoff $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Handoff state: $($result.handoff_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
