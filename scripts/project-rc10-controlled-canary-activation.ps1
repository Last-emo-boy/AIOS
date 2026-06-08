param(
    [string]$ArtifactDir = ".workflow/artifacts/rc10-controlled-canary-activation",
    [string]$GeneratedAt = "",
    [string]$BindingContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc10/docs/exact-approval-canary-rollback-execution-contract.md",
    [string]$PublicationResultPath = ".workflow/artifacts/rc10-external-object-publication/result.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/result.json",
    [string]$InstallerFetchResultPath = ".workflow/artifacts/rc10-installer-quarantine-fetch/result.json",
    [string]$TargetEnrollmentResultPath = ".workflow/artifacts/rc10-two-node-canary-enrollment/result.json",
    [string]$TargetSetPath = ".workflow/artifacts/rc10-two-node-canary-enrollment/canary-target-set.json",
    [string]$TargetHandoffPath = ".workflow/artifacts/rc10-two-node-canary-enrollment/controlled-execution-handoff.json",
    [string]$BindingResultPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/result.json",
    [string]$ExactApprovalBindingPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/exact-approval-binding.json",
    [string]$PlanSpecBindingPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/agentcore-planspec-binding.json",
    [string]$SecurityDecisionPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/security-execution-decision.json",
    [string]$ExecutionBindingDenialPath = ".workflow/artifacts/rc10-exact-approval-execution-enable/execution-binding-denial.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc10-external-object-publication/external-object-descriptor-candidate.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
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
    $script:checks += [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
}

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ([string]::IsNullOrWhiteSpace($Blocker)) {
        return
    }
    $normalized = switch -Exact ($Blocker) {
        "declared-current-artifact-drift-unresolved" { "declared-current-artifact-drift-denied" }
        "two-node-canary-target-set-not-enrolled" { "target-set-not-enrolled" }
        "exact-operator-approval-pending" { "exact-operator-approval-not-granted" }
        "security-execution-approval-not-bound" { "security-execution-effect-envelope-not-bound" }
        "remote-fleet-execution-disabled" { "remote-fleet-execution-not-enabled" }
        default { $Blocker }
    }
    if ($script:blockers -notcontains $normalized) {
        $script:blockers += $normalized
    }
}

function Add-Blockers {
    param($Values)
    foreach ($value in @($Values)) {
        Add-UniqueBlocker ([string]$value)
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
        ("signing" + "-key.pem"),
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedBindingContractPath = Resolve-RepoPath $BindingContractPath
$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedInstallerFetchResultPath = Resolve-RepoPath $InstallerFetchResultPath
$resolvedTargetEnrollmentResultPath = Resolve-RepoPath $TargetEnrollmentResultPath
$resolvedTargetSetPath = Resolve-RepoPath $TargetSetPath
$resolvedTargetHandoffPath = Resolve-RepoPath $TargetHandoffPath
$resolvedBindingResultPath = Resolve-RepoPath $BindingResultPath
$resolvedExactApprovalBindingPath = Resolve-RepoPath $ExactApprovalBindingPath
$resolvedPlanSpecBindingPath = Resolve-RepoPath $PlanSpecBindingPath
$resolvedSecurityDecisionPath = Resolve-RepoPath $SecurityDecisionPath
$resolvedExecutionBindingDenialPath = Resolve-RepoPath $ExecutionBindingDenialPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$driftResult = Read-Json $resolvedDriftResultPath
$installerFetchResult = Read-Json $resolvedInstallerFetchResultPath
$targetEnrollmentResult = Read-Json $resolvedTargetEnrollmentResultPath
$targetSet = Read-Json $resolvedTargetSetPath
$targetHandoff = Read-Json $resolvedTargetHandoffPath
$bindingResult = Read-Json $resolvedBindingResultPath
$exactApprovalBinding = Read-Json $resolvedExactApprovalBindingPath
$planSpecBinding = Read-Json $resolvedPlanSpecBindingPath
$securityDecision = Read-Json $resolvedSecurityDecisionPath
$executionBindingDenial = Read-Json $resolvedExecutionBindingDenialPath
$descriptor = Read-Json $resolvedDescriptorPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportRecovery = Read-Json $resolvedSupportRecoveryPath

$releaseId = [string]$descriptor.release_id
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$publicationResultSha256 = Get-FileSha256 $resolvedPublicationResultPath
$driftResultSha256 = Get-FileSha256 $resolvedDriftResultPath
$installerFetchResultSha256 = Get-FileSha256 $resolvedInstallerFetchResultPath
$targetEnrollmentResultSha256 = Get-FileSha256 $resolvedTargetEnrollmentResultPath
$targetSetSha256 = Get-FileSha256 $resolvedTargetSetPath
$targetHandoffSha256 = Get-FileSha256 $resolvedTargetHandoffPath
$bindingResultSha256 = Get-FileSha256 $resolvedBindingResultPath
$exactApprovalBindingSha256 = Get-FileSha256 $resolvedExactApprovalBindingPath
$planSpecBindingSha256 = Get-FileSha256 $resolvedPlanSpecBindingPath
$securityDecisionSha256 = Get-FileSha256 $resolvedSecurityDecisionPath
$executionBindingDenialSha256 = Get-FileSha256 $resolvedExecutionBindingDenialPath
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportRecoverySha256 = Get-FileSha256 $resolvedSupportRecoveryPath

$publicationReady = $publicationResult.status -eq "passed" -and
    $publicationResult.publication_surface.external_object_url_published -eq $true -and
    $publicationResult.publication_surface.published_drift_zero -eq $true
$driftReady = $driftResult.status -eq "passed" -and
    $driftResult.reconciliation_surface.drift_zero -eq $true
$fetchReady = $installerFetchResult.status -eq "passed" -and $installerFetchResult.fetch_surface.fetch_allowed -eq $true
$targetSetEnrolled = $targetEnrollmentResult.status -eq "passed" -and $targetEnrollmentResult.enrollment_surface.target_set_enrolled -eq $true
$exactApprovalGranted = $bindingResult.status -eq "passed" -and $bindingResult.binding_surface.exact_approval_granted -eq $true
$exactApprovalBound = $bindingResult.status -eq "passed" -and $bindingResult.binding_surface.exact_approval_bound -eq $true
$agentCorePlanSpecBound = $bindingResult.status -eq "passed" -and $bindingResult.binding_surface.agentcore_planspec_bound -eq $true -and $planSpecBinding.executable -eq $true
$securityExecutionAllowed = $bindingResult.status -eq "passed" -and $bindingResult.binding_surface.security_execution_allowed -eq $true -and @($securityDecision.allowed_effect_set | Where-Object { [string]$_ -eq "controlled-canary-activation" }).Count -gt 0
$remoteDispatchEnabled = $bindingResult.binding_surface.remote_dispatch_enabled -eq $true -or $targetEnrollmentResult.enrollment_surface.remote_dispatch_enabled -eq $true
$compatibilityBindingPresent = $targetEnrollmentResult.enrollment_surface.compatibility_binding_present -eq $true
$rollbackBaselineBindingPresent = $targetEnrollmentResult.enrollment_surface.rollback_baseline_binding_present -eq $true
$supportRecoveryBindingPresent = $targetEnrollmentResult.enrollment_surface.support_recovery_binding_present -eq $true

Add-Blockers $publicationResult.blockers
Add-Blockers $publicationResult.publication_surface.blockers
Add-Blockers $driftResult.blockers
Add-Blockers $driftResult.reconciliation_surface.blockers
Add-Blockers $installerFetchResult.blockers
Add-Blockers $installerFetchResult.fetch_surface.blockers
Add-Blockers $targetEnrollmentResult.blockers
Add-Blockers $targetEnrollmentResult.enrollment_surface.blockers
Add-Blockers $bindingResult.blockers
Add-Blockers $bindingResult.binding_surface.blockers
Add-Blockers $executionBindingDenial.blockers

if (-not $publicationReady) {
    Add-UniqueBlocker "publication-not-published-drift-zero"
    Add-UniqueBlocker "missing-external-https-object-uri"
}
if (-not $driftReady) { Add-UniqueBlocker "drift-zero-denied" }
if (-not $fetchReady) { Add-UniqueBlocker "installer-quarantine-fetch-not-verified" }
if (-not $targetSetEnrolled) { Add-UniqueBlocker "target-set-not-enrolled" }
if ([int]$targetEnrollmentResult.enrollment_surface.enrolled_target_count -lt [int]$targetEnrollmentResult.enrollment_surface.required_minimum_target_count) { Add-UniqueBlocker "fewer-than-two-eligible-targets" }
if (-not $exactApprovalGranted -or -not $exactApprovalBound) { Add-UniqueBlocker "exact-operator-approval-not-granted" }
if (-not $agentCorePlanSpecBound) { Add-UniqueBlocker "agentcore-planspec-not-bound" }
if (-not $securityExecutionAllowed) { Add-UniqueBlocker "security-execution-effect-envelope-not-bound" }
if (-not $remoteDispatchEnabled) { Add-UniqueBlocker "remote-fleet-execution-not-enabled" }
Add-UniqueBlocker "controlled-execution-not-authorized"

$sourceTasksComplete = $publicationResult.summary.rc10_010_complete -eq $true -and
    $driftResult.summary.rc10_011_complete -eq $true -and
    $installerFetchResult.summary.rc10_012_complete -eq $true -and
    $targetEnrollmentResult.summary.rc10_020_complete -eq $true -and
    $bindingResult.summary.rc10_021_complete -eq $true

$activationAllowed = $publicationReady -and
    $driftReady -and
    $fetchReady -and
    $targetSetEnrolled -and
    $compatibilityBindingPresent -and
    $rollbackBaselineBindingPresent -and
    $supportRecoveryBindingPresent -and
    $exactApprovalGranted -and
    $exactApprovalBound -and
    $agentCorePlanSpecBound -and
    $securityExecutionAllowed -and
    $remoteDispatchEnabled

$activationState = if ($activationAllowed) { "activation-authorized" } else { "activation-denied" }
$activationAttemptId = "rc10-controlled-canary-activation-attempt"
$activationAttemptCore = [ordered]@{
    attempt_id = $activationAttemptId
    release_id = $releaseId
    payload_object_digest = [string]$descriptor.sha256
    object_descriptor_digest = $descriptorSha256
    publication_result_digest = $publicationResultSha256
    drift_result_digest = $driftResultSha256
    installer_fetch_result_digest = $installerFetchResultSha256
    target_enrollment_result_digest = $targetEnrollmentResultSha256
    target_set_digest = [string]$executionBindingDenial.target_set_digest
    exact_approval_digest = [string]$executionBindingDenial.exact_approval_digest
    agentcore_planspec_hash = [string]$executionBindingDenial.planspec_hash
    security_execution_decision_digest = [string]$executionBindingDenial.security_execution_decision_digest
    compatibility_digest = $compatibilitySha256
    rollback_baseline_digest = $rollbackBaselineSha256
    support_recovery_digest = $supportRecoverySha256
    requested_effect_set = @("controlled-canary-activation")
    expected_observation = "deny-before-side-effects-when-any-gate-missing"
    policy_version = "rc10-controlled-canary-activation-v1"
}
$activationAttemptDigest = Get-StringSha256 (($activationAttemptCore | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    activation_attempt_recorded = $true
    effect_prepared = $false
    effect_executed = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    boot_metadata_mutated = $false
    active_slot_mutated = $false
    persistent_state_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    support_upload_performed = $false
    remote_dispatch_enabled = $false
}

$gateInputs = [ordered]@{
    source_tasks_complete = $sourceTasksComplete
    external_object_descriptor_published = $publicationReady
    declared_current_artifact_drift_reconciled = $driftReady
    installer_quarantine_fetch_verified = $fetchReady
    target_set_enrolled = $targetSetEnrolled
    observed_candidate_node_count = [int]$targetEnrollmentResult.enrollment_surface.observed_candidate_node_count
    enrolled_target_count = [int]$targetEnrollmentResult.enrollment_surface.enrolled_target_count
    required_target_count = [int]$targetEnrollmentResult.enrollment_surface.required_minimum_target_count
    compatibility_binding_present = $compatibilityBindingPresent
    rollback_baseline_binding_present = $rollbackBaselineBindingPresent
    support_recovery_binding_present = $supportRecoveryBindingPresent
    exact_operator_approval_bound = $exactApprovalBound
    exact_operator_approval_granted = $exactApprovalGranted
    agentcore_planspec_bound = $agentCorePlanSpecBound
    agentcore_planspec_hash = [string]$executionBindingDenial.planspec_hash
    security_execution_approval_bound = $securityExecutionAllowed
    security_execution_allowed = $securityExecutionAllowed
    remote_fleet_execution_enabled = $remoteDispatchEnabled
}

$sourceBindings = [ordered]@{
    binding_contract_sha256 = Get-FileSha256 $resolvedBindingContractPath
    publication_result_sha256 = $publicationResultSha256
    drift_result_sha256 = $driftResultSha256
    installer_fetch_result_sha256 = $installerFetchResultSha256
    target_enrollment_result_sha256 = $targetEnrollmentResultSha256
    target_set_sha256 = $targetSetSha256
    target_handoff_sha256 = $targetHandoffSha256
    binding_result_sha256 = $bindingResultSha256
    exact_approval_binding_sha256 = $exactApprovalBindingSha256
    exact_approval_binding_digest = [string]$executionBindingDenial.exact_approval_digest
    agentcore_planspec_binding_sha256 = $planSpecBindingSha256
    agentcore_planspec_hash = [string]$executionBindingDenial.planspec_hash
    security_execution_decision_sha256 = $securityDecisionSha256
    security_execution_decision_digest = [string]$executionBindingDenial.security_execution_decision_digest
    execution_binding_denial_sha256 = $executionBindingDenialSha256
    descriptor_sha256 = $descriptorSha256
    compatibility_sha256 = $compatibilitySha256
    rollback_baseline_sha256 = $rollbackBaselineSha256
    support_recovery_sha256 = $supportRecoverySha256
}

$gateReport = [ordered]@{
    schema = "agentos.rc10-controlled-canary-activation-gate-report.v1"
    generated_at = $generatedAt
    task = "RC10-022"
    status = "activation-gates-evaluated-denied"
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_state = $activationState
    all_gates_passed = $activationAllowed
    activation_allowed = $activationAllowed
    activation_performed = $false
    gate_inputs = $gateInputs
    blockers = $script:blockers
    source_bindings = $sourceBindings
    side_effects = $sideEffects
    authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        object_storage_authority = $false
        signer_authority = $false
        frontend_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
}

$denialCases = @(
    [ordered]@{ id = "publication-not-published-drift-zero"; status = "passed"; activation_allowed = $false; reason = "No drift-zero external object publication is available for the current payload." },
    [ordered]@{ id = "missing-external-https-object-uri"; status = "passed"; activation_allowed = $false; reason = "No immutable credential-free HTTPS object URI is published for the current payload." },
    [ordered]@{ id = "drift-zero-denied"; status = "passed"; activation_allowed = $false; reason = "Declared/current drift remains nonzero, so external object trust cannot advance." },
    [ordered]@{ id = "installer-quarantine-fetch-not-verified"; status = "passed"; activation_allowed = $false; reason = "Installer fetch was denied before network and no quarantine payload was verified." },
    [ordered]@{ id = "fewer-than-two-eligible-targets"; status = "passed"; activation_allowed = $false; reason = "Only one candidate canary node is observed while two are required." },
    [ordered]@{ id = "target-set-not-enrolled"; status = "passed"; activation_allowed = $false; reason = "The canary target set is not enrolled." },
    [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; activation_allowed = $false; reason = "Exact approval remains unbound and approval_granted=false." },
    [ordered]@{ id = "agentcore-planspec-not-bound"; status = "passed"; activation_allowed = $false; reason = "The activation PlanSpec is projected but non-executable." },
    [ordered]@{ id = "security-execution-effect-envelope-not-bound"; status = "passed"; activation_allowed = $false; reason = "SecurityExecutionEngine denied the controlled-canary-activation effect." },
    [ordered]@{ id = "remote-fleet-execution-not-enabled"; status = "passed"; activation_allowed = $false; reason = "Remote fleet dispatch remains disabled." },
    [ordered]@{ id = "controlled-execution-not-authorized"; status = "passed"; activation_allowed = $false; reason = "At least one required controlled execution gate is missing." }
)

$denialEvidence = [ordered]@{
    schema = "agentos.rc10-controlled-canary-activation-denial-evidence.v1"
    generated_at = $generatedAt
    task = "RC10-022"
    status = "activation-denied"
    production_ready_claim = $false
    projection_only = $true
    denied = $true
    release_id = $releaseId
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_allowed = $false
    activation_performed = $false
    denial_cases = $denialCases
    blockers = $script:blockers
    preserved_boundaries = [ordered]@{
        exact_approval_granted = $false
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
    side_effects = $sideEffects
    source_bindings = $sourceBindings
}

$handoff = [ordered]@{
    schema = "agentos.rc10-controlled-activation-handoff.v1"
    generated_at = $generatedAt
    task = "RC10-022"
    status = "blocked-by-activation-denial"
    production_ready_claim = $false
    release_id = $releaseId
    activation_state = $activationState
    activation_attempt_id = $activationAttemptId
    activation_attempt_digest = $activationAttemptDigest
    activation_allowed = $false
    activation_performed = $false
    rollback_drill_allowed = $false
    rollback_execution_allowed = $false
    rollback_prerequisites = [ordered]@{
        controlled_canary_activation_evidence_required = $true
        controlled_canary_activation_performed = $false
        separate_rollback_approval_required = $true
        separate_rollback_planspec_required = $true
        separate_security_execution_decision_required = $true
    }
    blockers = $script:blockers
    next_task = "RC10-030"
}

$gateReportPath = Join-Path $resolvedArtifactDir "activation-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "activation-denial-evidence.json"
$handoffPath = Join-Path $resolvedArtifactDir "controlled-activation-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $gateReport $gateReportPath
Write-Json $denialEvidence $denialEvidencePath
Write-Json $handoff $handoffPath

Add-Check "source.rc10_010.publication_denied" ($publicationResult.status -eq "passed" -and $publicationResult.summary.rc10_010_complete -eq $true -and $publicationResult.publication_surface.published_drift_zero -eq $false) "RC10-022 must consume completed RC10-010 publication denial before activation." ([ordered]@{ status = $publicationResult.status; state = $publicationResult.publication_surface.state; published_drift_zero = $publicationResult.publication_surface.published_drift_zero })
Add-Check "source.rc10_011.drift_denied" ($driftResult.status -eq "passed" -and $driftResult.summary.rc10_011_complete -eq $true -and $driftResult.reconciliation_surface.state -eq "drift-zero-denied") "RC10-022 must consume completed RC10-011 drift-zero denial before activation." ([ordered]@{ status = $driftResult.status; state = $driftResult.reconciliation_surface.state; drift_count = $driftResult.summary.drift_count })
Add-Check "source.rc10_012.fetch_denied" ($installerFetchResult.status -eq "passed" -and $installerFetchResult.summary.rc10_012_complete -eq $true -and $installerFetchResult.fetch_surface.network_fetch_attempted -eq $false -and $installerFetchResult.fetch_surface.quarantine_payload_written -eq $false) "RC10-022 must consume completed RC10-012 fetch denial before activation." ([ordered]@{ status = $installerFetchResult.status; state = $installerFetchResult.fetch_surface.state; fetch_allowed = $installerFetchResult.fetch_surface.fetch_allowed })
Add-Check "source.rc10_020.target_enrollment_denied" ($targetEnrollmentResult.status -eq "passed" -and $targetEnrollmentResult.summary.rc10_020_complete -eq $true -and $targetEnrollmentResult.enrollment_surface.target_set_enrolled -eq $false) "RC10-022 must consume completed RC10-020 target-set denial before activation." ([ordered]@{ status = $targetEnrollmentResult.status; state = $targetEnrollmentResult.enrollment_surface.state; enrolled = $targetEnrollmentResult.enrollment_surface.enrolled_target_count; required = $targetEnrollmentResult.enrollment_surface.required_minimum_target_count })
Add-Check "source.rc10_021.binding_denied" ($bindingResult.status -eq "passed" -and $bindingResult.summary.rc10_021_complete -eq $true -and $bindingResult.binding_surface.state -eq "execution-binding-denied") "RC10-022 must consume completed RC10-021 execution binding denial before activation." ([ordered]@{ status = $bindingResult.status; state = $bindingResult.binding_surface.state; exact_approval_granted = $bindingResult.binding_surface.exact_approval_granted; security_execution_allowed = $bindingResult.binding_surface.security_execution_allowed })
Add-Check "activation.denied" ($activationAllowed -eq $false -and $gateReport.activation_state -eq "activation-denied" -and $denialEvidence.denied -eq $true) "Controlled canary activation must deny when any publication, drift, fetch, target, approval, PlanSpec, SecurityExecution, or remote gate is missing." ([ordered]@{ activation_allowed = $activationAllowed; blockers = $script:blockers })
Add-Check "activation.denial_cases.complete" (@($denialEvidence.denial_cases | Where-Object { $_.status -ne "passed" -or $_.activation_allowed -ne $false }).Count -eq 0 -and @($denialEvidence.denial_cases).Count -eq 11) "Activation denial evidence must cover every missing gate as a fail-closed case." ([ordered]@{ cases = @($denialEvidence.denial_cases).Count })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.effect_executed -eq $false -and $sideEffects.activation_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false) "RC10-022 must not prepare or execute activation, rollback, production mutation, support upload, or remote dispatch side effects." $sideEffects
Add-Check "handoff.rollback_blocked" ($handoff.status -eq "blocked-by-activation-denial" -and $handoff.rollback_execution_allowed -eq $false -and $handoff.next_task -eq "RC10-030") "Controlled activation handoff must move to RC10-030 while keeping rollback execution blocked." ([ordered]@{ status = $handoff.status; next_task = $handoff.next_task })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC10-022 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null

$source = [ordered]@{
    binding_contract = New-ArtifactRef $resolvedBindingContractPath
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    installer_fetch_result = New-ArtifactRef $resolvedInstallerFetchResultPath $installerFetchResult
    target_enrollment_result = New-ArtifactRef $resolvedTargetEnrollmentResultPath $targetEnrollmentResult
    target_set = New-ArtifactRef $resolvedTargetSetPath $targetSet
    target_handoff = New-ArtifactRef $resolvedTargetHandoffPath $targetHandoff
    binding_result = New-ArtifactRef $resolvedBindingResultPath $bindingResult
    exact_approval_binding = New-ArtifactRef $resolvedExactApprovalBindingPath $exactApprovalBinding
    agentcore_planspec_binding = New-ArtifactRef $resolvedPlanSpecBindingPath $planSpecBinding
    security_execution_decision = New-ArtifactRef $resolvedSecurityDecisionPath $securityDecision
    execution_binding_denial = New-ArtifactRef $resolvedExecutionBindingDenialPath $executionBindingDenial
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_recovery = New-ArtifactRef $resolvedSupportRecoveryPath $supportRecovery
}

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc10-controlled-canary-activation-result.v1"
    generated_at = $generatedAt
    task = "RC10-022"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    activation_surface = [ordered]@{
        state = $activationState
        activation_attempt_id = $activationAttemptId
        activation_attempt_digest = $activationAttemptDigest
        activation_allowed = $activationAllowed
        activation_performed = $false
        controlled_execution_authorized = $activationAllowed
        exact_approval_granted = $exactApprovalGranted
        agentcore_planspec_bound = $agentCorePlanSpecBound
        security_execution_approval_bound = $securityExecutionAllowed
        remote_dispatch_enabled = $remoteDispatchEnabled
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        blockers = $script:blockers
    }
    outputs = [ordered]@{
        activation_gate_report = [ordered]@{
            path = Get-StablePath $gateReportPath
            sha256 = Get-FileSha256 $gateReportPath
        }
        activation_denial_evidence = [ordered]@{
            path = Get-StablePath $denialEvidencePath
            sha256 = Get-FileSha256 $denialEvidencePath
        }
        controlled_activation_handoff = [ordered]@{
            path = Get-StablePath $handoffPath
            sha256 = Get-FileSha256 $handoffPath
        }
    }
    source = $source
    gate_inputs = $gateInputs
    source_bindings = $sourceBindings
    checks = $script:checks
    blockers = $script:blockers
    invariants = [ordered]@{
        local_projection_only = $true
        activation_attempt_recorded = $true
        external_payload_bytes_uploaded = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        mirror_authority = $false
        signer_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        rc10_022_complete = ($failedChecks.Count -eq 0)
        activation_state = $activationState
        activation_allowed = $activationAllowed
        activation_performed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ready_claim = $false
        next_task = "RC10-030"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC10-022 result."
}

Write-Host "RC10 controlled canary activation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Activation state: $($result.activation_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), blockers: $(@($script:blockers).Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
