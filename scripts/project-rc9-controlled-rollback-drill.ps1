param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-controlled-rollback-drill",
    [string]$GeneratedAt = "",
    [string]$BindingContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/controlled-execution-binding-contract.md",
    [string]$PublicationResultPath = ".workflow/artifacts/rc9-external-object-publication/result.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/result.json",
    [string]$InstallerFetchResultPath = ".workflow/artifacts/rc9-external-object-installer-fetch/result.json",
    [string]$TargetEnrollmentResultPath = ".workflow/artifacts/rc9-two-node-canary-enrollment/result.json",
    [string]$BindingResultPath = ".workflow/artifacts/rc9-exact-approval-execution-binding/result.json",
    [string]$ActivationResultPath = ".workflow/artifacts/rc9-controlled-canary-activation/result.json",
    [string]$ActivationGateReportPath = ".workflow/artifacts/rc9-controlled-canary-activation/activation-gate-report.json",
    [string]$ActivationDenialEvidencePath = ".workflow/artifacts/rc9-controlled-canary-activation/activation-denial-evidence.json",
    [string]$ActivationHandoffPath = ".workflow/artifacts/rc9-controlled-canary-activation/controlled-activation-handoff.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
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
        "agentcore-planspec-not-bound" { "AgentCore-PlanSpec-not-bound" }
        "security-execution-approval-not-bound" { "SecurityExecutionEngine-approval-not-bound" }
        "remote-fleet-execution-disabled" { "remote-fleet-execution-not-enabled" }
        "canary-activation-not-performed" { "controlled-canary-activation-not-performed" }
        "canary-activation-evidence-not-executed" { "controlled-canary-activation-not-performed" }
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
$resolvedBindingResultPath = Resolve-RepoPath $BindingResultPath
$resolvedActivationResultPath = Resolve-RepoPath $ActivationResultPath
$resolvedActivationGateReportPath = Resolve-RepoPath $ActivationGateReportPath
$resolvedActivationDenialEvidencePath = Resolve-RepoPath $ActivationDenialEvidencePath
$resolvedActivationHandoffPath = Resolve-RepoPath $ActivationHandoffPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$driftResult = Read-Json $resolvedDriftResultPath
$installerFetchResult = Read-Json $resolvedInstallerFetchResultPath
$targetEnrollmentResult = Read-Json $resolvedTargetEnrollmentResultPath
$bindingResult = Read-Json $resolvedBindingResultPath
$activationResult = Read-Json $resolvedActivationResultPath
$activationGateReport = Read-Json $resolvedActivationGateReportPath
$activationDenialEvidence = Read-Json $resolvedActivationDenialEvidencePath
$activationHandoff = Read-Json $resolvedActivationHandoffPath
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
$bindingResultSha256 = Get-FileSha256 $resolvedBindingResultPath
$activationResultSha256 = Get-FileSha256 $resolvedActivationResultPath
$activationGateReportSha256 = Get-FileSha256 $resolvedActivationGateReportPath
$activationDenialEvidenceSha256 = Get-FileSha256 $resolvedActivationDenialEvidencePath
$activationHandoffSha256 = Get-FileSha256 $resolvedActivationHandoffPath
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportRecoverySha256 = Get-FileSha256 $resolvedSupportRecoveryPath

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
Add-Blockers $activationResult.blockers
Add-Blockers $activationResult.activation_surface.blockers
Add-Blockers $activationHandoff.blockers

$publicationReady = $publicationResult.status -eq "passed" -and $publicationResult.publication_surface.external_object_url_published -eq $true
$driftReady = $driftResult.status -eq "passed" -and $driftResult.reconciliation_surface.state -eq "reconciled-current-artifact"
$fetchReady = $installerFetchResult.status -eq "passed" -and $installerFetchResult.fetch_surface.fetch_allowed -eq $true
$targetSetEnrolled = $targetEnrollmentResult.status -eq "passed" -and $targetEnrollmentResult.enrollment_surface.target_set_enrolled -eq $true
$activationPerformed = $activationResult.status -eq "passed" -and $activationResult.activation_surface.activation_performed -eq $true
$activationEvidenceReady = $activationResult.status -eq "passed" -and $activationResult.summary.rc9_022_complete -eq $true
$rollbackBaselinePresent = -not [string]::IsNullOrWhiteSpace([string]$rollbackBaseline.rollback_baseline_sha256)
$supportRecoveryPresent = $supportRecovery.status -eq "hosted-metadata-only" -and $supportRecovery.rollback_execution_allowed -eq $false
$rollbackApprovalGranted = $false
$rollbackPlanSpecBound = $false
$rollbackSecurityExecutionAllowed = $false
$remoteDispatchEnabled = $activationResult.activation_surface.remote_dispatch_enabled -eq $true -or $targetEnrollmentResult.enrollment_surface.remote_dispatch_enabled -eq $true

if (-not $publicationReady) { Add-UniqueBlocker "external-https-object-uri-not-published" }
if (-not $driftReady) { Add-UniqueBlocker "declared-current-artifact-drift-denied" }
if (-not $fetchReady) { Add-UniqueBlocker "installer-quarantine-fetch-not-run" }
if (-not $targetSetEnrolled) { Add-UniqueBlocker "target-set-not-enrolled" }
if ([int]$targetEnrollmentResult.enrollment_surface.enrolled_target_count -lt [int]$targetEnrollmentResult.enrollment_surface.required_minimum_target_count) { Add-UniqueBlocker "two-or-more-enrolled-canary-target-nodes-required" }
if ($bindingResult.binding_surface.exact_approval_granted -ne $true) { Add-UniqueBlocker "exact-operator-approval-not-granted" }
if ($bindingResult.binding_surface.agentcore_planspec_bound -ne $true) { Add-UniqueBlocker "AgentCore-PlanSpec-not-bound" }
if ($bindingResult.binding_surface.security_execution_allowed -ne $true) { Add-UniqueBlocker "SecurityExecutionEngine-approval-not-bound" }
if (-not $remoteDispatchEnabled) { Add-UniqueBlocker "remote-fleet-execution-not-enabled" }
if (-not $activationPerformed) { Add-UniqueBlocker "controlled-canary-activation-not-performed" }
if (-not $rollbackApprovalGranted) { Add-UniqueBlocker "rollback-exact-operator-approval-not-granted" }
if (-not $rollbackPlanSpecBound) { Add-UniqueBlocker "AgentCore-rollback-PlanSpec-not-bound" }
if (-not $rollbackSecurityExecutionAllowed) { Add-UniqueBlocker "SecurityExecutionEngine-rollback-approval-not-bound" }
Add-UniqueBlocker "rollback-execution-not-authorized"

$sourceTasksComplete = $publicationResult.summary.rc9_010_complete -eq $true -and
    $driftResult.summary.rc9_011_complete -eq $true -and
    $installerFetchResult.summary.rc9_012_complete -eq $true -and
    $targetEnrollmentResult.summary.rc9_020_complete -eq $true -and
    $bindingResult.summary.rc9_021_complete -eq $true -and
    $activationResult.summary.rc9_022_complete -eq $true

$rollbackExecutionAllowed = $publicationReady -and
    $driftReady -and
    $fetchReady -and
    $targetSetEnrolled -and
    $activationPerformed -and
    $rollbackBaselinePresent -and
    $supportRecoveryPresent -and
    $rollbackApprovalGranted -and
    $rollbackPlanSpecBound -and
    $rollbackSecurityExecutionAllowed -and
    $remoteDispatchEnabled

$rollbackState = if ($rollbackExecutionAllowed) { "rollback-authorized" } else { "rollback-denied" }
$rollbackAttemptId = "rc9-controlled-rollback-drill-attempt"
$rollbackPlanSpecId = "rc9-controlled-rollback-drill-planspec-required"
$rollbackPolicyId = "rc9-controlled-rollback-drill-policy"
$rollbackDecisionId = "rc9-controlled-rollback-drill-decision-denied"

$sourceBindings = [ordered]@{
    binding_contract_sha256 = Get-FileSha256 $resolvedBindingContractPath
    publication_result_sha256 = $publicationResultSha256
    drift_result_sha256 = $driftResultSha256
    installer_fetch_result_sha256 = $installerFetchResultSha256
    target_enrollment_result_sha256 = $targetEnrollmentResultSha256
    binding_result_sha256 = $bindingResultSha256
    activation_result_sha256 = $activationResultSha256
    activation_gate_report_sha256 = $activationGateReportSha256
    activation_denial_evidence_sha256 = $activationDenialEvidenceSha256
    activation_handoff_sha256 = $activationHandoffSha256
    activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    descriptor_sha256 = $descriptorSha256
    compatibility_sha256 = $compatibilitySha256
    rollback_baseline_sha256 = $rollbackBaselineSha256
    support_recovery_sha256 = $supportRecoverySha256
}

$rollbackPlanSpecCore = [ordered]@{
    planspec_id = $rollbackPlanSpecId
    plan_kind = "controlled-rollback-drill"
    release_id = $releaseId
    payload_object_digest = [string]$descriptor.sha256
    object_descriptor_digest = $descriptorSha256
    external_object_publication_digest = $publicationResultSha256
    declared_current_reconciliation_digest = $driftResultSha256
    target_enrollment_result_digest = $targetEnrollmentResultSha256
    activation_attempt_digest = [string]$activationResult.activation_surface.activation_attempt_digest
    activation_result_digest = $activationResultSha256
    activation_performed = $activationPerformed
    previous_active_artifact_set_digest = [string]$rollbackBaseline.previous_active_artifact_set_sha256
    activated_artifact_set_digest = "not-activated"
    rollback_baseline_digest = [string]$rollbackBaseline.rollback_baseline_sha256
    rollback_target_set_digest = "not-bound"
    exact_rollback_approval_digest = "not-bound"
    security_execution_rollback_decision_digest = "not-bound"
    support_recovery_digest = $supportRecoverySha256
    expected_observations = @(
        "rollback-denied-while-canary-activation-not-performed",
        "rollback-denied-while-rollback-approval-not-bound",
        "no-side-effects-observed"
    )
    audit_journal_path = "required-before-execution"
    expiry = "required-before-execution"
    policy_version = "rc9-controlled-rollback-drill-v1"
}
$rollbackPlanSpecHash = Get-StringSha256 (($rollbackPlanSpecCore | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    rollback_attempt_recorded = $true
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
    activation_evidence_ready = $activationEvidenceReady
    canary_activation_allowed = $activationResult.activation_surface.activation_allowed
    canary_activation_performed = $activationPerformed
    rollback_baseline_present = $rollbackBaselinePresent
    rollback_baseline_execution_allowed = $rollbackBaseline.execution_status.rollback_execution_allowed
    support_recovery_binding_present = $supportRecoveryPresent
    exact_activation_approval_granted = $bindingResult.binding_surface.exact_approval_granted
    rollback_exact_operator_approval_granted = $rollbackApprovalGranted
    agentcore_activation_planspec_bound = $bindingResult.binding_surface.agentcore_planspec_bound
    agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
    agentcore_rollback_planspec_hash = $rollbackPlanSpecHash
    security_execution_activation_allowed = $bindingResult.binding_surface.security_execution_allowed
    security_execution_rollback_approval_bound = $rollbackSecurityExecutionAllowed
    remote_fleet_execution_enabled = $remoteDispatchEnabled
}

$rollbackRequirement = [ordered]@{
    schema = "agentos.rc9-rollback-planspec-requirement.v1"
    generated_at = $generatedAt
    task = "RC9-030"
    status = "rollback-planspec-required-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    rollback_planspec_id = $rollbackPlanSpecId
    rollback_planspec_hash = $rollbackPlanSpecHash
    rollback_planspec_core = $rollbackPlanSpecCore
    rollback_policy_id = $rollbackPolicyId
    rollback_decision_id = $rollbackDecisionId
    exact_rollback_approval_required = $true
    exact_rollback_approval_granted = $false
    agentcore_rollback_planspec_required = $true
    agentcore_rollback_planspec_bound = $false
    security_execution_engine_required = $true
    security_execution_rollback_approval_bound = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    source_bindings = $sourceBindings
    gate_inputs = $gateInputs
    blockers = $script:blockers
    side_effects = $sideEffects
}

$gateReport = [ordered]@{
    schema = "agentos.rc9-controlled-rollback-drill-gate-report.v1"
    generated_at = $generatedAt
    task = "RC9-030"
    status = "rollback-drill-gates-evaluated-denied"
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    rollback_state = $rollbackState
    all_gates_passed = $rollbackExecutionAllowed
    rollback_readiness_ready = $rollbackBaselinePresent -and $supportRecoveryPresent
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    gate_inputs = $gateInputs
    rollback_surface = [ordered]@{
        previous_active_artifact_set_digest = [string]$rollbackBaseline.previous_active_artifact_set_sha256
        activated_artifact_set_digest = "not-activated"
        restored_active_artifact_set_digest = [string]$rollbackBaseline.restored_active_artifact_set_sha256
        rollback_baseline_digest = [string]$rollbackBaseline.rollback_baseline_sha256
        rollback_baseline_file_sha256 = $rollbackBaselineSha256
        baseline_consistent = $rollbackBaseline.previous_active_artifact_set_sha256 -eq $rollbackBaseline.restored_active_artifact_set_sha256
    }
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
    [ordered]@{ id = "external-https-object-uri-not-published"; status = "passed"; rollback_execution_allowed = $false; reason = "No immutable credential-free HTTPS object URI is published for the current payload." },
    [ordered]@{ id = "declared-current-artifact-drift-denied"; status = "passed"; rollback_execution_allowed = $false; reason = "Declared/current drift remains denied, so external object trust cannot advance." },
    [ordered]@{ id = "installer-quarantine-fetch-not-run"; status = "passed"; rollback_execution_allowed = $false; reason = "Installer fetch was denied before network and no quarantine payload was verified." },
    [ordered]@{ id = "target-set-not-enrolled"; status = "passed"; rollback_execution_allowed = $false; reason = "The canary target set is not enrolled." },
    [ordered]@{ id = "two-or-more-enrolled-canary-target-nodes-required"; status = "passed"; rollback_execution_allowed = $false; reason = "Zero enrolled canary targets are present while two are required." },
    [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; rollback_execution_allowed = $false; reason = "Activation exact approval remains unbound and approval_granted=false." },
    [ordered]@{ id = "AgentCore-PlanSpec-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "The activation PlanSpec is projected but non-executable." },
    [ordered]@{ id = "SecurityExecutionEngine-approval-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "SecurityExecutionEngine denied the activation effect." },
    [ordered]@{ id = "remote-fleet-execution-not-enabled"; status = "passed"; rollback_execution_allowed = $false; reason = "Remote fleet dispatch remains disabled." },
    [ordered]@{ id = "controlled-canary-activation-not-performed"; status = "passed"; rollback_execution_allowed = $false; reason = "RC9-022 denied activation, so there is no executed canary activation to roll back." },
    [ordered]@{ id = "controlled-execution-not-authorized"; status = "passed"; rollback_execution_allowed = $false; reason = "The inherited controlled execution authorization gate is still denied." },
    [ordered]@{ id = "rollback-exact-operator-approval-not-granted"; status = "passed"; rollback_execution_allowed = $false; reason = "A separate exact rollback approval is required and not granted." },
    [ordered]@{ id = "AgentCore-rollback-PlanSpec-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "The rollback PlanSpec is only a requirement projection and is not executable." },
    [ordered]@{ id = "SecurityExecutionEngine-rollback-approval-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "SecurityExecutionEngine rollback approval is absent." },
    [ordered]@{ id = "rollback-execution-not-authorized"; status = "passed"; rollback_execution_allowed = $false; reason = "At least one required rollback gate is missing." }
)

$denialEvidence = [ordered]@{
    schema = "agentos.rc9-controlled-rollback-drill-denial-evidence.v1"
    generated_at = $generatedAt
    task = "RC9-030"
    status = "rollback-denied"
    production_ready_claim = $false
    projection_only = $true
    denied = $true
    release_id = $releaseId
    rollback_attempt_id = $rollbackAttemptId
    rollback_planspec_hash = $rollbackPlanSpecHash
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    denial_cases = $denialCases
    blockers = $script:blockers
    preserved_boundaries = [ordered]@{
        activation_performed = $false
        exact_rollback_approval_granted = $false
        agentcore_rollback_planspec_executable = $false
        security_execution_rollback_allowed = $false
        install_allowed = $false
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
    schema = "agentos.rc9-controlled-rollback-handoff.v1"
    generated_at = $generatedAt
    task = "RC9-030"
    status = "blocked-by-rollback-denial"
    production_ready_claim = $false
    release_id = $releaseId
    rollback_state = $rollbackState
    rollback_attempt_id = $rollbackAttemptId
    rollback_planspec_hash = $rollbackPlanSpecHash
    activation_performed = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    support_recovery_binding_ready = $supportRecoveryPresent
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    blockers = $script:blockers
    next_task = "RC9-031"
}

$requirementPath = Join-Path $resolvedArtifactDir "rollback-planspec-requirement.json"
$gateReportPath = Join-Path $resolvedArtifactDir "rollback-drill-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "rollback-drill-denial-evidence.json"
$handoffPath = Join-Path $resolvedArtifactDir "controlled-rollback-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $rollbackRequirement $requirementPath
Write-Json $gateReport $gateReportPath
Write-Json $denialEvidence $denialEvidencePath
Write-Json $handoff $handoffPath

Add-Check "source.rc9_022.activation_denied" ($activationResult.status -eq "passed" -and $activationResult.summary.rc9_022_complete -eq $true -and $activationResult.activation_surface.state -eq "activation-denied" -and $activationResult.activation_surface.activation_performed -eq $false) "RC9-030 must consume completed RC9-022 activation denial before rollback drill evaluation." ([ordered]@{ status = $activationResult.status; state = $activationResult.activation_surface.state; activation_performed = $activationResult.activation_surface.activation_performed })
Add-Check "source.activation_handoff.rollback_blocked" ($activationHandoff.status -eq "blocked-by-activation-denial" -and $activationHandoff.rollback_execution_allowed -eq $false -and $activationHandoff.next_task -eq "RC9-030") "RC9-030 must consume the activation handoff that keeps rollback blocked." ([ordered]@{ status = $activationHandoff.status; rollback_execution_allowed = $activationHandoff.rollback_execution_allowed; next_task = $activationHandoff.next_task })
Add-Check "source.rollback_baseline.present" ($rollbackBaselinePresent -and $rollbackBaseline.execution_status.rollback_execution_allowed -eq $false) "Rollback baseline must be present while rollback execution remains blocked." ([ordered]@{ rollback_baseline_sha256 = $rollbackBaseline.rollback_baseline_sha256; execution_allowed = $rollbackBaseline.execution_status.rollback_execution_allowed })
Add-Check "rollback.planspec_requirement.projected_blocked" ((Test-Path -LiteralPath $requirementPath -PathType Leaf) -and $rollbackRequirement.executable -eq $false -and $rollbackRequirement.rollback_execution_allowed -eq $false -and -not [string]::IsNullOrWhiteSpace($rollbackRequirement.rollback_planspec_hash)) "Rollback PlanSpec requirement must be projected and non-executable." ([ordered]@{ path = Get-StablePath $requirementPath; sha256 = Get-FileSha256 $requirementPath; planspec_hash = $rollbackPlanSpecHash })
Add-Check "rollback.gates.fail_closed" ($rollbackExecutionAllowed -eq $false -and $gateReport.rollback_state -eq "rollback-denied") "Rollback drill must deny when activation, rollback approval, AgentCore rollback PlanSpec, SecurityExecution, or upstream gates are missing." ([ordered]@{ rollback_execution_allowed = $rollbackExecutionAllowed; blockers = $script:blockers })
Add-Check "rollback.denial_cases.complete" (@($denialEvidence.denial_cases | Where-Object { $_.status -ne "passed" -or $_.rollback_execution_allowed -ne $false }).Count -eq 0 -and @($denialEvidence.denial_cases).Count -eq 15) "Rollback denial evidence must cover every missing rollback execution gate as fail-closed." ([ordered]@{ cases = @($denialEvidence.denial_cases).Count })
Add-Check "side_effects.none" ($sideEffects.effect_prepared -eq $false -and $sideEffects.effect_executed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.active_slot_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false) "RC9-030 must not prepare or execute rollback, production mutation, support upload, or remote dispatch side effects." $sideEffects
Add-Check "handoff.support_recovery_next" ($handoff.status -eq "blocked-by-rollback-denial" -and $handoff.next_task -eq "RC9-031" -and $handoff.support_upload_allowed -eq $false) "Rollback handoff must move to RC9-031 while keeping support upload and recovery execution blocked." ([ordered]@{ status = $handoff.status; next_task = $handoff.next_task; support_upload_allowed = $handoff.support_upload_allowed })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $requirementPath),
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-030 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null

$source = [ordered]@{
    binding_contract = New-ArtifactRef $resolvedBindingContractPath
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    installer_fetch_result = New-ArtifactRef $resolvedInstallerFetchResultPath $installerFetchResult
    target_enrollment_result = New-ArtifactRef $resolvedTargetEnrollmentResultPath $targetEnrollmentResult
    binding_result = New-ArtifactRef $resolvedBindingResultPath $bindingResult
    activation_result = New-ArtifactRef $resolvedActivationResultPath $activationResult
    activation_gate_report = New-ArtifactRef $resolvedActivationGateReportPath $activationGateReport
    activation_denial_evidence = New-ArtifactRef $resolvedActivationDenialEvidencePath $activationDenialEvidence
    activation_handoff = New-ArtifactRef $resolvedActivationHandoffPath $activationHandoff
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_recovery = New-ArtifactRef $resolvedSupportRecoveryPath $supportRecovery
}

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc9-controlled-rollback-drill-result.v1"
    generated_at = $generatedAt
    task = "RC9-030"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    rollback_surface = [ordered]@{
        state = $rollbackState
        rollback_attempt_id = $rollbackAttemptId
        rollback_planspec_id = $rollbackPlanSpecId
        rollback_planspec_hash = $rollbackPlanSpecHash
        rollback_readiness_ready = $rollbackBaselinePresent -and $supportRecoveryPresent
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        controlled_canary_activation_performed = $activationPerformed
        exact_rollback_approval_granted = $rollbackApprovalGranted
        agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
        security_execution_rollback_approval_bound = $rollbackSecurityExecutionAllowed
        support_upload_allowed = $false
        remote_dispatch_enabled = $remoteDispatchEnabled
        blockers = $script:blockers
    }
    outputs = [ordered]@{
        rollback_planspec_requirement = [ordered]@{
            path = Get-StablePath $requirementPath
            sha256 = Get-FileSha256 $requirementPath
        }
        rollback_drill_gate_report = [ordered]@{
            path = Get-StablePath $gateReportPath
            sha256 = Get-FileSha256 $gateReportPath
        }
        rollback_drill_denial_evidence = [ordered]@{
            path = Get-StablePath $denialEvidencePath
            sha256 = Get-FileSha256 $denialEvidencePath
        }
        controlled_rollback_handoff = [ordered]@{
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
        rollback_attempt_recorded = $true
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
        rc9_030_complete = ($failedChecks.Count -eq 0)
        rollback_state = $rollbackState
        rollback_readiness_ready = $rollbackBaselinePresent -and $supportRecoveryPresent
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        canary_activation_performed = $activationPerformed
        support_upload_allowed = $false
        remote_dispatch_enabled = $remoteDispatchEnabled
        production_ready_claim = $false
        next_task = "RC9-031"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-030 result."
}

Write-Host "RC9 controlled rollback drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Rollback state: $($result.rollback_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), blockers: $(@($script:blockers).Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
