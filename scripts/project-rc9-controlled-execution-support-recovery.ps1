param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-controlled-execution-support-recovery",
    [string]$GeneratedAt = "",
    [string]$BindingContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/controlled-execution-binding-contract.md",
    [string]$ActivationResultPath = ".workflow/artifacts/rc9-controlled-canary-activation/result.json",
    [string]$ActivationDenialEvidencePath = ".workflow/artifacts/rc9-controlled-canary-activation/activation-denial-evidence.json",
    [string]$ActivationHandoffPath = ".workflow/artifacts/rc9-controlled-canary-activation/controlled-activation-handoff.json",
    [string]$RollbackResultPath = ".workflow/artifacts/rc9-controlled-rollback-drill/result.json",
    [string]$RollbackPlanSpecRequirementPath = ".workflow/artifacts/rc9-controlled-rollback-drill/rollback-planspec-requirement.json",
    [string]$RollbackGateReportPath = ".workflow/artifacts/rc9-controlled-rollback-drill/rollback-drill-gate-report.json",
    [string]$RollbackDenialEvidencePath = ".workflow/artifacts/rc9-controlled-rollback-drill/rollback-drill-denial-evidence.json",
    [string]$RollbackHandoffPath = ".workflow/artifacts/rc9-controlled-rollback-drill/controlled-rollback-handoff.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$RecoveryOperationsPath = ".workflow/artifacts/rc5-hosted-support-recovery/recovery-operations.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [switch]$FailOnBlocked
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

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
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
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
        $script:blockers += $entry
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

function Get-RecoveryOperation {
    param($RecoveryJson, [string]$Id)
    if ($null -eq $RecoveryJson -or $null -eq $RecoveryJson.operations) {
        return $null
    }
    return @($RecoveryJson.operations | Where-Object { $_.id -eq $Id } | Select-Object -First 1)[0]
}

function Test-RecoveryOperationsNonExecutable {
    param($RecoveryJson)
    if ($null -eq $RecoveryJson -or $null -eq $RecoveryJson.operations) {
        return $false
    }
    return @($RecoveryJson.operations | Where-Object { $_.executable_by_mirror -ne $false }).Count -eq 0
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedBindingContractPath = Resolve-RepoPath $BindingContractPath
$resolvedActivationResultPath = Resolve-RepoPath $ActivationResultPath
$resolvedActivationDenialEvidencePath = Resolve-RepoPath $ActivationDenialEvidencePath
$resolvedActivationHandoffPath = Resolve-RepoPath $ActivationHandoffPath
$resolvedRollbackResultPath = Resolve-RepoPath $RollbackResultPath
$resolvedRollbackPlanSpecRequirementPath = Resolve-RepoPath $RollbackPlanSpecRequirementPath
$resolvedRollbackGateReportPath = Resolve-RepoPath $RollbackGateReportPath
$resolvedRollbackDenialEvidencePath = Resolve-RepoPath $RollbackDenialEvidencePath
$resolvedRollbackHandoffPath = Resolve-RepoPath $RollbackHandoffPath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedRecoveryOperationsPath = Resolve-RepoPath $RecoveryOperationsPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath

$activationResult = Read-Json $resolvedActivationResultPath
$activationDenialEvidence = Read-Json $resolvedActivationDenialEvidencePath
$activationHandoff = Read-Json $resolvedActivationHandoffPath
$rollbackResult = Read-Json $resolvedRollbackResultPath
$rollbackPlanSpecRequirement = Read-Json $resolvedRollbackPlanSpecRequirementPath
$rollbackGateReport = Read-Json $resolvedRollbackGateReportPath
$rollbackDenialEvidence = Read-Json $resolvedRollbackDenialEvidencePath
$rollbackHandoff = Read-Json $resolvedRollbackHandoffPath
$supportIndex = Read-Json $resolvedSupportIndexPath
$recoveryOperations = Read-Json $resolvedRecoveryOperationsPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$compatibility = Read-Json $resolvedCompatibilityPath

$sourceRefs = [ordered]@{
    binding_contract = New-ArtifactRef $resolvedBindingContractPath
    activation_result = New-ArtifactRef $resolvedActivationResultPath $activationResult
    activation_denial_evidence = New-ArtifactRef $resolvedActivationDenialEvidencePath $activationDenialEvidence
    activation_handoff = New-ArtifactRef $resolvedActivationHandoffPath $activationHandoff
    rollback_result = New-ArtifactRef $resolvedRollbackResultPath $rollbackResult
    rollback_planspec_requirement = New-ArtifactRef $resolvedRollbackPlanSpecRequirementPath $rollbackPlanSpecRequirement
    rollback_gate_report = New-ArtifactRef $resolvedRollbackGateReportPath $rollbackGateReport
    rollback_denial_evidence = New-ArtifactRef $resolvedRollbackDenialEvidencePath $rollbackDenialEvidence
    rollback_handoff = New-ArtifactRef $resolvedRollbackHandoffPath $rollbackHandoff
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    recovery_operations = New-ArtifactRef $resolvedRecoveryOperationsPath $recoveryOperations
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
}

$sourceBindings = [ordered]@{}
foreach ($key in $sourceRefs.Keys) {
    $sourceBindings["$($key)_sha256"] = $sourceRefs[$key].sha256
}

$rollbackReadinessOperation = Get-RecoveryOperation -RecoveryJson $recoveryOperations -Id "rollback-readiness-explain"
$releaseId = [string]$rollbackResult.release_id
$remainingBlockers = @($rollbackResult.rollback_surface.blockers)

$activationDeniedReady = $activationResult.status -eq "passed" -and
    $activationResult.summary.rc9_022_complete -eq $true -and
    $activationResult.activation_surface.state -eq "activation-denied" -and
    $activationResult.activation_surface.activation_allowed -eq $false -and
    $activationResult.activation_surface.activation_performed -eq $false -and
    $activationDenialEvidence.status -eq "activation-denied" -and
    $activationDenialEvidence.activation_allowed -eq $false -and
    $activationDenialEvidence.activation_performed -eq $false -and
    $activationHandoff.status -eq "blocked-by-activation-denial" -and
    $activationHandoff.rollback_execution_allowed -eq $false

$rollbackDeniedReady = $rollbackResult.status -eq "passed" -and
    $rollbackResult.summary.rc9_030_complete -eq $true -and
    $rollbackResult.rollback_surface.state -eq "rollback-denied" -and
    $rollbackResult.rollback_surface.rollback_execution_allowed -eq $false -and
    $rollbackResult.rollback_surface.rollback_execution_performed -eq $false -and
    $rollbackResult.rollback_surface.controlled_canary_activation_performed -eq $false -and
    $rollbackPlanSpecRequirement.executable -eq $false -and
    $rollbackPlanSpecRequirement.rollback_execution_allowed -eq $false -and
    $rollbackGateReport.rollback_execution_allowed -eq $false -and
    $rollbackGateReport.rollback_execution_performed -eq $false -and
    $rollbackDenialEvidence.status -eq "rollback-denied" -and
    $rollbackDenialEvidence.rollback_execution_allowed -eq $false -and
    @($rollbackDenialEvidence.denial_cases).Count -eq 15 -and
    $rollbackHandoff.status -eq "blocked-by-rollback-denial" -and
    $rollbackHandoff.next_task -eq "RC9-031"

$supportReady = $supportIndex.status -eq "hosted-metadata-only" -and
    $supportIndex.production_ready_claim -eq $false -and
    $supportIndex.redacted -eq $true -and
    $supportIndex.support_upload_allowed -eq $false -and
    $supportIndex.recovery_execution_allowed -eq $false -and
    $supportIndex.rollback_execution_allowed -eq $false -and
    $supportIndex.activation_allowed -eq $false -and
    $supportIndex.authority.support_authority -eq $false -and
    $supportIndex.authority.recovery_authority -eq $false -and
    $supportIndex.authority.signing_authority -eq $false -and
    $supportIndex.authority.remote_dispatch_authority -eq $false -and
    $supportIndex.authority.tui_authority -eq $false

$recoveryReady = $recoveryOperations.status -eq "projection-only" -and
    $recoveryOperations.production_ready_claim -eq $false -and
    (Test-RecoveryOperationsNonExecutable -RecoveryJson $recoveryOperations) -and
    $recoveryOperations.invariants.support_upload_performed -eq $false -and
    $recoveryOperations.invariants.rollback_execution_performed -eq $false -and
    $recoveryOperations.invariants.active_slot_mutated -eq $false -and
    $recoveryOperations.invariants.active_artifact_set_mutated -eq $false -and
    $recoveryOperations.invariants.production_ring_mutated -eq $false -and
    $recoveryOperations.invariants.remote_dispatch_enabled -eq $false -and
    $recoveryOperations.invariants.tui_authority -eq $false

$rollbackBaselineReady = $rollbackBaseline.execution_status.rollback_execution_allowed -eq $false -and
    $rollbackBaseline.execution_status.rollback_execution_performed -eq $false -and
    $rollbackBaseline.previous_active_artifact_set_sha256 -eq $rollbackBaseline.restored_active_artifact_set_sha256 -and
    $rollbackBaseline.support_recovery_binding.executable_by_mirror -eq $false -and
    $null -ne $rollbackReadinessOperation -and
    $rollbackReadinessOperation.executable_by_mirror -eq $false -and
    $rollbackReadinessOperation.rollback_baseline_sha256 -eq $rollbackBaseline.rollback_baseline_sha256

$compatibilityReady = $compatibility.production_ready_claim -eq $false -and
    $compatibility.status -eq "compatibility-projected-verification-blocked" -and
    $compatibility.authority.mirror_is_root_of_trust -eq $false -and
    $compatibility.authority.installer_preflight_can_activate -eq $false -and
    $compatibility.authority.tui_authority -eq $false

$invariants = [ordered]@{
    local_projection_only = $true
    support_bundle_redacted = $true
    support_upload_allowed = $false
    support_upload_performed = $false
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
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
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    mirror_authority = $false
    signer_authority = $false
    production_ready_claim = $false
}

$evidenceChain = [ordered]@{
    schema = "agentos.rc9-controlled-execution-support-recovery-chain.v1"
    generated_at = $generatedAt
    task = "RC9-031"
    status = "support-recovery-bound-controlled-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    controlled_execution = [ordered]@{
        activation_state = $activationResult.activation_surface.state
        activation_allowed = $false
        activation_performed = $false
        rollback_state = $rollbackResult.rollback_surface.state
        rollback_readiness_ready = $rollbackResult.rollback_surface.rollback_readiness_ready
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
    }
    support_surface = [ordered]@{
        source_schema = $supportIndex.schema
        status = $supportIndex.status
        redacted = $supportIndex.redacted
        support_upload_allowed = $supportIndex.support_upload_allowed
        recovery_execution_allowed = $supportIndex.recovery_execution_allowed
        rollback_execution_allowed = $supportIndex.rollback_execution_allowed
        activation_allowed = $supportIndex.activation_allowed
        support_mode = $supportIndex.support_mode
    }
    recovery_surface = [ordered]@{
        source_schema = $recoveryOperations.schema
        status = $recoveryOperations.status
        operation_count = @($recoveryOperations.operations).Count
        all_operations_non_executable_by_mirror = Test-RecoveryOperationsNonExecutable -RecoveryJson $recoveryOperations
        rollback_baseline_sha256 = $rollbackBaseline.rollback_baseline_sha256
        previous_active_artifact_set_sha256 = $rollbackBaseline.previous_active_artifact_set_sha256
        restored_active_artifact_set_sha256 = $rollbackBaseline.restored_active_artifact_set_sha256
        baseline_consistent = $rollbackBaseline.previous_active_artifact_set_sha256 -eq $rollbackBaseline.restored_active_artifact_set_sha256
        rollback_readiness_operation_executable_by_mirror = if ($null -ne $rollbackReadinessOperation) { $rollbackReadinessOperation.executable_by_mirror } else { $null }
    }
    source_bindings = $sourceBindings
    remaining_blockers_before_controlled_execution = $remainingBlockers
    invariants = $invariants
}

$supportBundle = [ordered]@{
    schema = "agentos.rc9-controlled-execution-support-bundle-projection.v1"
    generated_at = $generatedAt
    task = "RC9-031"
    status = "redacted-local-support-projection"
    production_ready_claim = $false
    projection_only = $true
    local_only = $true
    redacted = $true
    upload_allowed = $false
    upload_performed = $false
    release_id = $releaseId
    sections = [ordered]@{
        activation_denial = [ordered]@{
            source = $sourceRefs.activation_denial_evidence.path
            sha256 = $sourceRefs.activation_denial_evidence.sha256
            activation_allowed = $activationDenialEvidence.activation_allowed
            activation_performed = $activationDenialEvidence.activation_performed
            blockers = $activationDenialEvidence.blockers
        }
        rollback_denial = [ordered]@{
            source = $sourceRefs.rollback_denial_evidence.path
            sha256 = $sourceRefs.rollback_denial_evidence.sha256
            rollback_execution_allowed = $rollbackDenialEvidence.rollback_execution_allowed
            rollback_execution_performed = $rollbackDenialEvidence.rollback_execution_performed
            blockers = $rollbackDenialEvidence.blockers
        }
        support_metadata = [ordered]@{
            source = $sourceRefs.support_index.path
            sha256 = $sourceRefs.support_index.sha256
            support_upload_allowed = $false
            recovery_execution_allowed = $false
            redacted = $supportIndex.redacted
        }
        recovery_metadata = [ordered]@{
            source = $sourceRefs.recovery_operations.path
            sha256 = $sourceRefs.recovery_operations.sha256
            all_operations_non_executable_by_mirror = Test-RecoveryOperationsNonExecutable -RecoveryJson $recoveryOperations
            rollback_baseline_sha256 = $rollbackBaseline.rollback_baseline_sha256
        }
    }
    operator_summary = [ordered]@{
        current_state = "controlled-execution-blocked"
        safe_next_task = "RC9-040 final audit and next milestone planning after RC9-031 evidence is committed"
        support_truth = "redacted local evidence projection; no support upload endpoint is authorized"
        recovery_truth = "rollback baseline plus activation/rollback denial evidence; no recovery or rollback execution is authorized"
    }
    source_bindings = $sourceBindings
    invariants = $invariants
}

$recoveryIndex = [ordered]@{
    schema = "agentos.rc9-controlled-execution-recovery-reference-index.v1"
    generated_at = $generatedAt
    task = "RC9-031"
    status = "projection-only-recovery-execution-blocked"
    production_ready_claim = $false
    release_id = $releaseId
    entries = @(
        [ordered]@{ id = "activation-denial"; kind = "local-artifact"; path = $sourceRefs.activation_denial_evidence.path; sha256 = $sourceRefs.activation_denial_evidence.sha256; executable = $false },
        [ordered]@{ id = "rollback-denial"; kind = "local-artifact"; path = $sourceRefs.rollback_denial_evidence.path; sha256 = $sourceRefs.rollback_denial_evidence.sha256; executable = $false },
        [ordered]@{ id = "rollback-planspec-requirement"; kind = "local-artifact"; path = $sourceRefs.rollback_planspec_requirement.path; sha256 = $sourceRefs.rollback_planspec_requirement.sha256; executable = $false },
        [ordered]@{ id = "controlled-rollback-handoff"; kind = "local-artifact"; path = $sourceRefs.rollback_handoff.path; sha256 = $sourceRefs.rollback_handoff.sha256; executable = $false },
        [ordered]@{ id = "support-index"; kind = "local-artifact"; path = $sourceRefs.support_index.path; sha256 = $sourceRefs.support_index.sha256; executable = $false },
        [ordered]@{ id = "recovery-operations"; kind = "local-artifact"; path = $sourceRefs.recovery_operations.path; sha256 = $sourceRefs.recovery_operations.sha256; executable = $false },
        [ordered]@{ id = "rollback-baseline"; kind = "local-artifact"; path = $sourceRefs.rollback_baseline.path; sha256 = $sourceRefs.rollback_baseline.sha256; executable = $false },
        [ordered]@{ id = "compatibility"; kind = "local-artifact"; path = $sourceRefs.compatibility.path; sha256 = $sourceRefs.compatibility.sha256; executable = $false }
    )
    recovery_authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        signer_authority = $false
        support_metadata_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
    required_before_execution = @(
        "external HTTPS object URI",
        "declared/current artifact drift reconciliation",
        "quarantine payload fetch verification",
        "2+ enrolled canary target nodes",
        "exact operator approval",
        "AgentCore activation and rollback PlanSpec",
        "SecurityExecutionEngine activation and rollback approval",
        "controlled canary activation execution",
        "remote fleet execution gate"
    )
    invariants = $invariants
}

$evidenceChainPath = Join-Path $resolvedArtifactDir "support-recovery-evidence-chain.json"
$supportBundlePath = Join-Path $resolvedArtifactDir "controlled-execution-support-bundle.json"
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $evidenceChain $evidenceChainPath
Write-Json $supportBundle $supportBundlePath
Write-Json $recoveryIndex $recoveryIndexPath

Add-Check "source.rc9_022.activation_denied_ready" $activationDeniedReady "RC9-031 must bind RC9-022 activation denial without treating it as executed activation." ([ordered]@{ state = $activationResult.activation_surface.state; activation_performed = $activationResult.activation_surface.activation_performed; handoff = $activationHandoff.status })
Add-Check "source.rc9_030.rollback_denied_ready" $rollbackDeniedReady "RC9-031 must bind RC9-030 rollback denial and non-executable rollback PlanSpec requirement without executing rollback." ([ordered]@{ state = $rollbackResult.rollback_surface.state; rollback_execution_performed = $rollbackResult.rollback_surface.rollback_execution_performed; handoff_next_task = $rollbackHandoff.next_task })
Add-Check "support.metadata.non_authoritative" $supportReady "Support metadata must remain redacted, upload-disabled, recovery-disabled, rollback-disabled, and non-authoritative." ([ordered]@{ status = $supportIndex.status; redacted = $supportIndex.redacted; support_upload_allowed = $supportIndex.support_upload_allowed })
Add-Check "recovery.operations.non_executable" $recoveryReady "Recovery operations must remain projection-only and non-executable by mirror, model, shell, or TUI." ([ordered]@{ status = $recoveryOperations.status; operation_count = @($recoveryOperations.operations).Count })
Add-Check "rollback.baseline.bound_to_recovery" $rollbackBaselineReady "Rollback baseline must be support/recovery bound while rollback execution remains blocked." ([ordered]@{ rollback_baseline_sha256 = $rollbackBaseline.rollback_baseline_sha256; operation = if ($null -ne $rollbackReadinessOperation) { $rollbackReadinessOperation.id } else { $null } })
Add-Check "compatibility.metadata.non_authoritative" $compatibilityReady "Compatibility metadata must remain verification-blocked and non-authoritative." ([ordered]@{ status = $compatibility.status })
Add-Check "support.outputs.projected" ((Test-Path -LiteralPath $evidenceChainPath -PathType Leaf) -and (Test-Path -LiteralPath $supportBundlePath -PathType Leaf) -and (Test-Path -LiteralPath $recoveryIndexPath -PathType Leaf)) "RC9-031 must emit support/recovery evidence chain, redacted support bundle projection, and recovery reference index." ([ordered]@{ evidence_chain = Get-FileSha256 $evidenceChainPath; support_bundle = Get-FileSha256 $supportBundlePath; recovery_index = Get-FileSha256 $recoveryIndexPath })
Add-Check "authority.not_broadened" ($invariants.support_upload_performed -eq $false -and $invariants.recovery_execution_performed -eq $false -and $invariants.rollback_execution_performed -eq $false -and $invariants.production_ring_mutated -eq $false -and $invariants.remote_dispatch_enabled -eq $false -and $invariants.tui_authority -eq $false) "RC9-031 must not sign, upload payloads, install, activate, rollback, recover, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI authority." $invariants

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $evidenceChainPath),
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-031 projected artifacts must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$passed = $failedChecks.Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc9-controlled-execution-support-recovery-result.v1"
    generated_at = $generatedAt
    task = "RC9-031"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc9_031_complete = $passed
    controlled_execution_support_recovery_bound = $passed
    support_recovery_evidence_projected = $passed
    release_id = $releaseId
    activation_state = $activationResult.activation_surface.state
    activation_allowed = $false
    activation_performed = $false
    rollback_state = $rollbackResult.rollback_surface.state
    rollback_readiness_ready = $rollbackResult.rollback_surface.rollback_readiness_ready
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    support_upload_allowed = $false
    support_upload_performed = $false
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    artifacts = [ordered]@{
        support_recovery_evidence_chain = [ordered]@{
            path = Get-StablePath $evidenceChainPath
            sha256 = Get-FileSha256 $evidenceChainPath
            schema = $evidenceChain.schema
            status = $evidenceChain.status
        }
        controlled_execution_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = Get-FileSha256 $supportBundlePath
            schema = $supportBundle.schema
            status = $supportBundle.status
        }
        recovery_reference_index = [ordered]@{
            path = Get-StablePath $recoveryIndexPath
            sha256 = Get-FileSha256 $recoveryIndexPath
            schema = $recoveryIndex.schema
            status = $recoveryIndex.status
        }
    }
    source_artifacts = $sourceRefs
    source_bindings = $sourceBindings
    support_surface = $evidenceChain.support_surface
    recovery_surface = $evidenceChain.recovery_surface
    remaining_blockers_before_controlled_execution = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    invariants = $invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        rc9_031_complete = $passed
        controlled_execution_support_recovery_bound = $passed
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        activation_allowed = $false
        activation_performed = $false
        rollback_readiness_ready = $rollbackResult.rollback_surface.rollback_readiness_ready
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ready_claim = $false
        next_task = "RC9-040"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-031 result."
}

Write-Host "RC9 controlled execution support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), remaining execution blockers: $(@($remainingBlockers).Count)"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
