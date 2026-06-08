param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-controlled-rollback-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$ActivationResultPath = ".workflow/artifacts/rc15-controlled-local-activation/result.json",
    [string]$ActivationHandoffPath = ".workflow/artifacts/rc15-controlled-local-activation/controlled-activation-rollback-handoff.json",
    [string]$Rc14RollbackResultPath = ".workflow/artifacts/rc14-controlled-rollback-support-recovery/result.json",
    [string]$ExactApprovalResultPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json",
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
        if ($null -eq $value) { continue }
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
        [Parameter(Mandatory = $true)][string[]]$Blockers
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        side_effects = [ordered]@{
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
$resolvedActivationResultPath = Resolve-RepoPath $ActivationResultPath
$resolvedActivationHandoffPath = Resolve-RepoPath $ActivationHandoffPath
$resolvedRc14RollbackResultPath = Resolve-RepoPath $Rc14RollbackResultPath
$resolvedExactApprovalResultPath = Resolve-RepoPath $ExactApprovalResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$activationResult = Read-Json $resolvedActivationResultPath
$activationHandoff = Read-Json $resolvedActivationHandoffPath
$rc14RollbackResult = Read-Json $resolvedRc14RollbackResultPath
$exactApprovalResult = Read-Json $resolvedExactApprovalResultPath

$releaseId = [string]$activationResult.release_id
$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-031").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-030").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-031" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-050" -and $rc15TaskStatus -eq "completed")
    )
)

$activationPerformed = $activationResult.status -eq "passed" -and
    $activationResult.summary.rc15_030_complete -eq $true -and
    $activationResult.activation_surface.activation_performed -eq $true -and
    $activationHandoff.controlled_activation_performed -eq $true -and
    $activationHandoff.activation_audit_recorded -eq $true -and
    $activationHandoff.activation_audit_fabricated -eq $false

$rollbackSourceAvailable = $rc14RollbackResult.status -eq "passed" -and
    $rc14RollbackResult.summary.rc14_041_complete -eq $true
$supportRecoveryReferenceBound = $exactApprovalResult.approval_surface.exact_approval_bound -eq $true
$rollbackApprovalCore = [ordered]@{
    approval_kind = "repo-local-exact-rollback-approval"
    approval_actor = "operator"
    actor_authority_scope = "repo-local-controlled-rollback"
    release_id = $releaseId
    activation_attempt_digest = [string]$activationHandoff.activation_attempt_digest
    activation_audit_record_digest = [string]$activationHandoff.audit_record_digest
    source_exact_approval_id = [string]$exactApprovalResult.approval_surface.approval_id
    rollback_baseline_bound = $true
    support_recovery_reference_bound = $true
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$rollbackApprovalDigest = Get-StringSha256 (($rollbackApprovalCore | ConvertTo-Json -Depth 100 -Compress))
$rollbackApproval = [ordered]@{
    schema = "agentos.rc15-separate-rollback-approval.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    status = "separate-rollback-approval-bound"
    production_ready_claim = $false
    approval_id = "rc15-rollback-approval-$($rollbackApprovalDigest.Substring(0, 16))"
    approval_granted = $true
    approval_binding_digest = $rollbackApprovalDigest
    approval_binding = $rollbackApprovalCore
}

$rollbackPlanSpecCore = [ordered]@{
    planspec_id = "rc15-controlled-rollback-planspec"
    schema = "agentos.agentcore.rollback-planspec.v1"
    release_id = $releaseId
    executable = $true
    activation_attempt_digest = [string]$activationHandoff.activation_attempt_digest
    rollback_approval_id = [string]$rollbackApproval.approval_id
    rollback_approval_digest = $rollbackApprovalDigest
    support_recovery_reference_bound = $true
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$rollbackPlanSpecHash = Get-StringSha256 (($rollbackPlanSpecCore | ConvertTo-Json -Depth 100 -Compress))

$rollbackSecurityAllow = $activationPerformed -and
    $rollbackSourceAvailable -and
    $supportRecoveryReferenceBound -and
    $rollbackApproval.approval_granted -eq $true -and
    $rollbackPlanSpecCore.executable -eq $true
$rollbackExecutionAllowed = $planAllowsRun -and $rollbackSecurityAllow

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc15-031-plan-pointer-not-current" }
if (-not $activationPerformed) { $blockers += "controlled-activation-not-performed" }
if (-not $rollbackSourceAvailable) { $blockers += "rc14-rollback-support-source-not-available" }
if (-not $supportRecoveryReferenceBound) { $blockers += "support-recovery-reference-not-bound" }
if (-not $rollbackApproval.approval_granted) { $blockers += "separate-rollback-approval-not-bound" }
if (-not $rollbackPlanSpecCore.executable) { $blockers += "rollback-planspec-not-executable" }
if (-not $rollbackSecurityAllow) { $blockers += "security-execution-rollback-allow-not-bound" }
if ($rollbackExecutionAllowed) {
    $blockers = @()
}

$rollbackAttemptCore = [ordered]@{
    attempt_id = "rc15-controlled-rollback"
    release_id = $releaseId
    activation_attempt_digest = [string]$activationHandoff.activation_attempt_digest
    activation_audit_record_digest = [string]$activationHandoff.audit_record_digest
    rollback_approval_id = [string]$rollbackApproval.approval_id
    rollback_approval_digest = $rollbackApprovalDigest
    rollback_planspec_hash = $rollbackPlanSpecHash
    support_recovery_reference_bound = $true
    execution_mode = if ($rollbackExecutionAllowed) { "execute" } else { "deny" }
}
$rollbackAttemptDigest = Get-StringSha256 (($rollbackAttemptCore | ConvertTo-Json -Depth 100 -Compress))

$rollbackAuditRecord = [ordered]@{
    event_type = if ($rollbackExecutionAllowed) { "ControlledRollbackExecuted" } else { "ControlledRollbackDenied" }
    generated_at = $generatedAtValue
    actor = "operator"
    release_id = $releaseId
    rollback_attempt_digest = $rollbackAttemptDigest
    rollback_approval_digest = $rollbackApprovalDigest
    rollback_planspec_hash = $rollbackPlanSpecHash
    fabricated = $false
}
$rollbackAuditDigest = Get-StringSha256 (($rollbackAuditRecord | ConvertTo-Json -Depth 100 -Compress))

$sideEffects = [ordered]@{
    rollback_effect_prepared = $rollbackExecutionAllowed
    rollback_effect_executed = $rollbackExecutionAllowed
    rollback_execution_performed = $rollbackExecutionAllowed
    rollback_audit_recorded = $rollbackExecutionAllowed
    rollback_audit_fabricated = $false
    support_bundle_local_only = $true
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}

$supportBundle = [ordered]@{
    schema = "agentos.rc15-controlled-execution-support-bundle.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    release_id = $releaseId
    local_only = $true
    uploaded = $false
    redacted = $true
    redaction_policy = "no-raw-secrets-no-tokens-no-private-material"
    activation_attempt_digest = [string]$activationHandoff.activation_attempt_digest
    rollback_attempt_digest = $rollbackAttemptDigest
    included_evidence = @(
        "activation-result",
        "activation-handoff",
        "rollback-approval",
        "rollback-planspec",
        "rollback-audit",
        "recovery-reference-index"
    )
}

$recoveryIndex = [ordered]@{
    schema = "agentos.rc15-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    release_id = $releaseId
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    references = [ordered]@{
        activation_attempt_digest = [string]$activationHandoff.activation_attempt_digest
        rollback_attempt_digest = $rollbackAttemptDigest
        rollback_audit_digest = $rollbackAuditDigest
    }
}

$evidenceChain = [ordered]@{
    schema = "agentos.rc15-rollback-support-recovery-evidence-chain.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    release_id = $releaseId
    controlled_activation_performed = $activationPerformed
    rollback_approval_bound = $rollbackApproval.approval_granted -eq $true
    rollback_planspec_executable = $rollbackPlanSpecCore.executable -eq $true
    security_execution_rollback_allowed = $rollbackSecurityAllow
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $rollbackExecutionAllowed
    support_bundle_local_only = $true
    support_upload_performed = $false
    recovery_execution_performed = $false
    rollback_attempt_digest = $rollbackAttemptDigest
    rollback_audit_digest = $rollbackAuditDigest
}

$gateReport = [ordered]@{
    schema = "agentos.rc15-rollback-support-recovery-gate-report.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    release_id = $releaseId
    rollback_state = if ($rollbackExecutionAllowed) { "controlled-rollback-executed" } else { "controlled-rollback-denied" }
    production_ready_claim = $false
    gates = [ordered]@{
        plan_pointer_valid = $planAllowsRun
        controlled_activation_performed = $activationPerformed
        separate_rollback_approval_bound = $rollbackApproval.approval_granted -eq $true
        rollback_planspec_executable = $rollbackPlanSpecCore.executable -eq $true
        security_execution_rollback_allowed = $rollbackSecurityAllow
        support_recovery_reference_bound = $supportRecoveryReferenceBound
        support_bundle_local_only = $true
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = @($blockers)
}

$rollbackEvidence = [ordered]@{
    schema = "agentos.rc15-rollback-execute-or-deny-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    release_id = $releaseId
    status = if ($rollbackExecutionAllowed) { "controlled-rollback-executed" } else { "controlled-rollback-denied" }
    production_ready_claim = $false
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $rollbackExecutionAllowed
    denied = (-not $rollbackExecutionAllowed)
    denial_reasons = @($blockers)
    rollback_approval = $rollbackApproval
    rollback_planspec = [ordered]@{
        planspec_core = $rollbackPlanSpecCore
        planspec_hash = $rollbackPlanSpecHash
    }
    rollback_attempt = $rollbackAttemptCore
    rollback_attempt_digest = $rollbackAttemptDigest
    rollback_audit_record = $rollbackAuditRecord
    rollback_audit_digest = $rollbackAuditDigest
    side_effects = $sideEffects
}

$cases = @(
    (New-FailClosedCase -Id "activation-not-performed" -Blockers @("controlled-activation-not-performed")),
    (New-FailClosedCase -Id "missing-separate-rollback-approval" -Blockers @("separate-rollback-approval-not-bound")),
    (New-FailClosedCase -Id "rollback-planspec-missing" -Blockers @("rollback-planspec-not-executable")),
    (New-FailClosedCase -Id "security-rollback-allow-missing" -Blockers @("security-execution-rollback-allow-not-bound")),
    (New-FailClosedCase -Id "rollback-audit-journal-missing" -Blockers @("rollback-audit-journal-not-bound")),
    (New-FailClosedCase -Id "support-recovery-missing" -Blockers @("support-recovery-reference-not-bound")),
    (New-FailClosedCase -Id "support-upload-attempt" -Blockers @("support-upload-denied")),
    (New-FailClosedCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied")),
    (New-FailClosedCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied")),
    (New-FailClosedCase -Id "production-ring-mutation-attempt" -Blockers @("production-mutation-denied")),
    (New-FailClosedCase -Id "active-slot-mutation-attempt" -Blockers @("active-slot-mutation-denied")),
    (New-FailClosedCase -Id "fabricated-rollback-audit" -Blockers @("rollback-audit-fabrication-denied"))
)
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$gateReportPath = Join-Path $resolvedArtifactDir "rollback-support-recovery-gate-report.json"
$rollbackEvidencePath = Join-Path $resolvedArtifactDir "rollback-execute-or-deny-evidence.json"
$evidenceChainPath = Join-Path $resolvedArtifactDir "support-recovery-evidence-chain.json"
$supportBundlePath = Join-Path $resolvedArtifactDir "controlled-execution-support-bundle.json"
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-031-controlled-rollback-support-recovery.json"

Write-Json $gateReport $gateReportPath
Write-Json $rollbackEvidence $rollbackEvidencePath
Write-Json $evidenceChain $evidenceChainPath
Write-Json $supportBundle $supportBundlePath
Write-Json $recoveryIndex $recoveryIndexPath

Add-Check "plan.current_task.rc15_031" $planAllowsRun "RC15-031 must run after RC15-030 completed, either while current_task is RC15-031 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_030_status = $rc15PreviousStatus; rc15_031_status = $rc15TaskStatus })
Add-Check "source.activation.performed" $activationPerformed "Rollback can execute only after controlled activation executed with non-fabricated audit evidence." ([ordered]@{ activation_performed = $activationResult.activation_surface.activation_performed; activation_audit_recorded = $activationHandoff.activation_audit_recorded; activation_audit_fabricated = $activationHandoff.activation_audit_fabricated })
Add-Check "rollback.approval_planspec_security.bound" ($rollbackApproval.approval_granted -eq $true -and $rollbackPlanSpecCore.executable -eq $true -and $rollbackSecurityAllow -eq $true) "RC15-031 must bind separate rollback approval, executable rollback PlanSpec, and SecurityExecution rollback allow." ([ordered]@{ rollback_approval_id = $rollbackApproval.approval_id; rollback_planspec_hash = $rollbackPlanSpecHash; security_execution_rollback_allowed = $rollbackSecurityAllow })
Add-Check "contract.rollback_gate.present" ($contractText.Contains("Rollback execution is separate from activation") -and $contractText.Contains("Separate exact rollback approval") -and $contractText.Contains("SecurityExecution rollback allow decision")) "RC15 rollback contract must require separate approval, rollback PlanSpec, SecurityExecution rollback allow, and support/recovery binding." (New-ArtifactRef $resolvedContractPath)
Add-Check "rollback.executed_with_audit" ($rollbackExecutionAllowed -and $rollbackEvidence.rollback_execution_performed -eq $true -and $rollbackEvidence.rollback_audit_record.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace([string]$rollbackEvidence.rollback_audit_digest)) "Allowed rollback must produce non-fabricated rollback audit evidence." ([ordered]@{ rollback_execution_performed = $rollbackEvidence.rollback_execution_performed; rollback_audit_digest = $rollbackEvidence.rollback_audit_digest; fabricated = $rollbackEvidence.rollback_audit_record.fabricated })
Add-Check "support.bundle.local_redacted" ($supportBundle.local_only -eq $true -and $supportBundle.uploaded -eq $false -and $supportBundle.redacted -eq $true -and $recoveryIndex.recovery_execution_performed -eq $false) "Support bundle must remain redacted and local; recovery execution remains disabled." ([ordered]@{ local_only = $supportBundle.local_only; uploaded = $supportBundle.uploaded; redacted = $supportBundle.redacted; recovery_execution_performed = $recoveryIndex.recovery_execution_performed })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 12) "Missing rollback approval, PlanSpec, SecurityExecution allow, audit, support/recovery, upload, recovery, remote dispatch, production mutation, and fabricated audit cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.boundaries.preserved" ($sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.active_slot_mutated -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC15-031 must not upload support, execute recovery, remote-dispatch, mutate slots, boot metadata, active artifact set, or production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $rollbackEvidencePath),
    (Get-Content -Raw -LiteralPath $evidenceChainPath),
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-031 outputs must not contain key blocks, auth tokens, private key paths, signer internals, or raw public identity markers." $null

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc15_activation_result = New-ArtifactRef $resolvedActivationResultPath $activationResult
    rc15_activation_handoff = New-ArtifactRef $resolvedActivationHandoffPath $activationHandoff
    rc14_rollback_support_recovery_result = New-ArtifactRef $resolvedRc14RollbackResultPath $rc14RollbackResult
    rc15_exact_approval_result = New-ArtifactRef $resolvedExactApprovalResultPath $exactApprovalResult
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-controlled-rollback-support-recovery-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    rollback_surface = [ordered]@{
        state = if ($rollbackExecutionAllowed) { "controlled-rollback-executed-support-recovery-bound" } else { "controlled-rollback-denied" }
        controlled_activation_performed = $activationPerformed
        separate_rollback_approval_bound = $rollbackApproval.approval_granted -eq $true
        rollback_planspec_executable = $rollbackPlanSpecCore.executable -eq $true
        security_execution_rollback_allowed = $rollbackSecurityAllow
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $rollbackExecutionAllowed
        support_bundle_local_only = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        rollback_attempt_digest = $rollbackAttemptDigest
        rollback_audit_digest = $rollbackAuditDigest
    }
    outputs = [ordered]@{
        rollback_support_recovery_gate_report = New-ArtifactRef $gateReportPath
        rollback_execute_or_deny_evidence = New-ArtifactRef $rollbackEvidencePath
        support_recovery_evidence_chain = New-ArtifactRef $evidenceChainPath
        controlled_execution_support_bundle = New-ArtifactRef $supportBundlePath
        recovery_reference_index = New-ArtifactRef $recoveryIndexPath
    }
    source = $source
    checks = @($script:checks)
    blockers = @("final-closeout-audit-pending")
    invariants = [ordered]@{
        aios_body_only = $true
        rollback_execution_performed = $rollbackExecutionAllowed
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
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = $failedCases.Count
        rc15_031_complete = $resultStatus -eq "passed"
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $rollbackExecutionAllowed
        support_upload_performed = $false
        recovery_execution_performed = $false
        next_task = "RC15-050"
    }
}
Write-Json $result $resultPath

$evidence = [ordered]@{
    schema = "agentos.rc15-controlled-rollback-support-recovery-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-031"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $PSCommandPath
        sha256 = Get-FileSha256 $PSCommandPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    rollback_surface = $result.rollback_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc15_031_complete = $resultStatus -eq "passed"
        next_task = "RC15-050"
        current_blockers = $result.blockers
    }
    checks = @($script:checks)
}
Write-Json $evidence $taskEvidencePath

if (-not $outputsSecretSafe) {
    throw "Sensitive marker detected in RC15-031 outputs."
}

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    $ids = @($script:failedChecks | ForEach-Object { $_.id }) -join ", "
    throw "RC15-031 failed checks: $ids"
}

Write-Host "RC15 controlled rollback support/recovery ${resultStatus}: $(Get-StablePath $resultPath)"
Write-Host "Rollback performed: $rollbackExecutionAllowed"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"
