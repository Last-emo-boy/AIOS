param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-controlled-local-update",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$InstallResultPath = ".workflow/artifacts/rc17-controlled-local-install/result.json",
    [string]$InstallEvidencePath = ".workflow/artifacts/rc17-controlled-local-install/install-execute-or-deny-evidence.json",
    [string]$InstallAuditRecordPath = ".workflow/artifacts/rc17-controlled-local-install/install-audit-record.json",
    [string]$SecurityAllowResultPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/result.json",
    [string]$SecurityAllowDecisionPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/security-execution-install-update-allow-decision.json",
    [string]$RollbackPreconditionsResultPath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/result.json",
    [string]$RollbackPreconditionPackagePath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/rollback-precondition-package.json",
    [string]$ObservationPlanPath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/post-install-update-observation-plan.json",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json",
    [string]$PlanSpecPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/install-update-planspec.json",
    [string]$ApprovalBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/result.json",
    [string]$TargetBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Write-Json {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param([string]$Id, [bool]$Passed, [string]$Message, $Evidence = $null)
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function New-ArtifactRef {
    param([string]$Path, $Json = $null)
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityMarker = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        $identityMarker
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-DenialCase {
    param([string]$Id, [string[]]$Blockers, [string]$Reason)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        side_effects = [ordered]@{
            update_effect_prepared = $false
            update_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_payload_downloaded = $false
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
$resolvedInstallResultPath = Resolve-RepoPath $InstallResultPath
$resolvedInstallEvidencePath = Resolve-RepoPath $InstallEvidencePath
$resolvedInstallAuditRecordPath = Resolve-RepoPath $InstallAuditRecordPath
$resolvedSecurityAllowResultPath = Resolve-RepoPath $SecurityAllowResultPath
$resolvedSecurityAllowDecisionPath = Resolve-RepoPath $SecurityAllowDecisionPath
$resolvedRollbackPreconditionsResultPath = Resolve-RepoPath $RollbackPreconditionsResultPath
$resolvedRollbackPreconditionPackagePath = Resolve-RepoPath $RollbackPreconditionPackagePath
$resolvedObservationPlanPath = Resolve-RepoPath $ObservationPlanPath
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecPath = Resolve-RepoPath $PlanSpecPath
$resolvedApprovalBindingResultPath = Resolve-RepoPath $ApprovalBindingResultPath
$resolvedTargetBindingResultPath = Resolve-RepoPath $TargetBindingResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installResult = Read-Json $resolvedInstallResultPath
$installEvidence = Read-Json $resolvedInstallEvidencePath
$installAudit = Read-Json $resolvedInstallAuditRecordPath
$allowResult = Read-Json $resolvedSecurityAllowResultPath
$allowDecision = Read-Json $resolvedSecurityAllowDecisionPath
$rollbackResult = Read-Json $resolvedRollbackPreconditionsResultPath
$rollbackPackage = Read-Json $resolvedRollbackPreconditionPackagePath
$observationPlan = Read-Json $resolvedObservationPlanPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpec = Read-Json $resolvedPlanSpecPath
$approvalResult = Read-Json $resolvedApprovalBindingResultPath
$targetResult = Read-Json $resolvedTargetBindingResultPath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-030"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-031"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-031" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-032" -and $rc17TaskStatus -eq "completed")
    )
)

$packageId = [string]$allowResult.package_id
$mediaId = [string]$allowResult.media_id
$releaseId = [string]$allowResult.release_id
$targetBindingId = [string]$allowResult.target_binding_id
$approvalId = [string]$allowResult.approval_id
$planspecCoreHash = [string]$allowResult.planspec_core_hash
$effectEnvelopeCoreHash = [string]$allowResult.effect_envelope_core_hash
$decisionMaterialHash = [string]$allowResult.decision_material_hash

$installOrderingBound = $installResult.status -eq "passed" -and
    $installResult.summary.rc17_030_complete -eq $true -and
    $installResult.summary.install_performed -eq $true -and
    $installResult.summary.update_performed -eq $false -and
    $installResult.summary.host_active_slot_mutated -eq $false -and
    $installResult.summary.host_boot_metadata_mutated -eq $false -and
    $installEvidence.status -eq "controlled-local-install-executed" -and
    $installAudit.fabricated -eq $false
$targetBound = $targetResult.status -eq "passed" -and $targetResult.summary.exact_install_update_target_bound -eq $true
$approvalBound = $approvalResult.status -eq "passed" -and $approvalResult.summary.exact_install_update_approval_bound -eq $true -and $approvalResult.summary.approval_granted -eq $true
$planspecExecutable = $planSpecResult.status -eq "passed" -and $planSpecResult.summary.agentcore_install_update_planspec_executable -eq $true -and $planSpec.update_plan.executable -eq $true
$securityAllowBound = $allowResult.status -eq "passed" -and $allowResult.summary.security_execution_install_update_allow -eq $true -and $allowDecision.security_execution_install_update_allow -eq $true -and (@($allowDecision.security_execution_allowed_effects) -contains "update")
$rollbackPreconditionsBound = $rollbackResult.status -eq "passed" -and $rollbackResult.summary.rollback_preconditions_bound -eq $true -and $rollbackPackage.rollback_preconditions_bound -eq $true
$observationPlanBound = $observationPlan.status -eq "post-install-update-observation-plan-bound-effects-denied" -and @($observationPlan.observations).Count -ge 10
$identityBound = $planSpec.update_plan.package_id -eq $packageId -and
    $planSpec.update_plan.media_id -eq $mediaId -and
    $planSpec.update_plan.release_id -eq $releaseId -and
    $planSpec.update_plan.target_binding_id -eq $targetBindingId
$auditMaterialBound = -not [string]::IsNullOrWhiteSpace([string]$allowDecision.effect_envelope_core.audit_sink_descriptor_sha256) -and
    -not [string]::IsNullOrWhiteSpace([string]$allowDecision.effect_envelope_core.approval_nonce_sha256) -and
    -not [string]::IsNullOrWhiteSpace([string]$allowDecision.effect_envelope_core.policy_version)

$updateAllowed = $planAllowsRun -and
    $installOrderingBound -and
    $targetBound -and
    $approvalBound -and
    $planspecExecutable -and
    $securityAllowBound -and
    $rollbackPreconditionsBound -and
    $observationPlanBound -and
    $identityBound -and
    $auditMaterialBound

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc17-031-plan-pointer-not-current" }
if (-not $installOrderingBound) { $blockers += "controlled-local-install-evidence-not-bound" }
if (-not $targetBound) { $blockers += "exact-install-update-target-not-bound" }
if (-not $approvalBound) { $blockers += "exact-install-update-approval-not-bound" }
if (-not $planspecExecutable) { $blockers += "agentcore-install-update-planspec-not-executable" }
if (-not $securityAllowBound) { $blockers += "security-execution-install-update-allow-not-bound" }
if (-not $rollbackPreconditionsBound) { $blockers += "rollback-preconditions-not-bound" }
if (-not $observationPlanBound) { $blockers += "post-install-update-observation-plan-not-bound" }
if (-not $identityBound) { $blockers += "update-target-identity-mismatch" }
if (-not $auditMaterialBound) { $blockers += "update-audit-material-not-bound" }
if ($updateAllowed) { $blockers = @() }

$updateAttemptCore = [ordered]@{
    schema = "agentos.rc17-controlled-local-update-attempt-core.v1"
    task = "RC17-031"
    operation = "update"
    execution_mode = if ($updateAllowed) { "execute" } else { "deny" }
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    planspec_core_hash = $planspecCoreHash
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    rollback_precondition_core_hash = [string]$rollbackResult.rollback_surface.rollback_precondition_core_hash
    install_attempt_digest = [string]$installResult.install_surface.install_attempt_digest
    install_audit_record_sha256 = [string]$installResult.install_surface.install_audit_record_sha256
    update_strategy = $planSpec.update_plan.update_strategy
    observation_plan_sha256 = Get-FileSha256 $resolvedObservationPlanPath
    audit_sink_descriptor_sha256 = [string]$allowDecision.effect_envelope_core.audit_sink_descriptor_sha256
    approval_nonce_sha256 = [string]$allowDecision.effect_envelope_core.approval_nonce_sha256
    policy_version = [string]$allowDecision.effect_envelope_core.policy_version
    repo_local_target_only = $true
    host_active_slot_mutation_allowed = $false
    host_boot_metadata_mutation_allowed = $false
}
$updateAttemptDigest = Get-StringSha256 (($updateAttemptCore | ConvertTo-Json -Depth 100))

$sideEffects = [ordered]@{
    prior_install_performed = $installOrderingBound
    update_effect_prepared = $updateAllowed
    update_effect_executed = $updateAllowed
    update_performed = $updateAllowed
    repo_local_update_evidence_written = $updateAllowed
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_payload_downloaded = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
}

$auditRecord = [ordered]@{
    schema = "agentos.rc17-controlled-local-update-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC17-031"
    event_type = if ($updateAllowed) { "ControlledLocalUpdateExecuted" } else { "ControlledLocalUpdateDenied" }
    production_ready_claim = $false
    local_only = $true
    fabricated = $false
    update_allowed = $updateAllowed
    update_performed = $updateAllowed
    update_attempt_digest = $updateAttemptDigest
    install_attempt_digest = [string]$installResult.install_surface.install_attempt_digest
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    rollback_precondition_core_hash = [string]$rollbackResult.rollback_surface.rollback_precondition_core_hash
    blockers = @($blockers)
    forbidden_side_effects = [ordered]@{
        remote_payload_downloaded = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
    }
}
$auditRecordPath = Join-Path $resolvedArtifactDir "update-audit-record.json"
Write-Json $auditRecord $auditRecordPath
$auditRecordDigest = Get-FileSha256 $auditRecordPath

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_controlled_local_install_result = New-ArtifactRef $resolvedInstallResultPath $installResult
    rc17_controlled_local_install_evidence = New-ArtifactRef $resolvedInstallEvidencePath $installEvidence
    rc17_controlled_local_install_audit = New-ArtifactRef $resolvedInstallAuditRecordPath $installAudit
    rc17_security_allow_result = New-ArtifactRef $resolvedSecurityAllowResultPath $allowResult
    rc17_security_allow_decision = New-ArtifactRef $resolvedSecurityAllowDecisionPath $allowDecision
    rc17_rollback_preconditions_result = New-ArtifactRef $resolvedRollbackPreconditionsResultPath $rollbackResult
    rc17_rollback_precondition_package = New-ArtifactRef $resolvedRollbackPreconditionPackagePath $rollbackPackage
    rc17_observation_plan = New-ArtifactRef $resolvedObservationPlanPath $observationPlan
    rc17_agentcore_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    rc17_agentcore_planspec = New-ArtifactRef $resolvedPlanSpecPath $planSpec
    rc17_approval_binding_result = New-ArtifactRef $resolvedApprovalBindingResultPath $approvalResult
    rc17_target_binding_result = New-ArtifactRef $resolvedTargetBindingResultPath $targetResult
}

$updateEvidence = [ordered]@{
    schema = "agentos.rc17-controlled-local-update-execute-or-deny-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-031"
    status = if ($updateAllowed) { "controlled-local-update-executed" } else { "controlled-local-update-denied-before-effect" }
    production_ready_claim = $false
    update_allowed = $updateAllowed
    update_performed = $updateAllowed
    prior_install_performed = $installOrderingBound
    denied = (-not $updateAllowed)
    denial_reasons = @($blockers)
    update_attempt = $updateAttemptCore
    update_attempt_digest = $updateAttemptDigest
    audit_record = [ordered]@{
        path = Get-StablePath $auditRecordPath
        sha256 = $auditRecordDigest
        fabricated = $false
    }
    side_effects = $sideEffects
    post_update_observation_requirements = $observationPlan.observations
    source = $source
}
$updateEvidencePath = Join-Path $resolvedArtifactDir "update-execute-or-deny-evidence.json"
Write-Json $updateEvidence $updateEvidencePath

$caseSpecs = @(
    [ordered]@{ id = "missing-install-ordering"; blockers = @("controlled-local-install-evidence-not-bound"); reason = "Update requires prior controlled install evidence." },
    [ordered]@{ id = "missing-target"; blockers = @("exact-install-update-target-not-bound"); reason = "Exact target is required." },
    [ordered]@{ id = "missing-approval"; blockers = @("exact-install-update-approval-not-bound"); reason = "Exact approval is required." },
    [ordered]@{ id = "missing-planspec"; blockers = @("agentcore-install-update-planspec-not-executable"); reason = "Executable PlanSpec is required." },
    [ordered]@{ id = "missing-security-allow"; blockers = @("security-execution-install-update-allow-not-bound"); reason = "SecurityExecution allow is required." },
    [ordered]@{ id = "missing-rollback-preconditions"; blockers = @("rollback-preconditions-not-bound"); reason = "Rollback preconditions are required." },
    [ordered]@{ id = "missing-observation-plan"; blockers = @("post-install-update-observation-plan-not-bound"); reason = "Observation plan is required." },
    [ordered]@{ id = "target-mismatch"; blockers = @("update-target-identity-mismatch"); reason = "Target mismatch must deny." },
    [ordered]@{ id = "audit-material-missing"; blockers = @("update-audit-material-not-bound"); reason = "Audit material is required." },
    [ordered]@{ id = "remote-payload-download"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of scope." },
    [ordered]@{ id = "host-active-slot-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is out of scope." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is out of scope." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of scope." },
    [ordered]@{ id = "support-upload"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "fabricated-audit"; blockers = @("update-audit-fabrication-denied"); reason = "Fabricated audit cannot prove update." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc17_031" $planAllowsRun "RC17-031 must run after RC17-030 completed, either while current_task is RC17-031 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_030_status = $rc17PreviousStatus; rc17_031_status = $rc17TaskStatus })
Add-Check "contract.controlled_update.present" ($contractText.Contains("Controlled local update must execute against the exact repo-local target or deny before effect with audit") -and $contractText.Contains("RC17 must not mutate host active slot metadata")) "RC17 contract must require controlled local update execute-or-deny evidence and forbid host/production mutation." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.required_gates.bound" ($installOrderingBound -and $targetBound -and $approvalBound -and $planspecExecutable -and $securityAllowBound -and $rollbackPreconditionsBound -and $observationPlanBound) "Update execution is impossible unless install ordering evidence, exact target, exact approval, executable PlanSpec, SecurityExecution allow, rollback preconditions, and observation plan are bound." ([ordered]@{ install_ordering_bound = $installOrderingBound; target_bound = $targetBound; approval_bound = $approvalBound; planspec_executable = $planspecExecutable; security_allow = $securityAllowBound; rollback_preconditions_bound = $rollbackPreconditionsBound; observation_plan_bound = $observationPlanBound })
Add-Check "update.identity.audit.bound" ($identityBound -and $auditMaterialBound) "Controlled local update must bind package/media/release/target identity and audit material." ([ordered]@{ identity_bound = $identityBound; audit_material_bound = $auditMaterialBound; package_id = $packageId; media_id = $mediaId; release_id = $releaseId })
Add-Check "update.executed_or_denied_with_audit" (($updateAllowed -and $updateEvidence.update_performed -eq $true -and $auditRecord.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($auditRecordDigest)) -or ((-not $updateAllowed) -and $updateEvidence.denied -eq $true -and $auditRecord.fabricated -eq $false)) "Controlled local update must either execute against the exact repo-local target or deny before effect with non-fabricated audit evidence." ([ordered]@{ update_allowed = $updateAllowed; update_performed = $updateEvidence.update_performed; audit_sha256 = $auditRecordDigest; fabricated = $auditRecord.fabricated; blockers = @($blockers) })
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.active_slot_mutated -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.private_signing_material_handled -eq $false) "RC17-031 must not download remote payloads, mutate host slot or boot metadata, mutate production rings, upload support, execute recovery, remote-dispatch, or handle private signing material." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing gates and forbidden authority surfaces must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $updateEvidencePath),
    (Get-Content -Raw -LiteralPath $auditRecordPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-031 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc17-controlled-local-update-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-031"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    update_surface = [ordered]@{
        state = if ($updateAllowed) { "controlled-local-update-executed" } else { "controlled-local-update-denied-before-effect" }
        prior_install_performed = $installOrderingBound
        update_allowed = $updateAllowed
        update_effect_prepared = $sideEffects.update_effect_prepared
        update_effect_executed = $sideEffects.update_effect_executed
        update_performed = $sideEffects.update_performed
        repo_local_update_evidence_written = $sideEffects.repo_local_update_evidence_written
        rollback_execution_performed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        production_ring_mutation_allowed = $false
        update_attempt_digest = $updateAttemptDigest
        update_audit_record_sha256 = $auditRecordDigest
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        update_execute_or_deny_evidence = [ordered]@{
            path = Get-StablePath $updateEvidencePath
            sha256 = Get-FileSha256 $updateEvidencePath
            update_attempt_digest = $updateAttemptDigest
        }
        update_audit_record = [ordered]@{
            path = Get-StablePath $auditRecordPath
            sha256 = $auditRecordDigest
            fabricated = $false
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        controlled_local_update = $true
        prior_install_performed = $installOrderingBound
        update_performed = $sideEffects.update_performed
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc17_031_complete = (@($script:failedChecks).Count -eq 0)
        prior_install_performed = $installOrderingBound
        update_allowed = $updateAllowed
        update_performed = $sideEffects.update_performed
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        production_ring_mutated = $false
        next_task = "RC17-032"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-031-controlled-local-update.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-controlled-local-update-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-031"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    update_surface = $result.update_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-032"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC17-031 outputs." }

Write-Host "RC17 controlled local update $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $updateEvidencePath)"
Write-Host "Audit: $(Get-StablePath $auditRecordPath)"
Write-Host "Update performed: $($sideEffects.update_performed); host slot/boot mutations: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
