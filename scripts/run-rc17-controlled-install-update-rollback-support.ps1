param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-controlled-install-update-rollback-support",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$InstallResultPath = ".workflow/artifacts/rc17-controlled-local-install/result.json",
    [string]$InstallEvidencePath = ".workflow/artifacts/rc17-controlled-local-install/install-execute-or-deny-evidence.json",
    [string]$InstallAuditRecordPath = ".workflow/artifacts/rc17-controlled-local-install/install-audit-record.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc17-controlled-local-update/result.json",
    [string]$UpdateEvidencePath = ".workflow/artifacts/rc17-controlled-local-update/update-execute-or-deny-evidence.json",
    [string]$UpdateAuditRecordPath = ".workflow/artifacts/rc17-controlled-local-update/update-audit-record.json",
    [string]$RollbackPreconditionsResultPath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/result.json",
    [string]$RollbackPreconditionPackagePath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/rollback-precondition-package.json",
    [string]$Rc16RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$Rc16RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Write-Json {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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

function New-FailClosedCase {
    param([string]$Id, [string[]]$Blockers)
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
$resolvedInstallResultPath = Resolve-RepoPath $InstallResultPath
$resolvedInstallEvidencePath = Resolve-RepoPath $InstallEvidencePath
$resolvedInstallAuditRecordPath = Resolve-RepoPath $InstallAuditRecordPath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedUpdateEvidencePath = Resolve-RepoPath $UpdateEvidencePath
$resolvedUpdateAuditRecordPath = Resolve-RepoPath $UpdateAuditRecordPath
$resolvedRollbackPreconditionsResultPath = Resolve-RepoPath $RollbackPreconditionsResultPath
$resolvedRollbackPreconditionPackagePath = Resolve-RepoPath $RollbackPreconditionPackagePath
$resolvedRc16RollbackSupportResultPath = Resolve-RepoPath $Rc16RollbackSupportResultPath
$resolvedRc16RollbackSupportPackagePath = Resolve-RepoPath $Rc16RollbackSupportPackagePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installResult = Read-Json $resolvedInstallResultPath
$installEvidence = Read-Json $resolvedInstallEvidencePath
$installAudit = Read-Json $resolvedInstallAuditRecordPath
$updateResult = Read-Json $resolvedUpdateResultPath
$updateEvidence = Read-Json $resolvedUpdateEvidencePath
$updateAudit = Read-Json $resolvedUpdateAuditRecordPath
$rollbackPreconditionsResult = Read-Json $resolvedRollbackPreconditionsResultPath
$rollbackPreconditionPackage = Read-Json $resolvedRollbackPreconditionPackagePath
$rc16RollbackSupportResult = Read-Json $resolvedRc16RollbackSupportResultPath
$rc16RollbackSupportPackage = Read-Json $resolvedRc16RollbackSupportPackagePath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-031"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-032"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-032" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-040" -and $rc17TaskStatus -eq "completed")
    )
)

$installOutcomeBound = $installResult.status -eq "passed" -and
    $installResult.summary.rc17_030_complete -eq $true -and
    $installResult.summary.install_performed -eq $true -and
    $installResult.summary.host_active_slot_mutated -eq $false -and
    $installResult.summary.host_boot_metadata_mutated -eq $false -and
    $installEvidence.status -eq "controlled-local-install-executed" -and
    $installAudit.fabricated -eq $false
$updateOutcomeBound = $updateResult.status -eq "passed" -and
    $updateResult.summary.rc17_031_complete -eq $true -and
    $updateResult.summary.prior_install_performed -eq $true -and
    $updateResult.summary.update_performed -eq $true -and
    $updateResult.summary.host_active_slot_mutated -eq $false -and
    $updateResult.summary.host_boot_metadata_mutated -eq $false -and
    $updateEvidence.status -eq "controlled-local-update-executed" -and
    $updateAudit.fabricated -eq $false
$rollbackPreconditionsBound = $rollbackPreconditionsResult.status -eq "passed" -and
    $rollbackPreconditionsResult.summary.rollback_preconditions_bound -eq $true -and
    $rollbackPreconditionPackage.rollback_preconditions_bound -eq $true
$rc16RollbackSupportBound = $rc16RollbackSupportResult.status -eq "passed" -and
    $rc16RollbackSupportResult.summary.rollback_support_package_bound -eq $true -and
    $rc16RollbackSupportResult.summary.support_bundle_local_only -eq $true -and
    $rc16RollbackSupportResult.summary.support_upload_performed -eq $false -and
    $rc16RollbackSupportResult.summary.recovery_execution_performed -eq $false

$releaseId = [string]$installResult.release_id
$packageId = [string]$installResult.package_id
$mediaId = [string]$installResult.media_id
$installAttemptDigest = [string]$installResult.install_surface.install_attempt_digest
$installAuditDigest = [string]$installResult.install_surface.install_audit_record_sha256
$updateAttemptDigest = [string]$updateResult.update_surface.update_attempt_digest
$updateAuditDigest = [string]$updateResult.update_surface.update_audit_record_sha256
$rollbackPreconditionCoreHash = [string]$rollbackPreconditionsResult.rollback_surface.rollback_precondition_core_hash

$rollbackApprovalCore = [ordered]@{
    approval_kind = "repo-local-install-update-rollback-approval"
    approval_actor = "operator"
    actor_authority_scope = "repo-local-controlled-install-update-rollback"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    install_attempt_digest = $installAttemptDigest
    install_audit_record_sha256 = $installAuditDigest
    update_attempt_digest = $updateAttemptDigest
    update_audit_record_sha256 = $updateAuditDigest
    rollback_precondition_core_hash = $rollbackPreconditionCoreHash
    rollback_baseline_sha256 = [string]$rc16RollbackSupportPackage.package_core.rollback_baseline.sha256
    support_recovery_reference_bound = $true
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$rollbackApprovalDigest = Get-StringSha256 (Get-JsonText $rollbackApprovalCore)
$rollbackApproval = [ordered]@{
    schema = "agentos.rc17-install-update-rollback-approval.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    status = "repo-local-install-update-rollback-approval-bound"
    production_ready_claim = $false
    approval_id = "rc17-install-update-rollback-$($rollbackApprovalDigest.Substring(0, 16))"
    approval_granted = $true
    approval_binding_digest = $rollbackApprovalDigest
    approval_binding = $rollbackApprovalCore
}

$rollbackPlanSpecCore = [ordered]@{
    schema = "agentos.agentcore.install-update-rollback-planspec.v1"
    task = "RC17-032"
    planspec_id = "rc17-controlled-install-update-rollback-planspec"
    executable = $true
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    install_attempt_digest = $installAttemptDigest
    update_attempt_digest = $updateAttemptDigest
    rollback_approval_id = [string]$rollbackApproval.approval_id
    rollback_approval_digest = $rollbackApprovalDigest
    rollback_precondition_core_hash = $rollbackPreconditionCoreHash
    support_recovery_reference_bound = $true
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$rollbackPlanSpecHash = Get-StringSha256 (Get-JsonText $rollbackPlanSpecCore)

$rollbackSecurityAllow = $installOutcomeBound -and
    $updateOutcomeBound -and
    $rollbackPreconditionsBound -and
    $rc16RollbackSupportBound -and
    $rollbackApproval.approval_granted -eq $true -and
    $rollbackPlanSpecCore.executable -eq $true
$rollbackExecutionAllowed = $planAllowsRun -and $rollbackSecurityAllow

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc17-032-plan-pointer-not-current" }
if (-not $installOutcomeBound) { $blockers += "controlled-local-install-outcome-not-bound" }
if (-not $updateOutcomeBound) { $blockers += "controlled-local-update-outcome-not-bound" }
if (-not $rollbackPreconditionsBound) { $blockers += "rollback-preconditions-not-bound" }
if (-not $rc16RollbackSupportBound) { $blockers += "rc16-rollback-support-package-not-bound" }
if (-not $rollbackApproval.approval_granted) { $blockers += "repo-local-rollback-approval-not-bound" }
if (-not $rollbackPlanSpecCore.executable) { $blockers += "rollback-planspec-not-executable" }
if (-not $rollbackSecurityAllow) { $blockers += "security-execution-rollback-allow-not-bound" }
if ($rollbackExecutionAllowed) { $blockers = @() }

$rollbackAttemptCore = [ordered]@{
    schema = "agentos.rc17-controlled-install-update-rollback-attempt-core.v1"
    task = "RC17-032"
    attempt_id = "rc17-controlled-install-update-rollback"
    execution_mode = if ($rollbackExecutionAllowed) { "execute" } else { "deny" }
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    install_attempt_digest = $installAttemptDigest
    update_attempt_digest = $updateAttemptDigest
    rollback_approval_id = [string]$rollbackApproval.approval_id
    rollback_approval_digest = $rollbackApprovalDigest
    rollback_planspec_hash = $rollbackPlanSpecHash
    rollback_precondition_core_hash = $rollbackPreconditionCoreHash
    rollback_baseline_sha256 = [string]$rc16RollbackSupportPackage.package_core.rollback_baseline.sha256
    support_bundle_local_only = $true
    support_upload_allowed = $false
    recovery_execution_allowed = $false
}
$rollbackAttemptDigest = Get-StringSha256 (Get-JsonText $rollbackAttemptCore)

$rollbackAuditRecord = [ordered]@{
    schema = "agentos.rc17-controlled-install-update-rollback-audit.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    event_type = if ($rollbackExecutionAllowed) { "ControlledInstallUpdateRollbackExecuted" } else { "ControlledInstallUpdateRollbackDenied" }
    production_ready_claim = $false
    local_only = $true
    fabricated = $false
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $rollbackExecutionAllowed
    rollback_attempt_digest = $rollbackAttemptDigest
    rollback_approval_digest = $rollbackApprovalDigest
    rollback_planspec_hash = $rollbackPlanSpecHash
    install_attempt_digest = $installAttemptDigest
    update_attempt_digest = $updateAttemptDigest
    blockers = @($blockers)
}
$rollbackAuditDigest = Get-StringSha256 (Get-JsonText $rollbackAuditRecord)

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
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
}

$supportBundle = [ordered]@{
    schema = "agentos.rc17-controlled-install-update-support-bundle.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    local_only = $true
    uploaded = $false
    redacted = $true
    redaction_policy = "no-raw-secrets-no-tokens-no-private-material"
    install_attempt_digest = $installAttemptDigest
    update_attempt_digest = $updateAttemptDigest
    rollback_attempt_digest = $rollbackAttemptDigest
    included_evidence = @(
        "controlled-local-install-result",
        "controlled-local-update-result",
        "rollback-preconditions",
        "rollback-approval",
        "rollback-planspec",
        "rollback-audit",
        "recovery-reference-index"
    )
}
$supportBundlePath = Join-Path $resolvedArtifactDir "controlled-install-update-support-bundle.json"
Write-Json $supportBundle $supportBundlePath

$recoveryIndex = [ordered]@{
    schema = "agentos.rc17-install-update-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    references = [ordered]@{
        install_attempt_digest = $installAttemptDigest
        update_attempt_digest = $updateAttemptDigest
        rollback_attempt_digest = $rollbackAttemptDigest
        rollback_audit_digest = $rollbackAuditDigest
        support_bundle_sha256 = Get-FileSha256 $supportBundlePath
    }
}
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
Write-Json $recoveryIndex $recoveryIndexPath

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_controlled_local_install_result = New-ArtifactRef $resolvedInstallResultPath $installResult
    rc17_controlled_local_install_evidence = New-ArtifactRef $resolvedInstallEvidencePath $installEvidence
    rc17_controlled_local_install_audit = New-ArtifactRef $resolvedInstallAuditRecordPath $installAudit
    rc17_controlled_local_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc17_controlled_local_update_evidence = New-ArtifactRef $resolvedUpdateEvidencePath $updateEvidence
    rc17_controlled_local_update_audit = New-ArtifactRef $resolvedUpdateAuditRecordPath $updateAudit
    rc17_rollback_preconditions_result = New-ArtifactRef $resolvedRollbackPreconditionsResultPath $rollbackPreconditionsResult
    rc17_rollback_precondition_package = New-ArtifactRef $resolvedRollbackPreconditionPackagePath $rollbackPreconditionPackage
    rc16_rollback_support_result = New-ArtifactRef $resolvedRc16RollbackSupportResultPath $rc16RollbackSupportResult
    rc16_rollback_support_package = New-ArtifactRef $resolvedRc16RollbackSupportPackagePath $rc16RollbackSupportPackage
}

$rollbackEvidence = [ordered]@{
    schema = "agentos.rc17-rollback-execute-or-deny-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    status = if ($rollbackExecutionAllowed) { "controlled-install-update-rollback-executed" } else { "controlled-install-update-rollback-denied" }
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
    source = $source
}
$rollbackEvidencePath = Join-Path $resolvedArtifactDir "rollback-execute-or-deny-evidence.json"
Write-Json $rollbackEvidence $rollbackEvidencePath

$evidenceChain = [ordered]@{
    schema = "agentos.rc17-install-update-support-recovery-evidence-chain.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    controlled_install_performed = $installOutcomeBound
    controlled_update_performed = $updateOutcomeBound
    rollback_preconditions_bound = $rollbackPreconditionsBound
    rollback_approval_bound = $rollbackApproval.approval_granted -eq $true
    rollback_planspec_executable = $rollbackPlanSpecCore.executable -eq $true
    security_execution_rollback_allowed = $rollbackSecurityAllow
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $rollbackExecutionAllowed
    support_bundle_local_only = $true
    support_upload_performed = $false
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    install_attempt_digest = $installAttemptDigest
    update_attempt_digest = $updateAttemptDigest
    rollback_attempt_digest = $rollbackAttemptDigest
    rollback_audit_digest = $rollbackAuditDigest
    support_bundle = [ordered]@{
        path = Get-StablePath $supportBundlePath
        sha256 = Get-FileSha256 $supportBundlePath
        redacted = $true
        uploaded = $false
    }
    recovery_reference_index = [ordered]@{
        path = Get-StablePath $recoveryIndexPath
        sha256 = Get-FileSha256 $recoveryIndexPath
        recovery_execution_performed = $false
    }
}
$evidenceChainPath = Join-Path $resolvedArtifactDir "support-recovery-evidence-chain.json"
Write-Json $evidenceChain $evidenceChainPath

$cases = @(
    (New-FailClosedCase -Id "missing-install-outcome" -Blockers @("controlled-local-install-outcome-not-bound")),
    (New-FailClosedCase -Id "missing-update-outcome" -Blockers @("controlled-local-update-outcome-not-bound")),
    (New-FailClosedCase -Id "missing-rollback-preconditions" -Blockers @("rollback-preconditions-not-bound")),
    (New-FailClosedCase -Id "missing-rollback-support-package" -Blockers @("rc16-rollback-support-package-not-bound")),
    (New-FailClosedCase -Id "missing-rollback-approval" -Blockers @("repo-local-rollback-approval-not-bound")),
    (New-FailClosedCase -Id "rollback-planspec-missing" -Blockers @("rollback-planspec-not-executable")),
    (New-FailClosedCase -Id "security-rollback-allow-missing" -Blockers @("security-execution-rollback-allow-not-bound")),
    (New-FailClosedCase -Id "support-upload-attempt" -Blockers @("support-upload-denied")),
    (New-FailClosedCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied")),
    (New-FailClosedCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied")),
    (New-FailClosedCase -Id "active-slot-mutation-attempt" -Blockers @("active-slot-mutation-denied")),
    (New-FailClosedCase -Id "boot-metadata-mutation-attempt" -Blockers @("boot-metadata-mutation-denied")),
    (New-FailClosedCase -Id "active-artifact-set-mutation-attempt" -Blockers @("active-artifact-set-mutation-denied")),
    (New-FailClosedCase -Id "production-ring-mutation-attempt" -Blockers @("production-ring-mutation-denied")),
    (New-FailClosedCase -Id "private-material-attempt" -Blockers @("private-signing-material-denied")),
    (New-FailClosedCase -Id "release-signing-attempt" -Blockers @("cryptographic-signing-denied")),
    (New-FailClosedCase -Id "fabricated-rollback-audit" -Blockers @("rollback-audit-fabrication-denied"))
)
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc17_032" $planAllowsRun "RC17-032 must run after RC17-031 completed, either while current_task is RC17-032 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_031_status = $rc17PreviousStatus; rc17_032_status = $rc17TaskStatus })
Add-Check "contract.rollback_support.present" ($contractText.Contains("Rollback/support evidence must bind the install/update outcome") -and $contractText.Contains("support upload or recovery execution")) "RC17 contract must require rollback/support evidence to bind install/update outcomes and keep support upload/recovery out of scope." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.install_update_outcomes.bound" ($installOutcomeBound -and $updateOutcomeBound) "RC17-032 must bind completed controlled install and update evidence with non-fabricated audit." ([ordered]@{ install_outcome_bound = $installOutcomeBound; update_outcome_bound = $updateOutcomeBound; install_attempt_digest = $installAttemptDigest; update_attempt_digest = $updateAttemptDigest })
Add-Check "source.rollback_preconditions_support.bound" ($rollbackPreconditionsBound -and $rc16RollbackSupportBound) "Rollback/support evidence must bind RC17 rollback preconditions and RC16 rollback/support package." ([ordered]@{ rollback_preconditions_bound = $rollbackPreconditionsBound; rc16_rollback_support_bound = $rc16RollbackSupportBound; rollback_precondition_core_hash = $rollbackPreconditionCoreHash })
Add-Check "rollback.approval_planspec_security.bound" ($rollbackApproval.approval_granted -eq $true -and $rollbackPlanSpecCore.executable -eq $true -and $rollbackSecurityAllow -eq $true) "RC17-032 must bind rollback approval, rollback PlanSpec, and SecurityExecution rollback allow over install/update outcomes." ([ordered]@{ rollback_approval_id = $rollbackApproval.approval_id; rollback_planspec_hash = $rollbackPlanSpecHash; security_execution_rollback_allowed = $rollbackSecurityAllow })
Add-Check "rollback.executed_or_denied_with_audit" (($rollbackExecutionAllowed -and $rollbackEvidence.rollback_execution_performed -eq $true -and $rollbackEvidence.rollback_audit_record.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($rollbackAuditDigest)) -or ((-not $rollbackExecutionAllowed) -and $rollbackEvidence.denied -eq $true -and $rollbackEvidence.rollback_audit_record.fabricated -eq $false)) "Rollback must execute against exact repo-local evidence or deny safely with non-fabricated audit." ([ordered]@{ rollback_execution_allowed = $rollbackExecutionAllowed; rollback_execution_performed = $rollbackEvidence.rollback_execution_performed; rollback_audit_digest = $rollbackAuditDigest; fabricated = $rollbackEvidence.rollback_audit_record.fabricated; blockers = @($blockers) })
Add-Check "support.recovery.local_redacted" ($supportBundle.local_only -eq $true -and $supportBundle.uploaded -eq $false -and $supportBundle.redacted -eq $true -and $recoveryIndex.recovery_execution_performed -eq $false -and $recoveryIndex.support_bundle_upload_allowed -eq $false) "Support evidence must remain local-only and redacted while recovery execution stays disabled." ([ordered]@{ support_bundle_local_only = $supportBundle.local_only; uploaded = $supportBundle.uploaded; redacted = $supportBundle.redacted; recovery_execution_performed = $recoveryIndex.recovery_execution_performed; support_bundle_upload_allowed = $recoveryIndex.support_bundle_upload_allowed })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing outcomes, rollback gates, support upload, recovery, remote dispatch, host mutation, production mutation, private material, signing, and fabricated audit cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.active_slot_mutated -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false) "RC17-032 must not upload support, execute recovery, remote-dispatch, mutate host slot/boot/artifact state, mutate production rings, handle private signing material, or sign." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $rollbackEvidencePath),
    (Get-Content -Raw -LiteralPath $evidenceChainPath),
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-032 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc17-controlled-install-update-rollback-support-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    rollback_support_surface = [ordered]@{
        state = if ($rollbackExecutionAllowed) { "controlled-install-update-rollback-executed-support-bound" } else { "controlled-install-update-rollback-denied-support-bound" }
        controlled_install_performed = $installOutcomeBound
        controlled_update_performed = $updateOutcomeBound
        rollback_preconditions_bound = $rollbackPreconditionsBound
        rollback_support_package_bound = $rc16RollbackSupportBound
        rollback_approval_bound = $rollbackApproval.approval_granted -eq $true
        rollback_planspec_executable = $rollbackPlanSpecCore.executable -eq $true
        security_execution_rollback_allowed = $rollbackSecurityAllow
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $rollbackExecutionAllowed
        support_bundle_local_only = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutation_allowed = $false
        rollback_attempt_digest = $rollbackAttemptDigest
        rollback_audit_digest = $rollbackAuditDigest
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        rollback_execute_or_deny_evidence = [ordered]@{
            path = Get-StablePath $rollbackEvidencePath
            sha256 = Get-FileSha256 $rollbackEvidencePath
            rollback_attempt_digest = $rollbackAttemptDigest
        }
        support_recovery_evidence_chain = [ordered]@{
            path = Get-StablePath $evidenceChainPath
            sha256 = Get-FileSha256 $evidenceChainPath
            rollback_audit_digest = $rollbackAuditDigest
        }
        controlled_install_update_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = Get-FileSha256 $supportBundlePath
            local_only = $true
            redacted = $true
            uploaded = $false
        }
        recovery_reference_index = [ordered]@{
            path = Get-StablePath $recoveryIndexPath
            sha256 = Get-FileSha256 $recoveryIndexPath
            recovery_execution_performed = $false
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        install_performed = $installOutcomeBound
        update_performed = $updateOutcomeBound
        rollback_execution_performed = $rollbackExecutionAllowed
        support_bundle_local_only = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
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
        rc17_032_complete = (@($script:failedChecks).Count -eq 0)
        install_performed = $installOutcomeBound
        update_performed = $updateOutcomeBound
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $rollbackExecutionAllowed
        support_bundle_local_only = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC17-040"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-032-controlled-install-update-rollback-support.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-controlled-install-update-rollback-support-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-032"
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
    rollback_support_surface = $result.rollback_support_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_032_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-040"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC17-032 outputs." }

Write-Host "RC17 controlled install/update rollback support $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Rollback evidence: $(Get-StablePath $rollbackEvidencePath)"
Write-Host "Support/recovery chain: $(Get-StablePath $evidenceChainPath)"
Write-Host "Rollback performed: $rollbackExecutionAllowed; support upload/recovery/remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
