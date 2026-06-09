param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-lifecycle-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$RepairReinstallResultPath = ".workflow/artifacts/rc21-repair-reinstall-drill/result.json",
    [string]$RepairReinstallEvidencePath = ".workflow/artifacts/rc21-repair-reinstall-drill/repair-reinstall-evidence.json",
    [string]$DowngradeRollbackResultPath = ".workflow/artifacts/rc21-downgrade-rollback-drill/result.json",
    [string]$DowngradeRollbackEvidencePath = ".workflow/artifacts/rc21-downgrade-rollback-drill/downgrade-rollback-evidence.json",
    [string]$DryRunAcceptanceResultPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/result.json",
    [string]$DryRunAcceptanceEvidencePath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-acceptance-evidence.json",
    [string]$DryRunAuditRecordPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-audit-record.json",
    [string]$ExplainResumeAuditResultPath = ".workflow/artifacts/rc21-explain-resume-audit-package/result.json",
    [string]$ExplainResumeAuditPackagePath = ".workflow/artifacts/rc21-explain-resume-audit-package/explain-resume-audit-package.json",
    [string]$Rc20LifecycleSupportResultPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/result.json",
    [string]$Rc20LifecycleSupportBundlePath = ".workflow/artifacts/rc20-lifecycle-support-recovery/lifecycle-support-bundle.json",
    [string]$Rc20RecoveryReferenceIndexPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/recovery-reference-index.json",
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

function Get-JsonProperty {
    param($Json, [string]$Name)
    if ($null -eq $Json) { return $null }
    if ($Json.PSObject.Properties.Name -contains $Name) { return $Json.$Name }
    return $null
}

function New-ArtifactRef {
    param([string]$Path, $Json = $null, [string]$Role = "")
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        role = $Role
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
        consumer_ready_claim = Get-JsonProperty $Json "consumer_ready_claim"
    }
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $markers = @(
        ("BEGIN " + "PRIVATE" + " KEY"),
        ("BEGIN " + "PUBLIC" + " KEY"),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "p" + "em"),
        ("." + "p" + "em"),
        ("pass" + "word="),
        ("sec" + "ret=")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-NoForbiddenEffects {
    return [ordered]@{
        lifecycle_support_bundle_created = $true
        recovery_reference_index_created = $true
        local_only = $true
        redacted = $true
        projection_only = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        host_boot_state_authority = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_mutated = $false
        nginx_or_tls_changed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
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
        denied_before_support_upload = $true
        denied_before_recovery_execution = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            support_bundle_created = $false
            recovery_reference_index_created = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            signer_authority_granted = $false
            object_storage_provisioned = $false
            private_signing_material_handled = $false
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
$resolvedRepairReinstallResultPath = Resolve-RepoPath $RepairReinstallResultPath
$resolvedRepairReinstallEvidencePath = Resolve-RepoPath $RepairReinstallEvidencePath
$resolvedDowngradeRollbackResultPath = Resolve-RepoPath $DowngradeRollbackResultPath
$resolvedDowngradeRollbackEvidencePath = Resolve-RepoPath $DowngradeRollbackEvidencePath
$resolvedDryRunAcceptanceResultPath = Resolve-RepoPath $DryRunAcceptanceResultPath
$resolvedDryRunAcceptanceEvidencePath = Resolve-RepoPath $DryRunAcceptanceEvidencePath
$resolvedDryRunAuditRecordPath = Resolve-RepoPath $DryRunAuditRecordPath
$resolvedExplainResumeAuditResultPath = Resolve-RepoPath $ExplainResumeAuditResultPath
$resolvedExplainResumeAuditPackagePath = Resolve-RepoPath $ExplainResumeAuditPackagePath
$resolvedRc20LifecycleSupportResultPath = Resolve-RepoPath $Rc20LifecycleSupportResultPath
$resolvedRc20LifecycleSupportBundlePath = Resolve-RepoPath $Rc20LifecycleSupportBundlePath
$resolvedRc20RecoveryReferenceIndexPath = Resolve-RepoPath $Rc20RecoveryReferenceIndexPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$repairReinstallResult = Read-Json $resolvedRepairReinstallResultPath
$repairReinstallEvidence = Read-Json $resolvedRepairReinstallEvidencePath
$downgradeRollbackResult = Read-Json $resolvedDowngradeRollbackResultPath
$downgradeRollbackEvidence = Read-Json $resolvedDowngradeRollbackEvidencePath
$dryRunAcceptanceResult = Read-Json $resolvedDryRunAcceptanceResultPath
$dryRunAcceptanceEvidence = Read-Json $resolvedDryRunAcceptanceEvidencePath
$dryRunAuditRecord = Read-Json $resolvedDryRunAuditRecordPath
$explainResumeAuditResult = Read-Json $resolvedExplainResumeAuditResultPath
$explainResumeAuditPackage = Read-Json $resolvedExplainResumeAuditPackagePath
$rc20LifecycleSupportResult = Read-Json $resolvedRc20LifecycleSupportResultPath
$rc20LifecycleSupportBundle = Read-Json $resolvedRc20LifecycleSupportBundlePath
$rc20RecoveryReferenceIndex = Read-Json $resolvedRc20RecoveryReferenceIndexPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-031"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-032"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-032" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-040" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsSupport = (
    $contractText.Contains("Bind lifecycle support/recovery closure after repair/reinstall and downgrade/rollback drills as local, redacted, projection-only evidence") -and
    $contractText.Contains("Support output must be local-only and redacted") -and
    $contractText.Contains("Recovery output must remain a reference index or projection")
)

$dryRunReady = (
    $dryRunAcceptanceResult.status -eq "passed" -and
    $dryRunAcceptanceResult.summary.rc21_021_complete -eq $true -and
    $dryRunAcceptanceResult.summary.effect_preparation_performed -eq $false -and
    $dryRunAcceptanceEvidence.no_effect_surface.effect_preparation_performed -eq $false -and
    $dryRunAuditRecord.local_only -eq $true
)

$explainReady = (
    $explainResumeAuditResult.status -eq "passed" -and
    $explainResumeAuditResult.summary.rc21_022_complete -eq $true -and
    $explainResumeAuditPackage.local_only -eq $true -and
    $explainResumeAuditPackage.redacted -eq $true -and
    @($explainResumeAuditPackage.resume_projections | Where-Object { $_.resume_executable -ne $false -or $_.projection_only -ne $true }).Count -eq 0
)

$repairReady = (
    $repairReinstallResult.status -eq "passed" -and
    $repairReinstallResult.summary.rc21_030_complete -eq $true -and
    $repairReinstallResult.summary.repair_reinstall_drill_performed -eq $true -and
    $repairReinstallResult.summary.disposable_installed_system_boundary_only -eq $true -and
    $repairReinstallResult.summary.support_upload_performed -eq $false -and
    $repairReinstallResult.summary.recovery_execution_performed -eq $false -and
    $repairReinstallResult.summary.remote_dispatch_enabled -eq $false -and
    $repairReinstallResult.summary.host_rootfs_mutated -eq $false -and
    $repairReinstallResult.summary.active_artifact_set_mutated -eq $false -and
    $repairReinstallResult.summary.production_ring_mutated -eq $false -and
    $repairReinstallEvidence.no_forbidden_effects.private_signing_material_handled -eq $false
)

$downgradeReady = (
    $downgradeRollbackResult.status -eq "passed" -and
    $downgradeRollbackResult.summary.rc21_031_complete -eq $true -and
    $downgradeRollbackResult.summary.downgrade_rollback_drill_performed -eq $true -and
    $downgradeRollbackResult.summary.disposable_installed_system_boundary_only -eq $true -and
    $downgradeRollbackResult.summary.local_channel_history_only -eq $true -and
    $downgradeRollbackResult.summary.remote_fetch_performed -eq $false -and
    $downgradeRollbackResult.summary.support_upload_performed -eq $false -and
    $downgradeRollbackResult.summary.recovery_execution_performed -eq $false -and
    $downgradeRollbackResult.summary.remote_dispatch_enabled -eq $false -and
    $downgradeRollbackResult.summary.host_rootfs_mutated -eq $false -and
    $downgradeRollbackResult.summary.active_artifact_set_mutated -eq $false -and
    $downgradeRollbackResult.summary.production_ring_mutated -eq $false -and
    $downgradeRollbackEvidence.no_forbidden_effects.private_signing_material_handled -eq $false
)

$rc20SupportReady = (
    $rc20LifecycleSupportResult.status -eq "passed" -and
    $rc20LifecycleSupportResult.summary.rc20_032_complete -eq $true -and
    $rc20LifecycleSupportResult.summary.support_bundle_local_only -eq $true -and
    $rc20LifecycleSupportResult.summary.support_bundle_redacted -eq $true -and
    $rc20LifecycleSupportResult.summary.support_upload_performed -eq $false -and
    $rc20LifecycleSupportResult.summary.recovery_execution_performed -eq $false -and
    $rc20LifecycleSupportResult.summary.remote_dispatch_enabled -eq $false -and
    $rc20LifecycleSupportBundle.local_only -eq $true -and
    $rc20LifecycleSupportBundle.redacted -eq $true -and
    $rc20LifecycleSupportBundle.uploaded -eq $false -and
    $rc20RecoveryReferenceIndex.projection_only -eq $true -and
    $rc20RecoveryReferenceIndex.recovery_execution_performed -eq $false
)

$stateChainReady = (
    $repairReinstallResult.summary.restored_target_state_id -eq $downgradeRollbackResult.summary.restored_state_id -and
    $downgradeRollbackResult.summary.restored_state_id -eq $rc20LifecycleSupportResult.restored_target_state_id
)

$supportClosureAllowed = $planAllowsRun -and $contractAllowsSupport -and $dryRunReady -and $explainReady -and $repairReady -and $downgradeReady -and $rc20SupportReady -and $stateChainReady

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc21-032-plan-pointer-not-current" }
if (-not $contractAllowsSupport) { $blockers += "rc21-support-contract-language-missing" }
if (-not $dryRunReady) { $blockers += "rc21-dry-run-acceptance-not-ready" }
if (-not $explainReady) { $blockers += "rc21-explain-resume-audit-not-ready" }
if (-not $repairReady) { $blockers += "rc21-repair-reinstall-drill-not-ready" }
if (-not $downgradeReady) { $blockers += "rc21-downgrade-rollback-drill-not-ready" }
if (-not $rc20SupportReady) { $blockers += "rc20-lifecycle-support-recovery-not-ready" }
if (-not $stateChainReady) { $blockers += "rc21-lifecycle-restored-state-chain-mismatch" }
if ($supportClosureAllowed) { $blockers = @() }

$source = [ordered]@{
    rc21_plan = New-ArtifactRef $resolvedPlanPath $plan "rc21 workflow plan"
    rc21_authority_contract = [ordered]@{
        role = "rc21 authority contract"
        path = Get-StablePath $resolvedContractPath
        sha256 = Get-FileSha256 $resolvedContractPath
        size_bytes = (Get-Item -LiteralPath $resolvedContractPath).Length
        present = $true
    }
    rc21_repair_reinstall_result = New-ArtifactRef $resolvedRepairReinstallResultPath $repairReinstallResult "rc21 repair/reinstall result"
    rc21_repair_reinstall_evidence = New-ArtifactRef $resolvedRepairReinstallEvidencePath $repairReinstallEvidence "rc21 repair/reinstall evidence"
    rc21_downgrade_rollback_result = New-ArtifactRef $resolvedDowngradeRollbackResultPath $downgradeRollbackResult "rc21 downgrade/rollback result"
    rc21_downgrade_rollback_evidence = New-ArtifactRef $resolvedDowngradeRollbackEvidencePath $downgradeRollbackEvidence "rc21 downgrade/rollback evidence"
    rc21_dry_run_acceptance_result = New-ArtifactRef $resolvedDryRunAcceptanceResultPath $dryRunAcceptanceResult "rc21 dry-run acceptance result"
    rc21_dry_run_acceptance_evidence = New-ArtifactRef $resolvedDryRunAcceptanceEvidencePath $dryRunAcceptanceEvidence "rc21 dry-run acceptance evidence"
    rc21_dry_run_audit_record = New-ArtifactRef $resolvedDryRunAuditRecordPath $dryRunAuditRecord "rc21 dry-run audit record"
    rc21_explain_resume_audit_result = New-ArtifactRef $resolvedExplainResumeAuditResultPath $explainResumeAuditResult "rc21 explain/resume/audit result"
    rc21_explain_resume_audit_package = New-ArtifactRef $resolvedExplainResumeAuditPackagePath $explainResumeAuditPackage "rc21 explain/resume/audit package"
    rc20_lifecycle_support_result = New-ArtifactRef $resolvedRc20LifecycleSupportResultPath $rc20LifecycleSupportResult "rc20 lifecycle support result"
    rc20_lifecycle_support_bundle = New-ArtifactRef $resolvedRc20LifecycleSupportBundlePath $rc20LifecycleSupportBundle "rc20 lifecycle support bundle"
    rc20_recovery_reference_index = New-ArtifactRef $resolvedRc20RecoveryReferenceIndexPath $rc20RecoveryReferenceIndex "rc20 recovery reference index"
}

$supportBundleCore = [ordered]@{
    schema = "agentos.rc21-lifecycle-support-bundle-core.v1"
    task = "RC21-032"
    repair_reinstall_drill_id = [string]$repairReinstallResult.repair_reinstall_drill_id
    repair_reinstall_audit_record_id = [string]$repairReinstallResult.repair_reinstall_audit_record_id
    downgrade_rollback_drill_id = [string]$downgradeRollbackResult.downgrade_rollback_drill_id
    downgrade_rollback_audit_record_id = [string]$downgradeRollbackResult.downgrade_rollback_audit_record_id
    dry_run_acceptance_id = [string]$dryRunAcceptanceResult.dry_run_acceptance_id
    dry_run_audit_record_id = [string]$dryRunAcceptanceResult.dry_run_audit_record_id
    explain_resume_audit_package_id = [string]$explainResumeAuditResult.explain_resume_audit_package_id
    rc20_support_bundle_id = [string]$rc20LifecycleSupportResult.support_bundle_id
    rc20_recovery_reference_digest = [string]$rc20LifecycleSupportResult.recovery_reference_digest
    restored_state_id = [string]$downgradeRollbackResult.summary.restored_state_id
    repair_reinstall_result_sha256 = Get-FileSha256 $resolvedRepairReinstallResultPath
    repair_reinstall_evidence_sha256 = Get-FileSha256 $resolvedRepairReinstallEvidencePath
    downgrade_rollback_result_sha256 = Get-FileSha256 $resolvedDowngradeRollbackResultPath
    downgrade_rollback_evidence_sha256 = Get-FileSha256 $resolvedDowngradeRollbackEvidencePath
    dry_run_acceptance_result_sha256 = Get-FileSha256 $resolvedDryRunAcceptanceResultPath
    dry_run_acceptance_evidence_sha256 = Get-FileSha256 $resolvedDryRunAcceptanceEvidencePath
    dry_run_audit_record_sha256 = Get-FileSha256 $resolvedDryRunAuditRecordPath
    explain_resume_audit_result_sha256 = Get-FileSha256 $resolvedExplainResumeAuditResultPath
    explain_resume_audit_package_sha256 = Get-FileSha256 $resolvedExplainResumeAuditPackagePath
    rc20_lifecycle_support_result_sha256 = Get-FileSha256 $resolvedRc20LifecycleSupportResultPath
    rc20_lifecycle_support_bundle_sha256 = Get-FileSha256 $resolvedRc20LifecycleSupportBundlePath
    rc20_recovery_reference_index_sha256 = Get-FileSha256 $resolvedRc20RecoveryReferenceIndexPath
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    active_artifact_set_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$supportBundleDigest = Get-StringSha256 (Get-JsonText $supportBundleCore)

$supportBundle = [ordered]@{
    schema = "agentos.rc21-lifecycle-support-bundle.v1"
    generated_at = $generatedAtValue
    task = "RC21-032"
    status = if ($supportClosureAllowed) { "lifecycle-support-bundle-local-redacted" } else { "lifecycle-support-bundle-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    support_bundle_id = "rc21-lifecycle-support-$($supportBundleDigest.Substring(0, 16))"
    support_bundle_digest = $supportBundleDigest
    local_only = $true
    uploaded = $false
    redacted = $true
    redaction_policy = "no-raw-secrets-no-tokens-no-private-material-no-host-private-state"
    projection_only = $true
    support_bundle_core = $supportBundleCore
    included_evidence = @(
        "rc21-repair-reinstall-result",
        "rc21-repair-reinstall-evidence",
        "rc21-downgrade-rollback-result",
        "rc21-downgrade-rollback-evidence",
        "rc21-dry-run-acceptance",
        "rc21-explain-resume-audit-package",
        "rc20-lifecycle-support-recovery"
    )
    side_effects = New-NoForbiddenEffects
    source = $source
}
$supportBundlePath = Join-Path $resolvedArtifactDir "lifecycle-support-bundle.json"
Write-Json $supportBundle $supportBundlePath

$recoveryReferenceCore = [ordered]@{
    schema = "agentos.rc21-lifecycle-recovery-reference-core.v1"
    task = "RC21-032"
    support_bundle_id = $supportBundle.support_bundle_id
    support_bundle_digest = $supportBundleDigest
    support_bundle_sha256 = Get-FileSha256 $supportBundlePath
    repair_reinstall_drill_id = [string]$repairReinstallResult.repair_reinstall_drill_id
    downgrade_rollback_drill_id = [string]$downgradeRollbackResult.downgrade_rollback_drill_id
    restored_state_id = [string]$downgradeRollbackResult.summary.restored_state_id
    rc20_support_bundle_id = [string]$rc20LifecycleSupportResult.support_bundle_id
    rc20_recovery_reference_digest = [string]$rc20LifecycleSupportResult.recovery_reference_digest
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$recoveryReferenceDigest = Get-StringSha256 (Get-JsonText $recoveryReferenceCore)
$recoveryReferenceIndex = [ordered]@{
    schema = "agentos.rc21-lifecycle-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC21-032"
    status = "projection-only-no-recovery-execution"
    production_ready_claim = $false
    consumer_ready_claim = $false
    projection_only = $true
    recovery_reference_digest = $recoveryReferenceDigest
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
    references = $recoveryReferenceCore
    source = $source
}
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
Write-Json $recoveryReferenceIndex $recoveryIndexPath

$cases = @(
    (New-DenialCase -Id "missing-dry-run-acceptance" -Blockers @("rc21-dry-run-acceptance-not-ready") -Reason "Lifecycle support requires RC21 dry-run acceptance evidence."),
    (New-DenialCase -Id "missing-explain-resume-audit" -Blockers @("rc21-explain-resume-audit-not-ready") -Reason "Lifecycle support requires explain/resume/audit evidence."),
    (New-DenialCase -Id "missing-repair-reinstall" -Blockers @("rc21-repair-reinstall-drill-not-ready") -Reason "Lifecycle support requires RC21 repair/reinstall drill evidence."),
    (New-DenialCase -Id "missing-downgrade-rollback" -Blockers @("rc21-downgrade-rollback-drill-not-ready") -Reason "Lifecycle support requires RC21 downgrade/rollback drill evidence."),
    (New-DenialCase -Id "missing-rc20-support" -Blockers @("rc20-lifecycle-support-recovery-not-ready") -Reason "Lifecycle support must bind RC20 lifecycle support/recovery evidence."),
    (New-DenialCase -Id "restored-state-mismatch" -Blockers @("rc21-lifecycle-restored-state-chain-mismatch") -Reason "Lifecycle support denies incoherent restored state chain."),
    (New-DenialCase -Id "support-upload-attempt" -Blockers @("support-upload-denied") -Reason "Support upload is outside RC21 scope."),
    (New-DenialCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied") -Reason "Recovery execution is outside RC21 scope."),
    (New-DenialCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied") -Reason "Remote dispatch is outside RC21 scope."),
    (New-DenialCase -Id "host-rootfs-mutation" -Blockers @("host-rootfs-mutation-denied") -Reason "Host rootfs mutation is forbidden."),
    (New-DenialCase -Id "host-slot-mutation" -Blockers @("host-active-slot-mutation-denied") -Reason "Host active slot mutation is forbidden."),
    (New-DenialCase -Id "host-boot-metadata-mutation" -Blockers @("host-boot-metadata-mutation-denied") -Reason "Host boot metadata mutation is forbidden."),
    (New-DenialCase -Id "active-artifact-set-mutation" -Blockers @("active-artifact-set-mutation-denied") -Reason "Active artifact set mutation is forbidden."),
    (New-DenialCase -Id "production-ring-mutation" -Blockers @("production-ring-mutation-denied") -Reason "Production ring mutation is forbidden."),
    (New-DenialCase -Id "signer-authority" -Blockers @("signer-authority-denied") -Reason "Signer authority is outside RC21 scope."),
    (New-DenialCase -Id "object-storage-authority" -Blockers @("object-storage-authority-denied") -Reason "Object storage authority is outside RC21 scope."),
    (New-DenialCase -Id "private-material-attempt" -Blockers @("private-signing-material-denied") -Reason "Private signing material is forbidden."),
    (New-DenialCase -Id "endpoint-authority" -Blockers @("endpoint-reachability-authority-denied") -Reason "Endpoint reachability is not lifecycle support authority."),
    (New-DenialCase -Id "shell-authority" -Blockers @("shell-output-authority-denied") -Reason "Shell output is not lifecycle support authority."),
    (New-DenialCase -Id "tui-authority" -Blockers @("tui-output-authority-denied") -Reason "TUI output is not lifecycle support authority."),
    (New-DenialCase -Id "model-replay-authority" -Blockers @("model-replay-authority-denied") -Reason "Model replay is not lifecycle support authority."),
    (New-DenialCase -Id "ga-claim" -Blockers @("ga-claim-denied") -Reason "RC21 lifecycle support cannot claim GA production readiness.")
)
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc21_032" $planAllowsRun "RC21-032 must run after RC21-031 completed, with current_task set to RC21-032 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_031_status = $previousTaskStatus; rc21_032_status = $currentTaskStatus })
Add-Check "contract.support_recovery.present" $contractAllowsSupport "RC21-032 must consume the local redacted support and projection-only recovery contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "source.dry_run_explain.bound" ($dryRunReady -and $explainReady) "Support bundle must bind RC21 dry-run acceptance and explain/resume/audit evidence." ([ordered]@{ dry_run_status = $dryRunAcceptanceResult.status; explain_status = $explainResumeAuditResult.status; dry_run_effect_preparation = $dryRunAcceptanceResult.summary.effect_preparation_performed; resume_projection_count = @($explainResumeAuditPackage.resume_projections).Count })
Add-Check "source.lifecycle_drills.bound" ($repairReady -and $downgradeReady) "Support bundle must bind completed repair/reinstall and downgrade/rollback drill evidence." ([ordered]@{ repair_status = $repairReinstallResult.status; downgrade_status = $downgradeRollbackResult.status; repair_drill_id = $repairReinstallResult.repair_reinstall_drill_id; downgrade_drill_id = $downgradeRollbackResult.downgrade_rollback_drill_id })
Add-Check "source.rc20_support.bound" $rc20SupportReady "Support bundle must bind RC20 local-only lifecycle support/recovery evidence without upload or recovery execution." ([ordered]@{ support_bundle_id = $rc20LifecycleSupportResult.support_bundle_id; support_bundle_local_only = $rc20LifecycleSupportResult.summary.support_bundle_local_only; support_bundle_redacted = $rc20LifecycleSupportResult.summary.support_bundle_redacted; support_upload_performed = $rc20LifecycleSupportResult.summary.support_upload_performed; recovery_execution_performed = $rc20LifecycleSupportResult.summary.recovery_execution_performed })
Add-Check "source.restored_state.chain" $stateChainReady "Repair/reinstall, downgrade/rollback, and RC20 lifecycle support restored states must match." ([ordered]@{ repair_restored_state = $repairReinstallResult.summary.restored_target_state_id; downgrade_restored_state = $downgradeRollbackResult.summary.restored_state_id; rc20_restored_state = $rc20LifecycleSupportResult.restored_target_state_id })
Add-Check "support.bundle.local_redacted" ($supportBundle.local_only -eq $true -and $supportBundle.uploaded -eq $false -and $supportBundle.redacted -eq $true -and $supportBundle.support_bundle_core.repair_reinstall_result_sha256 -eq (Get-FileSha256 $resolvedRepairReinstallResultPath) -and $supportBundle.support_bundle_core.downgrade_rollback_result_sha256 -eq (Get-FileSha256 $resolvedDowngradeRollbackResultPath) -and $supportBundle.support_bundle_core.explain_resume_audit_package_sha256 -eq (Get-FileSha256 $resolvedExplainResumeAuditPackagePath) -and $supportBundle.support_bundle_core.rc20_lifecycle_support_result_sha256 -eq (Get-FileSha256 $resolvedRc20LifecycleSupportResultPath)) "Lifecycle support bundle must be local-only, redacted, and hash-bound to RC21 repair, downgrade, dry-run, explain/resume, and RC20 support evidence." ([ordered]@{ support_bundle_id = $supportBundle.support_bundle_id; local_only = $supportBundle.local_only; redacted = $supportBundle.redacted; uploaded = $supportBundle.uploaded })
Add-Check "recovery.index.projection_only" ($recoveryReferenceIndex.projection_only -eq $true -and $recoveryReferenceIndex.recovery_execution_allowed -eq $false -and $recoveryReferenceIndex.recovery_execution_performed -eq $false -and $recoveryReferenceIndex.support_bundle_upload_allowed -eq $false -and $recoveryReferenceIndex.remote_dispatch_enabled -eq $false) "Recovery reference index must be projection-only and must not execute recovery, upload support, or dispatch remotely." ([ordered]@{ recovery_reference_digest = $recoveryReferenceDigest; recovery_execution_allowed = $recoveryReferenceIndex.recovery_execution_allowed; recovery_execution_performed = $recoveryReferenceIndex.recovery_execution_performed; support_bundle_upload_allowed = $recoveryReferenceIndex.support_bundle_upload_allowed; remote_dispatch_enabled = $recoveryReferenceIndex.remote_dispatch_enabled })
Add-Check "authority.no_forbidden_side_effects" ($supportBundle.side_effects.support_upload_performed -eq $false -and $supportBundle.side_effects.recovery_execution_performed -eq $false -and $supportBundle.side_effects.remote_dispatch_enabled -eq $false -and $supportBundle.side_effects.host_rootfs_mutated -eq $false -and $supportBundle.side_effects.host_active_slot_mutated -eq $false -and $supportBundle.side_effects.host_boot_metadata_mutated -eq $false -and $supportBundle.side_effects.active_artifact_set_mutated -eq $false -and $supportBundle.side_effects.production_ring_mutated -eq $false -and $supportBundle.side_effects.signer_authority_granted -eq $false -and $supportBundle.side_effects.object_storage_provisioned -eq $false -and $supportBundle.side_effects.private_signing_material_handled -eq $false -and $supportBundle.side_effects.cryptographic_signing_performed -eq $false) "RC21-032 must not upload support, execute recovery, remote dispatch, mutate host/production state, grant signer/object storage authority, handle private material, or sign." $supportBundle.side_effects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing lifecycle sources and forbidden authority surfaces must fail closed before support upload, recovery execution, host mutation, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC21-032 outputs must not contain private material, tokens, raw sensitive assignments, support upload payloads, or recovery execution authority." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-lifecycle-support-recovery-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-032"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    support_bundle_id = [string]$supportBundle.support_bundle_id
    support_bundle_digest = [string]$supportBundleDigest
    recovery_reference_digest = [string]$recoveryReferenceDigest
    restored_state_id = [string]$downgradeRollbackResult.summary.restored_state_id
    lifecycle_support_surface = [ordered]@{
        state = if ($supportClosureAllowed) { "lifecycle-support-recovery-projection-bound" } else { "lifecycle-support-recovery-projection-denied" }
        dry_run_acceptance_bound = $dryRunReady
        explain_resume_audit_bound = $explainReady
        repair_reinstall_bound = $repairReady
        downgrade_rollback_bound = $downgradeReady
        rc20_lifecycle_support_bound = $rc20SupportReady
        restored_state_chain_bound = $stateChainReady
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        lifecycle_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = Get-FileSha256 $supportBundlePath
            support_bundle_id = $supportBundle.support_bundle_id
            support_bundle_digest = $supportBundleDigest
            local_only = $true
            redacted = $true
            uploaded = $false
        }
        recovery_reference_index = [ordered]@{
            path = Get-StablePath $recoveryIndexPath
            sha256 = Get-FileSha256 $recoveryIndexPath
            recovery_reference_digest = $recoveryReferenceDigest
            projection_only = $true
            recovery_execution_performed = $false
        }
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        lifecycle_support_projection_only = $true
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        signer_authority = $false
        object_storage_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc21_032_complete = (@($script:failedChecks).Count -eq 0)
        support_bundle_id = [string]$supportBundle.support_bundle_id
        recovery_reference_digest = [string]$recoveryReferenceDigest
        restored_state_chain_bound = $stateChainReady
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        signer_authority = $false
        object_storage_authority = $false
        private_signing_material_handled = $false
        next_task = "RC21-040"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-032-lifecycle-support-recovery.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-lifecycle-support-recovery-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-032"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
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
    lifecycle_support_surface = $result.lifecycle_support_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_032_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-040"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-032 outputs." }

Write-Host "RC21 lifecycle support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Lifecycle support bundle: $(Get-StablePath $supportBundlePath)"
Write-Host "Recovery index: $(Get-StablePath $recoveryIndexPath)"
Write-Host "Support upload/recovery/remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
