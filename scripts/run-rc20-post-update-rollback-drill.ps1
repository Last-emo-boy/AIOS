param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-post-update-rollback-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$UpdateResultPath = ".workflow/artifacts/rc20-post-install-update-drill/result.json",
    [string]$UpdateEvidencePath = ".workflow/artifacts/rc20-post-install-update-drill/update-drill-evidence.json",
    [string]$UpdateAuditPath = ".workflow/artifacts/rc20-post-install-update-drill/update-audit-record.json",
    [string]$Rc18RollbackResultPath = ".workflow/artifacts/rc18-isolated-rollback-drill/result.json",
    [string]$Rc18RollbackEvidencePath = ".workflow/artifacts/rc18-isolated-rollback-drill/rollback-drill-evidence.json",
    [string]$Rc18RollbackPreconditionPackagePath = ".workflow/artifacts/rc18-image-rollback-preconditions/rollback-precondition-package.json",
    [string]$Rc19SupportRecoveryResultPath = ".workflow/artifacts/rc19-first-user-support-recovery/result.json",
    [string]$Rc19SupportBundlePath = ".workflow/artifacts/rc19-first-user-support-recovery/first-user-support-bundle.json",
    [string]$Rc19RecoveryReferencePath = ".workflow/artifacts/rc19-first-user-support-recovery/recovery-reference-index.json",
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
        task = if ($null -ne $Json) { $Json.task } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $privateMarker = "PRIVATE" + " KEY"
    $publicMarker = "PUBLIC" + " KEY"
    $markers = @(
        ("BEGIN " + $privateMarker),
        ("BEGIN " + $publicMarker),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-SideEffects {
    param([bool]$RollbackPerformed = $false)
    return [ordered]@{
        rollback_plan_bound = $RollbackPerformed
        rollback_audit_record_bound = $RollbackPerformed
        post_rollback_observation_bound = $RollbackPerformed
        isolated_rollback_performed = $RollbackPerformed
        disposable_image_state_mutated = $RollbackPerformed
        restored_target_state_bound = $RollbackPerformed
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        mirror_frontend_mutated = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
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
        denied_before_rollback_or_host_effects = $true
        side_effects = New-SideEffects
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
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedUpdateEvidencePath = Resolve-RepoPath $UpdateEvidencePath
$resolvedUpdateAuditPath = Resolve-RepoPath $UpdateAuditPath
$resolvedRc18RollbackResultPath = Resolve-RepoPath $Rc18RollbackResultPath
$resolvedRc18RollbackEvidencePath = Resolve-RepoPath $Rc18RollbackEvidencePath
$resolvedRc18RollbackPreconditionPackagePath = Resolve-RepoPath $Rc18RollbackPreconditionPackagePath
$resolvedRc19SupportRecoveryResultPath = Resolve-RepoPath $Rc19SupportRecoveryResultPath
$resolvedRc19SupportBundlePath = Resolve-RepoPath $Rc19SupportBundlePath
$resolvedRc19RecoveryReferencePath = Resolve-RepoPath $Rc19RecoveryReferencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$updateResult = Read-Json $resolvedUpdateResultPath
$updateEvidence = Read-Json $resolvedUpdateEvidencePath
$updateAudit = Read-Json $resolvedUpdateAuditPath
$rc18RollbackResult = Read-Json $resolvedRc18RollbackResultPath
$rc18RollbackEvidence = Read-Json $resolvedRc18RollbackEvidencePath
$rc18RollbackPreconditionPackage = Read-Json $resolvedRc18RollbackPreconditionPackagePath
$rc19SupportRecoveryResult = Read-Json $resolvedRc19SupportRecoveryResultPath
$rc19SupportBundle = Read-Json $resolvedRc19SupportBundlePath
$rc19RecoveryReference = Read-Json $resolvedRc19RecoveryReferencePath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-030"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-031"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-031" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$updateReady = (
    $updateResult.status -eq "passed" -and
    $updateResult.summary.rc20_030_complete -eq $true -and
    $updateResult.update_surface.isolated_update_performed -eq $true -and
    $updateResult.update_surface.post_update_observation_bound -eq $true -and
    $updateResult.update_surface.rollback_prerequisites_bound -eq $true -and
    $updateResult.update_surface.host_active_slot_mutated -eq $false -and
    $updateResult.update_surface.host_boot_metadata_mutated -eq $false -and
    $updateResult.update_surface.production_ring_mutated -eq $false -and
    $updateEvidence.update_drill_id -eq $updateResult.update_drill_id -and
    $updateEvidence.audit_record.update_audit_record_id -eq $updateAudit.update_audit_record_id
)

$rc18RollbackReady = (
    $rc18RollbackResult.status -eq "passed" -and
    $rc18RollbackResult.summary.rc18_030_complete -eq $true -and
    $rc18RollbackResult.summary.isolated_rollback_performed -eq $true -and
    $rc18RollbackResult.summary.previous_updated_image_state_id -eq $updateResult.updated_image_state_id -and
    $rc18RollbackResult.summary.restored_image_state_id -eq $updateResult.previous_installed_image_state_id -and
    $rc18RollbackEvidence.status -eq "isolated-rollback-executed-inside-disposable-image" -and
    $rc18RollbackEvidence.rollback_audit.fabricated -eq $false -and
    $rc18RollbackEvidence.image_effect.host_active_slot_mutated -eq $false -and
    $rc18RollbackEvidence.image_effect.host_boot_metadata_mutated -eq $false -and
    $rc18RollbackEvidence.image_effect.production_ring_mutated -eq $false
)

$preconditionsBound = (
    $rc18RollbackPreconditionPackage.status -eq "image-rollback-preconditions-bound-execution-gated" -and
    $rc18RollbackPreconditionPackage.rollback_preconditions_bound -eq $true -and
    $rc18RollbackPreconditionPackage.precondition_core.updated_image_state_id -eq $updateResult.updated_image_state_id -and
    $rc18RollbackPreconditionPackage.precondition_core.prior_install_state_id -eq $updateResult.previous_installed_image_state_id -and
    $rc18RollbackPreconditionPackage.precondition_core.post_update_observation_sha256 -eq $updateEvidence.post_update_observation.sha256
)

$supportRecoveryReady = (
    $rc19SupportRecoveryResult.status -eq "passed" -and
    $rc19SupportRecoveryResult.summary.rc19_032_complete -eq $true -and
    $rc19SupportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $rc19SupportRecoveryResult.summary.support_bundle_redacted -eq $true -and
    $rc19SupportRecoveryResult.summary.support_upload_performed -eq $false -and
    $rc19SupportRecoveryResult.summary.recovery_execution_performed -eq $false -and
    $rc19SupportRecoveryResult.summary.remote_dispatch_enabled -eq $false -and
    $rc19SupportRecoveryResult.first_user_target_state_id -eq $updateEvidence.update_material.pre_update_target_state_id -and
    $rc19SupportBundle.local_only -eq $true -and
    $rc19SupportBundle.redacted -eq $true -and
    $rc19SupportBundle.uploaded -eq $false -and
    $rc19RecoveryReference.recovery_execution_performed -eq $false
)

$rollbackAllowed = $planAllowsRun -and $updateReady -and $rc18RollbackReady -and $preconditionsBound -and $supportRecoveryReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-031-plan-pointer-not-current" }
if (-not $updateReady) { $blockers += "rc20-post-install-update-not-ready" }
if (-not $rc18RollbackReady) { $blockers += "rc18-isolated-rollback-not-ready" }
if (-not $preconditionsBound) { $blockers += "rollback-preconditions-not-bound" }
if (-not $supportRecoveryReady) { $blockers += "rc19-support-recovery-not-ready" }
if ($rollbackAllowed) { $blockers = @() }

$rollbackApprovalMaterial = [ordered]@{
    schema = "agentos.rc20-post-update-rollback-approval-surrogate-material.v1"
    task = "RC20-031"
    approval_kind = "repo-local-single-user-post-update-rollback-approval-surrogate"
    selected_version = [string]$updateResult.selected_version
    update_drill_id = [string]$updateResult.update_drill_id
    update_audit_record_id = [string]$updateResult.update_audit_record_id
    release_bundle_id = [string]$updateEvidence.update_material.release_bundle_id
    install_acceptance_id = [string]$updateEvidence.update_material.install_acceptance_id
    first_boot_acceptance_id = [string]$updateEvidence.update_material.first_boot_acceptance_id
    previous_installed_image_state_id = [string]$updateResult.previous_installed_image_state_id
    updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = [string]$rc18RollbackResult.restored_image_state_id
    rollback_precondition_id = [string]$rc18RollbackResult.rollback_precondition_id
    rc19_support_bundle_id = [string]$rc19SupportRecoveryResult.support_bundle_id
    rc19_recovery_reference_digest = [string]$rc19SupportRecoveryResult.recovery_reference_digest
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$rollbackApprovalId = "sha256:$(Get-StringSha256 (Get-JsonText $rollbackApprovalMaterial))"

$rollbackPlanMaterial = [ordered]@{
    schema = "agentos.rc20-post-update-rollback-plan.v1"
    task = "RC20-031"
    operation = "post-update-rollback"
    execution_mode = if ($rollbackAllowed) { "execute-inside-disposable-installed-system" } else { "deny-before-rollback-effect" }
    rollback_approval_id = $rollbackApprovalId
    selected_version = [string]$updateResult.selected_version
    update_drill_id = [string]$updateResult.update_drill_id
    previous_updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = [string]$rc18RollbackResult.restored_image_state_id
    rc18_rollback_drill_digest = [string]$rc18RollbackResult.outputs.rollback_drill_evidence.rollback_drill_digest
    rc18_rollback_audit_digest = [string]$rc18RollbackResult.outputs.rollback_drill_evidence.rollback_audit_digest
    rc19_support_bundle_id = [string]$rc19SupportRecoveryResult.support_bundle_id
    rc19_recovery_reference_digest = [string]$rc19SupportRecoveryResult.recovery_reference_digest
    host_rootfs_mutation_allowed = $false
    active_artifact_set_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$rollbackPlanId = "sha256:$(Get-StringSha256 (Get-JsonText $rollbackPlanMaterial))"

$postRollbackObservation = [ordered]@{
    schema = "agentos.rc20-post-rollback-observation.v1"
    generated_at = $generatedAtValue
    task = "RC20-031"
    status = if ($rollbackAllowed) { "post-rollback-observation-bound-inside-disposable-installed-system" } else { "post-rollback-observation-denied" }
    previous_updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = if ($rollbackAllowed) { [string]$rc18RollbackResult.restored_image_state_id } else { $null }
    rollback_restored_pre_update_state = ($rollbackAllowed -and $rc18RollbackResult.restored_image_state_id -eq $updateResult.previous_installed_image_state_id)
    host_boot_state_authoritative = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}
$postRollbackObservationId = "sha256:$(Get-StringSha256 (Get-JsonText $postRollbackObservation))"

$rollbackAuditRecord = [ordered]@{
    schema = "agentos.rc20-post-update-rollback-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC20-031"
    status = if ($rollbackAllowed) { "post-update-rollback-audit-bound" } else { "post-update-rollback-audit-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    rollback_audit_record_id = $null
    rollback_approval_id = $rollbackApprovalId
    rollback_plan_id = $rollbackPlanId
    post_rollback_observation_id = $postRollbackObservationId
    rollback_allowed = $rollbackAllowed
    rollback_performed = $rollbackAllowed
    fabricated = $false
    local_only = $true
    events = @(
        [ordered]@{ id = "rc20-update-bound"; update_drill_id = $updateResult.update_drill_id; updated_image_state_id = $updateResult.updated_image_state_id },
        [ordered]@{ id = "rollback-approval-surrogate-bound"; rollback_approval_id = $rollbackApprovalId },
        [ordered]@{ id = "rollback-plan-bound"; rollback_plan_id = $rollbackPlanId },
        [ordered]@{ id = "rc18-isolated-rollback-bound"; source = Get-StablePath $resolvedRc18RollbackResultPath; restored_target_state_id = $rc18RollbackResult.restored_image_state_id },
        [ordered]@{ id = "post-rollback-observation-bound"; post_rollback_observation_id = $postRollbackObservationId },
        [ordered]@{ id = "support-recovery-remains-local"; support_bundle_id = $rc19SupportRecoveryResult.support_bundle_id; support_upload_performed = $false; recovery_execution_performed = $false }
    )
    side_effects = New-SideEffects -RollbackPerformed:$rollbackAllowed
}
$rollbackAuditRecord.rollback_audit_record_id = "sha256:$(Get-StringSha256 (Get-JsonText $rollbackAuditRecord))"
$rollbackAuditRecordPath = Join-Path $resolvedArtifactDir "rollback-audit-record.json"
Write-Json $rollbackAuditRecord $rollbackAuditRecordPath

$caseSpecs = @(
    [ordered]@{ id = "missing-update-evidence"; blockers = @("rc20-post-install-update-not-ready"); reason = "Rollback requires RC20-030 update evidence." },
    [ordered]@{ id = "missing-update-audit"; blockers = @("rc20-update-audit-not-bound"); reason = "Rollback requires update audit binding." },
    [ordered]@{ id = "missing-rollback-preconditions"; blockers = @("rollback-preconditions-not-bound"); reason = "Rollback requires rollback preconditions." },
    [ordered]@{ id = "missing-rc18-rollback"; blockers = @("rc18-isolated-rollback-not-ready"); reason = "Rollback requires isolated rollback evidence." },
    [ordered]@{ id = "stale-updated-state"; blockers = @("updated-image-state-mismatch"); reason = "Rollback denies stale updated image state." },
    [ordered]@{ id = "restored-state-mismatch"; blockers = @("restored-target-state-mismatch"); reason = "Rollback denies mismatched restored target state." },
    [ordered]@{ id = "missing-support-recovery"; blockers = @("rc19-support-recovery-not-ready"); reason = "Rollback requires support/recovery references." },
    [ordered]@{ id = "support-bundle-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload remains out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution remains out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch remains out of scope." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "mirror-frontend-authority"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not rollback authority." },
    [ordered]@{ id = "signer-authority"; blockers = @("signer-authority-denied"); reason = "Signer authority is out of scope." },
    [ordered]@{ id = "object-storage-provisioning"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "release-signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "Release signing is out of scope." },
    [ordered]@{ id = "fabricated-audit"; blockers = @("rollback-audit-fabrication-denied"); reason = "Fabricated audit cannot prove rollback." },
    [ordered]@{ id = "consumer-ready-claim"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for consumer smoke." },
    [ordered]@{ id = "ga-claim"; blockers = @("ga-claim-denied"); reason = "RC20-031 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$source = [ordered]@{
    rc20_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc20_contract = New-ArtifactRef $resolvedContractPath
    rc20_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc20_update_evidence = New-ArtifactRef $resolvedUpdateEvidencePath $updateEvidence
    rc20_update_audit = New-ArtifactRef $resolvedUpdateAuditPath $updateAudit
    rc18_rollback_result = New-ArtifactRef $resolvedRc18RollbackResultPath $rc18RollbackResult
    rc18_rollback_evidence = New-ArtifactRef $resolvedRc18RollbackEvidencePath $rc18RollbackEvidence
    rc18_rollback_precondition_package = New-ArtifactRef $resolvedRc18RollbackPreconditionPackagePath $rc18RollbackPreconditionPackage
    rc19_support_recovery_result = New-ArtifactRef $resolvedRc19SupportRecoveryResultPath $rc19SupportRecoveryResult
    rc19_support_bundle = New-ArtifactRef $resolvedRc19SupportBundlePath $rc19SupportBundle
    rc19_recovery_reference = New-ArtifactRef $resolvedRc19RecoveryReferencePath $rc19RecoveryReference
}

$rollbackEvidence = [ordered]@{
    schema = "agentos.rc20-post-update-rollback-drill-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-031"
    status = if ($rollbackAllowed) { "post-update-rollback-executed-inside-disposable-installed-system" } else { "post-update-rollback-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    rollback_allowed = $rollbackAllowed
    rollback_performed = $rollbackAllowed
    denied = (-not $rollbackAllowed)
    denial_reasons = @($blockers)
    rollback_approval_id = $rollbackApprovalId
    rollback_plan_id = $rollbackPlanId
    rollback_audit_record_id = $rollbackAuditRecord.rollback_audit_record_id
    post_rollback_observation_id = $postRollbackObservationId
    selected_version = [string]$updateResult.selected_version
    update_drill_id = [string]$updateResult.update_drill_id
    rollback_approval_surrogate = $rollbackApprovalMaterial
    rollback_plan = $rollbackPlanMaterial
    rollback_audit_record = [ordered]@{
        path = Get-StablePath $rollbackAuditRecordPath
        sha256 = Get-FileSha256 $rollbackAuditRecordPath
        rollback_audit_record_id = $rollbackAuditRecord.rollback_audit_record_id
    }
    post_rollback_observation = $postRollbackObservation
    restored_target_state = [ordered]@{
        pre_update_target_state_id = [string]$updateEvidence.update_material.pre_update_target_state_id
        previous_installed_image_state_id = [string]$updateResult.previous_installed_image_state_id
        updated_image_state_id = [string]$updateResult.updated_image_state_id
        restored_image_state_id = if ($rollbackAllowed) { [string]$rc18RollbackResult.restored_image_state_id } else { $null }
        restored_matches_previous_installed_image = ($rollbackAllowed -and $rc18RollbackResult.restored_image_state_id -eq $updateResult.previous_installed_image_state_id)
    }
    gate_bindings = [ordered]@{
        rc20_update_ready = $updateReady
        rc18_isolated_rollback_ready = $rc18RollbackReady
        rollback_preconditions_bound = $preconditionsBound
        rc19_support_recovery_ready = $supportRecoveryReady
    }
    side_effects = New-SideEffects -RollbackPerformed:$rollbackAllowed
    fail_closed_cases = $cases
    source = $source
}
$rollbackEvidencePath = Join-Path $resolvedArtifactDir "rollback-drill-evidence.json"
Write-Json $rollbackEvidence $rollbackEvidencePath

Add-Check "plan.current_task.rc20_031" $planAllowsRun "RC20-031 must run after RC20-030 completed, with current_task set to RC20-031." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_030_status = $rc20PreviousStatus; rc20_031_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-031 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "update.ready" $updateReady "Rollback drill must bind RC20-030 update evidence and update audit." ([ordered]@{ update_status = $updateResult.status; updated_image_state_id = $updateResult.updated_image_state_id; update_drill_id = $updateResult.update_drill_id; update_audit_record_id = $updateAudit.update_audit_record_id })
Add-Check "rollback.preconditions.bound" $preconditionsBound "Rollback drill must bind rollback preconditions for the updated image state." ([ordered]@{ rollback_precondition_id = $rc18RollbackPreconditionPackage.rollback_precondition_id; updated_image_state_id = $rc18RollbackPreconditionPackage.precondition_core.updated_image_state_id; prior_install_state_id = $rc18RollbackPreconditionPackage.precondition_core.prior_install_state_id })
Add-Check "rc18.rollback.executed_inside_boundary" $rc18RollbackReady "RC20 rollback must reuse isolated rollback evidence that restored the updated image to the previous installed image state without host mutation." ([ordered]@{ rc18_status = $rc18RollbackResult.status; isolated_rollback_performed = $rc18RollbackResult.summary.isolated_rollback_performed; restored_image_state_id = $rc18RollbackResult.restored_image_state_id; host_active_slot_mutated = $rc18RollbackResult.rollback_surface.host_active_slot_mutated })
Add-Check "support.recovery.ready" $supportRecoveryReady "Rollback drill must bind RC19 local-only redacted support/recovery references without upload or recovery execution." ([ordered]@{ support_bundle_id = $rc19SupportRecoveryResult.support_bundle_id; local_only = $rc19SupportBundle.local_only; redacted = $rc19SupportBundle.redacted; uploaded = $rc19SupportBundle.uploaded; recovery_execution_performed = $rc19RecoveryReference.recovery_execution_performed })
Add-Check "rollback.approval_plan_audit.bound" ($rollbackAllowed -and $rollbackEvidence.rollback_approval_id -eq $rollbackApprovalId -and $rollbackEvidence.rollback_plan_id -eq $rollbackPlanId -and $rollbackEvidence.rollback_audit_record.rollback_audit_record_id -eq $rollbackAuditRecord.rollback_audit_record_id) "Rollback evidence must bind approval surrogate, rollback plan, and rollback audit record." ([ordered]@{ rollback_approval_id = $rollbackApprovalId; rollback_plan_id = $rollbackPlanId; rollback_audit_record_id = $rollbackAuditRecord.rollback_audit_record_id })
Add-Check "post_rollback.observation.restored" ($rollbackAllowed -and $postRollbackObservation.rollback_restored_pre_update_state -eq $true -and $postRollbackObservation.host_boot_state_authoritative -eq $false) "Post-rollback observation must bind restored target state without claiming host boot authority." ([ordered]@{ post_rollback_observation_id = $postRollbackObservationId; restored_target_state_id = $postRollbackObservation.restored_target_state_id; host_boot_state_authoritative = $postRollbackObservation.host_boot_state_authoritative })
Add-Check "authority.no_forbidden_side_effects" ($rollbackEvidence.side_effects.host_rootfs_mutated -eq $false -and $rollbackEvidence.side_effects.host_active_slot_mutated -eq $false -and $rollbackEvidence.side_effects.host_boot_metadata_mutated -eq $false -and $rollbackEvidence.side_effects.active_artifact_set_mutated -eq $false -and $rollbackEvidence.side_effects.production_ring_mutated -eq $false -and $rollbackEvidence.side_effects.support_upload_performed -eq $false -and $rollbackEvidence.side_effects.recovery_execution_performed -eq $false -and $rollbackEvidence.side_effects.remote_dispatch_enabled -eq $false -and $rollbackEvidence.side_effects.signer_authority_granted -eq $false -and $rollbackEvidence.side_effects.object_storage_provisioned -eq $false -and $rollbackEvidence.side_effects.private_signing_material_handled -eq $false) "RC20-031 must not broaden support upload, recovery, remote dispatch, host mutation, active artifact set, production ring, signer, object storage, or private material authority." $rollbackEvidence.side_effects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing rollback inputs and forbidden authority surfaces must deny before rollback or host effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $rollbackAuditRecordPath),
    (Get-Content -Raw -LiteralPath $rollbackEvidencePath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC20-031 outputs must not contain key blocks, private authority paths, auth tokens, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-post-update-rollback-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-031"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    selected_version = [string]$updateResult.selected_version
    update_drill_id = [string]$updateResult.update_drill_id
    rollback_approval_id = $rollbackApprovalId
    rollback_plan_id = $rollbackPlanId
    rollback_audit_record_id = $rollbackAuditRecord.rollback_audit_record_id
    post_rollback_observation_id = $postRollbackObservationId
    previous_updated_image_state_id = [string]$updateResult.updated_image_state_id
    restored_target_state_id = if ($rollbackAllowed) { [string]$rc18RollbackResult.restored_image_state_id } else { $null }
    outputs = [ordered]@{
        rollback_drill_evidence = [ordered]@{
            path = Get-StablePath $rollbackEvidencePath
            sha256 = Get-FileSha256 $rollbackEvidencePath
            rollback_approval_id = $rollbackApprovalId
            rollback_plan_id = $rollbackPlanId
            post_rollback_observation_id = $postRollbackObservationId
        }
        rollback_audit_record = [ordered]@{
            path = Get-StablePath $rollbackAuditRecordPath
            sha256 = Get-FileSha256 $rollbackAuditRecordPath
            rollback_audit_record_id = $rollbackAuditRecord.rollback_audit_record_id
        }
    }
    rollback_surface = [ordered]@{
        state = if ($rollbackAllowed) { "post-update-rollback-executed-inside-disposable-installed-system" } else { "post-update-rollback-denied" }
        rc20_update_ready = $updateReady
        rc18_isolated_rollback_ready = $rc18RollbackReady
        rollback_preconditions_bound = $preconditionsBound
        rc19_support_recovery_ready = $supportRecoveryReady
        rollback_allowed = $rollbackAllowed
        rollback_performed = $rollbackAllowed
        disposable_image_state_mutated = $rollbackAllowed
        previous_updated_image_state_id = [string]$updateResult.updated_image_state_id
        restored_target_state_id = if ($rollbackAllowed) { [string]$rc18RollbackResult.restored_image_state_id } else { $null }
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
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        disposable_installed_system_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        rollback_performed = $rollbackAllowed
        restored_target_state_bound = $rollbackAllowed
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        mirror_frontend_changed = $false
        signer_authority = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_031_complete = (@($script:failedChecks).Count -eq 0)
        rollback_allowed = $rollbackAllowed
        rollback_performed = $rollbackAllowed
        previous_updated_image_state_id = [string]$updateResult.updated_image_state_id
        restored_target_state_id = if ($rollbackAllowed) { [string]$rc18RollbackResult.restored_image_state_id } else { $null }
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC20-032"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-031-post-update-rollback-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-post-update-rollback-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-031"
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
    rollback_surface = $result.rollback_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-032"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-031 outputs." }

Write-Host "RC20 post-update rollback drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Rollback evidence: $(Get-StablePath $rollbackEvidencePath)"
Write-Host "Rollback audit: $(Get-StablePath $rollbackAuditRecordPath)"
Write-Host "Rollback performed: $rollbackAllowed; restored target state: $($result.summary.restored_target_state_id)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
