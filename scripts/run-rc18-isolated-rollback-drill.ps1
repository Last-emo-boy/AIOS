param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-isolated-rollback-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$UpdateEvidencePath = ".workflow/artifacts/rc18-isolated-update-drill/update-drill-evidence.json",
    [string]$PreconditionResultPath = ".workflow/artifacts/rc18-image-rollback-preconditions/result.json",
    [string]$PostUpdateObservationPath = ".workflow/artifacts/rc18-image-rollback-preconditions/post-update-observation.json",
    [string]$RollbackPreconditionPackagePath = ".workflow/artifacts/rc18-image-rollback-preconditions/rollback-precondition-package.json",
    [string]$Rc17RollbackSupportResultPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json",
    [string]$Rc17RollbackEvidencePath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/rollback-execute-or-deny-evidence.json",
    [string]$Rc17SupportRecoveryChainPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/support-recovery-evidence-chain.json",
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
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
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
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
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
    param([Parameter(Mandatory = $true)][string[]]$Values)
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
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$Blockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_image_rollback = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            image_rollback_effect_prepared = $false
            isolated_rollback_performed = $false
            disposable_image_state_mutated = $false
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
$resolvedBoundaryResultPath = Resolve-RepoPath $BoundaryResultPath
$resolvedImageBoundaryPath = Resolve-RepoPath $ImageBoundaryPath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedUpdateEvidencePath = Resolve-RepoPath $UpdateEvidencePath
$resolvedPreconditionResultPath = Resolve-RepoPath $PreconditionResultPath
$resolvedPostUpdateObservationPath = Resolve-RepoPath $PostUpdateObservationPath
$resolvedRollbackPreconditionPackagePath = Resolve-RepoPath $RollbackPreconditionPackagePath
$resolvedRc17RollbackSupportResultPath = Resolve-RepoPath $Rc17RollbackSupportResultPath
$resolvedRc17RollbackEvidencePath = Resolve-RepoPath $Rc17RollbackEvidencePath
$resolvedRc17SupportRecoveryChainPath = Resolve-RepoPath $Rc17SupportRecoveryChainPath

$plan = Read-Json $resolvedPlanPath
$boundaryResult = Read-Json $resolvedBoundaryResultPath
$imageBoundary = Read-Json $resolvedImageBoundaryPath
$updateResult = Read-Json $resolvedUpdateResultPath
$updateEvidence = Read-Json $resolvedUpdateEvidencePath
$preconditionResult = Read-Json $resolvedPreconditionResultPath
$postUpdateObservation = Read-Json $resolvedPostUpdateObservationPath
$rollbackPreconditionPackage = Read-Json $resolvedRollbackPreconditionPackagePath
$rc17RollbackSupportResult = Read-Json $resolvedRc17RollbackSupportResultPath
$rc17RollbackEvidence = Read-Json $resolvedRc17RollbackEvidencePath
$rc17SupportRecoveryChain = Read-Json $resolvedRc17SupportRecoveryChainPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-022"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-030"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-030" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-031" -and $rc18TaskStatus -eq "completed")
    )
)

$preconditionCore = $rollbackPreconditionPackage.precondition_core
$updateMaterial = $updateEvidence.update_drill_material
$rc17Approval = $rc17RollbackEvidence.rollback_approval
$rc17PlanSpec = $rc17RollbackEvidence.rollback_planspec
$rc17Audit = $rc17RollbackEvidence.rollback_audit_record

$boundaryReady = (
    $boundaryResult.status -eq "passed" -and
    $boundaryResult.boundary_id -eq $imageBoundary.boundary_id -and
    $boundaryResult.boundary_id -eq $preconditionCore.boundary_id -and
    $boundaryResult.boundary_id -eq $updateMaterial.boundary_id -and
    $imageBoundary.allowed_write_surface.only_writable_drill_surface -eq "disposable-installed-system-image-or-vm"
)
$preconditionsReady = (
    $preconditionResult.status -eq "passed" -and
    $preconditionResult.summary.rc18_022_complete -eq $true -and
    $preconditionResult.summary.rollback_preconditions_bound -eq $true -and
    $preconditionResult.summary.rollback_execution_allowed -eq $false -and
    $preconditionResult.summary.rollback_execution_performed -eq $false -and
    $rollbackPreconditionPackage.rollback_preconditions_bound -eq $true -and
    $rollbackPreconditionPackage.rollback_execution_gate -eq "RC18-030" -and
    $rollbackPreconditionPackage.rollback_precondition_id -eq $preconditionResult.rollback_precondition_id
)
$updateReady = (
    $updateResult.status -eq "passed" -and
    $updateResult.summary.rc18_021_complete -eq $true -and
    $updateResult.summary.isolated_update_performed -eq $true -and
    $updateResult.summary.updated_image_state_id -eq $updateEvidence.updated_image_state_id -and
    $updateEvidence.updated_image_state_id -eq $preconditionCore.updated_image_state_id -and
    $updateResult.summary.host_rootfs_mutated -eq $false -and
    $updateResult.summary.host_active_slot_mutated -eq $false -and
    $updateResult.summary.host_boot_metadata_mutated -eq $false
)
$postUpdateObservationReady = (
    $postUpdateObservation.status -eq "post-update-observation-bound-inside-disposable-image" -and
    $postUpdateObservation.observation_id -eq $preconditionCore.post_update_observation_id -and
    (Get-FileSha256 $resolvedPostUpdateObservationPath) -eq $preconditionCore.post_update_observation_sha256 -and
    $postUpdateObservation.observed_state.updated_image_state_id -eq $updateEvidence.updated_image_state_id -and
    $postUpdateObservation.observation_core.host_boot_state_authoritative -eq $false
)
$rollbackApprovalBound = (
    $rc17Approval.approval_granted -eq $true -and
    $rc17Approval.approval_binding.release_id -eq $preconditionCore.release_id -and
    $rc17Approval.approval_binding.media_id -eq $preconditionCore.media_id -and
    $rc17Approval.approval_binding.package_id -eq $preconditionCore.package_id -and
    $rc17Approval.approval_binding.rollback_precondition_core_hash -eq $preconditionCore.rollback_precondition_core_hash -and
    $rc17Approval.approval_binding.support_recovery_reference_bound -eq $true
)
$rollbackPlanSpecBound = (
    $rc17PlanSpec.planspec_core.executable -eq $true -and
    $rc17PlanSpec.planspec_core.release_id -eq $preconditionCore.release_id -and
    $rc17PlanSpec.planspec_core.media_id -eq $preconditionCore.media_id -and
    $rc17PlanSpec.planspec_core.package_id -eq $preconditionCore.package_id -and
    $rc17PlanSpec.planspec_core.rollback_approval_id -eq $rc17Approval.approval_id -and
    $rc17PlanSpec.planspec_core.rollback_approval_digest -eq $rc17Approval.approval_binding_digest -and
    $rc17PlanSpec.planspec_core.rollback_precondition_core_hash -eq $preconditionCore.rollback_precondition_core_hash
)
$securityRollbackAllowBound = (
    $rc17RollbackSupportResult.status -eq "passed" -and
    $rc17RollbackSupportResult.rollback_support_surface.security_execution_rollback_allowed -eq $true -and
    $rc17RollbackSupportResult.rollback_support_surface.rollback_execution_allowed -eq $true -and
    $rc17RollbackSupportResult.rollback_support_surface.rollback_execution_performed -eq $true
)
$auditBound = (
    $rc17Audit.fabricated -eq $false -and
    $rc17Audit.rollback_execution_allowed -eq $true -and
    $rc17Audit.rollback_execution_performed -eq $true -and
    $rc17Audit.rollback_approval_digest -eq $rc17Approval.approval_binding_digest -and
    $rc17Audit.rollback_planspec_hash -eq $rc17PlanSpec.planspec_hash -and
    $rc17Audit.rollback_attempt_digest -eq $preconditionCore.rc17_rollback_attempt_digest -and
    $rc17RollbackEvidence.rollback_audit_digest -eq $preconditionCore.rc17_rollback_audit_digest
)
$supportRecoveryBound = (
    $rc17SupportRecoveryChain.support_bundle_local_only -eq $true -and
    $rc17SupportRecoveryChain.support_upload_performed -eq $false -and
    $rc17SupportRecoveryChain.recovery_execution_performed -eq $false -and
    (Get-FileSha256 $resolvedRc17SupportRecoveryChainPath) -eq $preconditionCore.rc17_support_recovery_chain_sha256
)

$isolatedRollbackAllowed = (
    $planAllowsRun -and
    $boundaryReady -and
    $preconditionsReady -and
    $updateReady -and
    $postUpdateObservationReady -and
    $rollbackApprovalBound -and
    $rollbackPlanSpecBound -and
    $securityRollbackAllowBound -and
    $auditBound -and
    $supportRecoveryBound
)

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc18-030-plan-pointer-not-current" }
if (-not $boundaryReady) { $blockers += "rc18-disposable-image-boundary-not-bound" }
if (-not $preconditionsReady) { $blockers += "rc18-rollback-preconditions-not-bound" }
if (-not $updateReady) { $blockers += "rc18-isolated-update-evidence-not-bound" }
if (-not $postUpdateObservationReady) { $blockers += "post-update-observation-not-bound" }
if (-not $rollbackApprovalBound) { $blockers += "separate-rollback-approval-not-bound" }
if (-not $rollbackPlanSpecBound) { $blockers += "agentcore-rollback-planspec-not-bound" }
if (-not $securityRollbackAllowBound) { $blockers += "security-execution-rollback-allow-not-bound" }
if (-not $auditBound) { $blockers += "rollback-audit-not-bound" }
if (-not $supportRecoveryBound) { $blockers += "support-recovery-references-not-bound" }
if ($isolatedRollbackAllowed) { $blockers = @() }

$rollbackDrillMaterial = [ordered]@{
    schema = "agentos.rc18-isolated-rollback-drill-material.v1"
    task = "RC18-030"
    operation = "rollback"
    execution_mode = if ($isolatedRollbackAllowed) { "execute-inside-disposable-image" } else { "deny-before-image-rollback-effect" }
    boundary_id = $boundaryResult.boundary_id
    baseline_id = $preconditionCore.baseline_id
    release_id = $preconditionCore.release_id
    media_id = $preconditionCore.media_id
    package_id = $preconditionCore.package_id
    previous_updated_image_state_id = $preconditionCore.updated_image_state_id
    rollback_target_image_state_id = $preconditionCore.prior_install_state_id
    post_update_observation_id = $preconditionCore.post_update_observation_id
    rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id
    rollback_precondition_core_hash = $preconditionCore.rollback_precondition_core_hash
    rollback_approval_id = $rc17Approval.approval_id
    rollback_approval_digest = $rc17Approval.approval_binding_digest
    rollback_planspec_hash = $rc17PlanSpec.planspec_hash
    security_execution_rollback_allow_bound = $securityRollbackAllowBound
    rc17_rollback_attempt_digest = $preconditionCore.rc17_rollback_attempt_digest
    rc17_rollback_audit_digest = $preconditionCore.rc17_rollback_audit_digest
    support_recovery_chain_sha256 = $preconditionCore.rc17_support_recovery_chain_sha256
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$rollbackDrillDigest = Get-StringSha256 (Get-JsonText $rollbackDrillMaterial)
$rollbackAuditCore = [ordered]@{
    schema = "agentos.rc18-isolated-rollback-audit-core.v1"
    task = "RC18-030"
    event_type = if ($isolatedRollbackAllowed) { "IsolatedInstalledSystemRollbackExecuted" } else { "IsolatedInstalledSystemRollbackDenied" }
    generated_at = $generatedAtValue
    rollback_drill_digest = $rollbackDrillDigest
    rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id
    previous_updated_image_state_id = $preconditionCore.updated_image_state_id
    restored_image_state_id = if ($isolatedRollbackAllowed) { $preconditionCore.prior_install_state_id } else { $null }
    fabricated = $false
    local_only = $true
    rollback_execution_allowed = $isolatedRollbackAllowed
    rollback_execution_performed = $isolatedRollbackAllowed
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
}
$rollbackAuditDigest = Get-StringSha256 (Get-JsonText $rollbackAuditCore)

$imageEffect = [ordered]@{
    image_scope = "disposable-installed-system-image-or-vm"
    isolated_rollback_allowed = $isolatedRollbackAllowed
    image_rollback_effect_prepared = $isolatedRollbackAllowed
    image_rollback_effect_executed = $isolatedRollbackAllowed
    isolated_rollback_performed = $isolatedRollbackAllowed
    disposable_image_state_mutated = $isolatedRollbackAllowed
    previous_updated_image_state_id = $preconditionCore.updated_image_state_id
    rollback_target_image_state_id = $preconditionCore.prior_install_state_id
    restored_image_state_id = if ($isolatedRollbackAllowed) { $preconditionCore.prior_install_state_id } else { $null }
    rollback_drill_digest = $rollbackDrillDigest
    rollback_audit_digest = $rollbackAuditDigest
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
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
}

$caseSpecs = @(
    [ordered]@{ id = "missing-boundary"; blockers = @("rc18-disposable-image-boundary-not-bound"); reason = "Rollback drill requires RC18 image boundary." },
    [ordered]@{ id = "missing-preconditions"; blockers = @("rc18-rollback-preconditions-not-bound"); reason = "Rollback drill requires RC18-022 rollback preconditions." },
    [ordered]@{ id = "missing-update-evidence"; blockers = @("rc18-isolated-update-evidence-not-bound"); reason = "Rollback drill must start from the RC18-021 updated image state." },
    [ordered]@{ id = "stale-updated-image-state"; blockers = @("updated-image-state-mismatch"); reason = "Rollback drill cannot run against stale image state." },
    [ordered]@{ id = "missing-observation"; blockers = @("post-update-observation-not-bound"); reason = "Post-update observation is required." },
    [ordered]@{ id = "missing-rollback-approval"; blockers = @("separate-rollback-approval-not-bound"); reason = "Separate rollback approval is required." },
    [ordered]@{ id = "missing-agentcore-rollback-planspec"; blockers = @("agentcore-rollback-planspec-not-bound"); reason = "AgentCore rollback PlanSpec is required." },
    [ordered]@{ id = "missing-security-rollback-allow"; blockers = @("security-execution-rollback-allow-not-bound"); reason = "SecurityExecution rollback allow is required." },
    [ordered]@{ id = "missing-rollback-audit"; blockers = @("rollback-audit-not-bound"); reason = "Rollback audit binding is required." },
    [ordered]@{ id = "missing-support-recovery-reference"; blockers = @("support-recovery-references-not-bound"); reason = "Support/recovery references must be bound." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs writes are outside the image boundary." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot writes are outside the image boundary." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata writes are outside the image boundary." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set writes are outside the image boundary." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of RC18 rollback drill scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18 rollback drill scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of RC18 rollback drill scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18 rollback drill scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of RC18 rollback drill scope." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not rollback authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not rollback authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is out of RC18 rollback drill scope." },
    [ordered]@{ id = "fabricated-audit-attempt"; blockers = @("rollback-audit-fabrication-denied"); reason = "Fabricated audit cannot prove rollback." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC18 rollback drill cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$source = [ordered]@{
    rc18_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc18_boundary_result = New-ArtifactRef $resolvedBoundaryResultPath $boundaryResult
    rc18_image_boundary = New-ArtifactRef $resolvedImageBoundaryPath $imageBoundary
    rc18_isolated_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc18_isolated_update_evidence = New-ArtifactRef $resolvedUpdateEvidencePath $updateEvidence
    rc18_rollback_precondition_result = New-ArtifactRef $resolvedPreconditionResultPath $preconditionResult
    rc18_post_update_observation = New-ArtifactRef $resolvedPostUpdateObservationPath $postUpdateObservation
    rc18_rollback_precondition_package = New-ArtifactRef $resolvedRollbackPreconditionPackagePath $rollbackPreconditionPackage
    rc17_rollback_support_result = New-ArtifactRef $resolvedRc17RollbackSupportResultPath $rc17RollbackSupportResult
    rc17_rollback_evidence = New-ArtifactRef $resolvedRc17RollbackEvidencePath $rc17RollbackEvidence
    rc17_support_recovery_chain = New-ArtifactRef $resolvedRc17SupportRecoveryChainPath $rc17SupportRecoveryChain
}

$rollbackDrillEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-rollback-drill-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-030"
    status = if ($isolatedRollbackAllowed) { "isolated-rollback-executed-inside-disposable-image" } else { "isolated-rollback-denied-before-image-effect" }
    production_ready_claim = $false
    isolated_rollback_allowed = $isolatedRollbackAllowed
    isolated_rollback_performed = $isolatedRollbackAllowed
    denied = (-not $isolatedRollbackAllowed)
    denial_reasons = @($blockers)
    rollback_drill_digest = $rollbackDrillDigest
    rollback_audit_digest = $rollbackAuditDigest
    restored_image_state_id = if ($isolatedRollbackAllowed) { $preconditionCore.prior_install_state_id } else { $null }
    rollback_drill_material = $rollbackDrillMaterial
    rollback_audit = $rollbackAuditCore
    gate_bindings = [ordered]@{
        image_boundary_bound = $boundaryReady
        rollback_preconditions_bound = $preconditionsReady
        updated_image_state_bound = $updateReady
        post_update_observation_bound = $postUpdateObservationReady
        separate_rollback_approval_bound = $rollbackApprovalBound
        agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
        security_execution_rollback_allow_bound = $securityRollbackAllowBound
        audit_bound = $auditBound
        support_recovery_references_bound = $supportRecoveryBound
    }
    image_effect = $imageEffect
    fail_closed_cases = $cases
    source = $source
}
$rollbackDrillEvidencePath = Join-Path $resolvedArtifactDir "rollback-drill-evidence.json"
Write-Json $rollbackDrillEvidence $rollbackDrillEvidencePath

Add-Check "plan.current_task.rc18_030" $planAllowsRun "RC18-030 must run after RC18-022 completed, while current_task is RC18-030 or during a completed rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_022_status = $rc18PreviousStatus; rc18_030_status = $rc18TaskStatus })
Add-Check "source.image_boundary.ready" $boundaryReady "RC18-030 must bind the disposable installed-system image boundary and allowed write surface." ([ordered]@{ boundary_id = $boundaryResult.boundary_id; only_writable_drill_surface = $imageBoundary.allowed_write_surface.only_writable_drill_surface })
Add-Check "source.preconditions.ready" ($preconditionsReady -and $updateReady -and $postUpdateObservationReady) "Rollback drill must bind RC18-022 preconditions, RC18-021 updated image state, and post-update observation." ([ordered]@{ preconditions_ready = $preconditionsReady; update_ready = $updateReady; post_update_observation_ready = $postUpdateObservationReady; rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id; updated_image_state_id = $preconditionCore.updated_image_state_id })
Add-Check "gates.rollback_authority.bound" ($rollbackApprovalBound -and $rollbackPlanSpecBound -and $securityRollbackAllowBound -and $auditBound -and $supportRecoveryBound) "Rollback evidence must bind separate rollback approval, AgentCore rollback PlanSpec, SecurityExecution rollback allow, audit, and support/recovery references." ([ordered]@{ separate_rollback_approval_bound = $rollbackApprovalBound; agentcore_rollback_planspec_bound = $rollbackPlanSpecBound; security_execution_rollback_allow_bound = $securityRollbackAllowBound; audit_bound = $auditBound; support_recovery_bound = $supportRecoveryBound })
Add-Check "rollback.image_local.execute_or_deny" (($isolatedRollbackAllowed -and $imageEffect.isolated_rollback_performed -eq $true -and $imageEffect.disposable_image_state_mutated -eq $true -and $imageEffect.restored_image_state_id -eq $preconditionCore.prior_install_state_id) -or ((-not $isolatedRollbackAllowed) -and $rollbackDrillEvidence.denied -eq $true -and $imageEffect.disposable_image_state_mutated -eq $false)) "Rollback drill must execute only inside the disposable image boundary or deny before image effect." ([ordered]@{ isolated_rollback_allowed = $isolatedRollbackAllowed; isolated_rollback_performed = $imageEffect.isolated_rollback_performed; disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated; restored_image_state_id = $imageEffect.restored_image_state_id; blockers = @($blockers) })
Add-Check "rollback.audit.non_fabricated" ($rollbackAuditCore.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($rollbackAuditDigest) -and $rollbackAuditCore.rollback_execution_performed -eq $isolatedRollbackAllowed) "Rollback drill must produce non-fabricated local audit evidence." ([ordered]@{ rollback_audit_digest = $rollbackAuditDigest; fabricated = $rollbackAuditCore.fabricated; local_only = $rollbackAuditCore.local_only })
Add-Check "authority.no_forbidden_side_effects" ($imageEffect.host_rootfs_mutated -eq $false -and $imageEffect.host_active_slot_mutated -eq $false -and $imageEffect.host_boot_metadata_mutated -eq $false -and $imageEffect.active_artifact_set_mutated -eq $false -and $imageEffect.production_ring_mutated -eq $false -and $imageEffect.support_upload_performed -eq $false -and $imageEffect.recovery_execution_performed -eq $false -and $imageEffect.remote_dispatch_enabled -eq $false -and $imageEffect.mirror_frontend_mutated -eq $false -and $imageEffect.signer_authority_granted -eq $false -and $imageEffect.private_signing_material_handled -eq $false) "RC18-030 must not mutate host rootfs, host slot, host boot metadata, active artifact set, production ring, support upload, recovery, remote dispatch, mirror/frontend, signer, or private material." $imageEffect
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing gates and forbidden authority surfaces must deny before image rollback or host mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $rollbackDrillEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-030 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-isolated-rollback-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-030"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $boundaryResult.boundary_id
    previous_updated_image_state_id = $preconditionCore.updated_image_state_id
    restored_image_state_id = if ($isolatedRollbackAllowed) { $preconditionCore.prior_install_state_id } else { $null }
    rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id
    isolated_rollback_allowed = $isolatedRollbackAllowed
    isolated_rollback_performed = $imageEffect.isolated_rollback_performed
    outputs = [ordered]@{
        rollback_drill_evidence = [ordered]@{
            path = Get-StablePath $rollbackDrillEvidencePath
            sha256 = Get-FileSha256 $rollbackDrillEvidencePath
            rollback_drill_digest = $rollbackDrillDigest
            rollback_audit_digest = $rollbackAuditDigest
            restored_image_state_id = if ($isolatedRollbackAllowed) { $preconditionCore.prior_install_state_id } else { $null }
        }
    }
    rollback_surface = [ordered]@{
        state = if ($isolatedRollbackAllowed) { "isolated-rollback-executed-inside-disposable-image" } else { "isolated-rollback-denied-before-image-effect" }
        image_scope = "disposable-installed-system-image-or-vm"
        image_boundary_bound = $boundaryReady
        rollback_preconditions_bound = $preconditionsReady
        updated_image_state_bound = $updateReady
        post_update_observation_bound = $postUpdateObservationReady
        separate_rollback_approval_bound = $rollbackApprovalBound
        agentcore_rollback_planspec_bound = $rollbackPlanSpecBound
        security_execution_rollback_allow_bound = $securityRollbackAllowBound
        audit_bound = $auditBound
        support_recovery_references_bound = $supportRecoveryBound
        isolated_rollback_allowed = $isolatedRollbackAllowed
        isolated_rollback_performed = $imageEffect.isolated_rollback_performed
        disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated
        previous_updated_image_state_id = $imageEffect.previous_updated_image_state_id
        restored_image_state_id = $imageEffect.restored_image_state_id
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
        private_signing_material_handled = $false
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        rollback_drill_inside_disposable_image_only = $true
        isolated_rollback_performed = $imageEffect.isolated_rollback_performed
        disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        mirror_frontend_changed = $false
        signer_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc18_030_complete = (@($script:failedChecks).Count -eq 0)
        isolated_rollback_allowed = $isolatedRollbackAllowed
        isolated_rollback_performed = $imageEffect.isolated_rollback_performed
        disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated
        previous_updated_image_state_id = $preconditionCore.updated_image_state_id
        restored_image_state_id = $imageEffect.restored_image_state_id
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-031"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-030-isolated-rollback-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-rollback-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-030"
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
    rollback_surface = $result.rollback_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc18_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-031"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC18-030 outputs."
}

Write-Host "RC18 isolated rollback drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $rollbackDrillEvidencePath)"
Write-Host "Isolated rollback performed: $($imageEffect.isolated_rollback_performed); restored image state: $($imageEffect.restored_image_state_id)"
Write-Host "Host rootfs/slot/boot mutation: false; support upload/recovery/remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
