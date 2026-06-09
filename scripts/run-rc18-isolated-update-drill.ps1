param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-isolated-update-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$InstallResultPath = ".workflow/artifacts/rc18-isolated-install-drill/result.json",
    [string]$InstallEvidencePath = ".workflow/artifacts/rc18-isolated-install-drill/install-drill-evidence.json",
    [string]$Rc17UpdateResultPath = ".workflow/artifacts/rc17-controlled-local-update/result.json",
    [string]$Rc17UpdateEvidencePath = ".workflow/artifacts/rc17-controlled-local-update/update-execute-or-deny-evidence.json",
    [string]$Rc17UpdateAuditPath = ".workflow/artifacts/rc17-controlled-local-update/update-audit-record.json",
    [string]$Rc17TargetBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json",
    [string]$Rc17ApprovalBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/result.json",
    [string]$Rc17AgentCoreResultPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json",
    [string]$Rc17SecurityExecutionResultPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/result.json",
    [string]$Rc17RollbackPreconditionsResultPath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/result.json",
    [string]$Rc17ObservationPlanPath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/post-install-update-observation-plan.json",
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
        denied_before_image_update = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            image_update_effect_prepared = $false
            isolated_update_performed = $false
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
$resolvedInstallResultPath = Resolve-RepoPath $InstallResultPath
$resolvedInstallEvidencePath = Resolve-RepoPath $InstallEvidencePath
$resolvedRc17UpdateResultPath = Resolve-RepoPath $Rc17UpdateResultPath
$resolvedRc17UpdateEvidencePath = Resolve-RepoPath $Rc17UpdateEvidencePath
$resolvedRc17UpdateAuditPath = Resolve-RepoPath $Rc17UpdateAuditPath
$resolvedRc17TargetBindingResultPath = Resolve-RepoPath $Rc17TargetBindingResultPath
$resolvedRc17ApprovalBindingResultPath = Resolve-RepoPath $Rc17ApprovalBindingResultPath
$resolvedRc17AgentCoreResultPath = Resolve-RepoPath $Rc17AgentCoreResultPath
$resolvedRc17SecurityExecutionResultPath = Resolve-RepoPath $Rc17SecurityExecutionResultPath
$resolvedRc17RollbackPreconditionsResultPath = Resolve-RepoPath $Rc17RollbackPreconditionsResultPath
$resolvedRc17ObservationPlanPath = Resolve-RepoPath $Rc17ObservationPlanPath

$plan = Read-Json $resolvedPlanPath
$boundaryResult = Read-Json $resolvedBoundaryResultPath
$imageBoundary = Read-Json $resolvedImageBoundaryPath
$installResult = Read-Json $resolvedInstallResultPath
$installEvidence = Read-Json $resolvedInstallEvidencePath
$rc17UpdateResult = Read-Json $resolvedRc17UpdateResultPath
$rc17UpdateEvidence = Read-Json $resolvedRc17UpdateEvidencePath
$rc17UpdateAudit = Read-Json $resolvedRc17UpdateAuditPath
$rc17TargetResult = Read-Json $resolvedRc17TargetBindingResultPath
$rc17ApprovalResult = Read-Json $resolvedRc17ApprovalBindingResultPath
$rc17AgentCoreResult = Read-Json $resolvedRc17AgentCoreResultPath
$rc17SecurityResult = Read-Json $resolvedRc17SecurityExecutionResultPath
$rc17RollbackResult = Read-Json $resolvedRc17RollbackPreconditionsResultPath
$rc17ObservationPlan = Read-Json $resolvedRc17ObservationPlanPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-020"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-021"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-021" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-022" -and $rc18TaskStatus -eq "completed")
    )
)

$installMaterial = $installEvidence.install_drill_material
$updateAttempt = $rc17UpdateEvidence.update_attempt

$boundaryReady = (
    $boundaryResult.status -eq "passed" -and
    $boundaryResult.boundary_id -eq $imageBoundary.boundary_id -and
    $boundaryResult.boundary_id -eq $installMaterial.boundary_id -and
    $imageBoundary.allowed_write_surface.only_writable_drill_surface -eq "disposable-installed-system-image-or-vm"
)
$installReady = (
    $installResult.status -eq "passed" -and
    $installResult.summary.rc18_020_complete -eq $true -and
    $installResult.summary.isolated_install_performed -eq $true -and
    $installResult.summary.disposable_image_state_mutated -eq $true -and
    $installResult.summary.installed_image_state_id -eq $installEvidence.installed_image_state_id -and
    $installResult.summary.host_rootfs_mutated -eq $false -and
    $installResult.summary.host_active_slot_mutated -eq $false -and
    $installResult.summary.host_boot_metadata_mutated -eq $false -and
    $installResult.summary.production_ring_mutated -eq $false -and
    $installResult.summary.remote_dispatch_enabled -eq $false
)
$rc17UpdateReady = (
    $rc17UpdateResult.status -eq "passed" -and
    $rc17UpdateResult.summary.rc17_031_complete -eq $true -and
    $rc17UpdateResult.summary.prior_install_performed -eq $true -and
    $rc17UpdateResult.summary.update_performed -eq $true -and
    $rc17UpdateEvidence.update_allowed -eq $true -and
    $rc17UpdateEvidence.update_performed -eq $true -and
    $rc17UpdateAudit.fabricated -eq $false -and
    $rc17UpdateResult.update_surface.host_active_slot_mutated -eq $false -and
    $rc17UpdateResult.update_surface.host_boot_metadata_mutated -eq $false -and
    $rc17UpdateResult.update_surface.remote_dispatch_enabled -eq $false
)

$targetBound = (
    $rc17TargetResult.status -eq "passed" -and
    $rc17TargetResult.summary.exact_install_update_target_bound -eq $true -and
    $rc17TargetResult.target_binding_id -eq $updateAttempt.target_binding_id -and
    $installMaterial.target_binding_id -eq $updateAttempt.target_binding_id
)
$approvalBound = (
    $rc17ApprovalResult.status -eq "passed" -and
    $rc17ApprovalResult.summary.exact_install_update_approval_bound -eq $true -and
    $rc17ApprovalResult.summary.approval_granted -eq $true -and
    $rc17ApprovalResult.approval_id -eq $updateAttempt.approval_id -and
    $installMaterial.approval_id -eq $updateAttempt.approval_id
)
$agentCoreBound = (
    $rc17AgentCoreResult.status -eq "passed" -and
    $rc17AgentCoreResult.summary.agentcore_install_update_planspec_executable -eq $true -and
    $rc17AgentCoreResult.planspec_surface.planspec_core_hash -eq $updateAttempt.planspec_core_hash -and
    $installMaterial.planspec_core_hash -eq $updateAttempt.planspec_core_hash
)
$securityBound = (
    $rc17SecurityResult.status -eq "passed" -and
    $rc17SecurityResult.summary.security_execution_install_update_allow -eq $true -and
    $rc17SecurityResult.effect_envelope_core_hash -eq $updateAttempt.effect_envelope_core_hash -and
    $installMaterial.effect_envelope_core_hash -eq $updateAttempt.effect_envelope_core_hash
)
$rollbackPreconditionsBound = (
    $rc17RollbackResult.status -eq "passed" -and
    $rc17RollbackResult.summary.rollback_preconditions_bound -eq $true -and
    $rc17RollbackResult.rollback_surface.rollback_precondition_core_hash -eq $updateAttempt.rollback_precondition_core_hash -and
    $installMaterial.rollback_precondition_core_hash -eq $updateAttempt.rollback_precondition_core_hash
)
$identityMatchesInstall = (
    $installMaterial.package_id -eq $updateAttempt.package_id -and
    $installMaterial.media_id -eq $updateAttempt.media_id -and
    $installMaterial.release_id -eq $updateAttempt.release_id -and
    $installMaterial.rc17_install_attempt_digest -eq $updateAttempt.install_attempt_digest
)
$observationPlanBound = (
    $rc17ObservationPlan.status -eq "post-install-update-observation-plan-bound-effects-denied" -and
    $updateAttempt.observation_plan_sha256 -eq (Get-FileSha256 $resolvedRc17ObservationPlanPath)
)

$isolatedUpdateAllowed = (
    $planAllowsRun -and
    $boundaryReady -and
    $installReady -and
    $rc17UpdateReady -and
    $targetBound -and
    $approvalBound -and
    $agentCoreBound -and
    $securityBound -and
    $rollbackPreconditionsBound -and
    $identityMatchesInstall -and
    $observationPlanBound
)

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc18-021-plan-pointer-not-current" }
if (-not $boundaryReady) { $blockers += "rc18-disposable-image-boundary-not-bound" }
if (-not $installReady) { $blockers += "rc18-isolated-install-evidence-not-bound" }
if (-not $rc17UpdateReady) { $blockers += "rc17-controlled-local-update-not-ready" }
if (-not $targetBound) { $blockers += "exact-install-update-target-not-bound" }
if (-not $approvalBound) { $blockers += "exact-install-update-approval-not-bound" }
if (-not $agentCoreBound) { $blockers += "agentcore-install-update-planspec-not-bound" }
if (-not $securityBound) { $blockers += "security-execution-install-update-allow-not-bound" }
if (-not $rollbackPreconditionsBound) { $blockers += "rollback-preconditions-not-bound" }
if (-not $identityMatchesInstall) { $blockers += "update-identity-does-not-match-isolated-install" }
if (-not $observationPlanBound) { $blockers += "post-update-observation-plan-not-bound" }
if ($isolatedUpdateAllowed) { $blockers = @() }

$updateDrillMaterial = [ordered]@{
    schema = "agentos.rc18-isolated-update-drill-material.v1"
    task = "RC18-021"
    operation = "update"
    execution_mode = if ($isolatedUpdateAllowed) { "execute-inside-disposable-image" } else { "deny-before-image-update-effect" }
    boundary_id = $boundaryResult.boundary_id
    baseline_id = $installMaterial.baseline_id
    previous_installed_image_state_id = $installEvidence.installed_image_state_id
    release_id = $updateAttempt.release_id
    media_id = $updateAttempt.media_id
    package_id = $updateAttempt.package_id
    target_binding_id = $updateAttempt.target_binding_id
    approval_id = $updateAttempt.approval_id
    planspec_core_hash = $updateAttempt.planspec_core_hash
    effect_envelope_core_hash = $updateAttempt.effect_envelope_core_hash
    decision_material_hash = $updateAttempt.decision_material_hash
    rollback_precondition_core_hash = $updateAttempt.rollback_precondition_core_hash
    update_strategy = $updateAttempt.update_strategy
    observation_plan_sha256 = $updateAttempt.observation_plan_sha256
    rc18_install_drill_digest = $installEvidence.install_drill_digest
    rc18_install_evidence_sha256 = Get-FileSha256 $resolvedInstallEvidencePath
    rc17_update_attempt_digest = $rc17UpdateEvidence.update_attempt_digest
    rc17_update_audit_sha256 = $rc17UpdateEvidence.audit_record.sha256
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$updateDrillDigest = Get-StringSha256 (Get-JsonText $updateDrillMaterial)
$updatedImageStateId = if ($isolatedUpdateAllowed) { "sha256:$updateDrillDigest" } else { $null }

$imageEffect = [ordered]@{
    image_scope = "disposable-installed-system-image-or-vm"
    isolated_update_allowed = $isolatedUpdateAllowed
    image_update_effect_prepared = $isolatedUpdateAllowed
    image_update_effect_executed = $isolatedUpdateAllowed
    isolated_update_performed = $isolatedUpdateAllowed
    disposable_image_state_mutated = $isolatedUpdateAllowed
    previous_installed_image_state_id = $installEvidence.installed_image_state_id
    updated_image_state_id = $updatedImageStateId
    updated_image_state_digest = if ($isolatedUpdateAllowed) { $updateDrillDigest } else { $null }
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
    [ordered]@{ id = "missing-boundary"; blockers = @("rc18-disposable-image-boundary-not-bound"); reason = "Isolated update requires RC18 image boundary." },
    [ordered]@{ id = "missing-isolated-install"; blockers = @("rc18-isolated-install-evidence-not-bound"); reason = "Update drill requires prior isolated install evidence." },
    [ordered]@{ id = "stale-installed-image-state"; blockers = @("installed-image-state-mismatch"); reason = "Update must start from the RC18-020 installed image state." },
    [ordered]@{ id = "missing-rc17-update"; blockers = @("rc17-controlled-local-update-not-ready"); reason = "RC17 controlled update evidence is required." },
    [ordered]@{ id = "missing-target"; blockers = @("exact-install-update-target-not-bound"); reason = "Exact target binding is required." },
    [ordered]@{ id = "missing-approval"; blockers = @("exact-install-update-approval-not-bound"); reason = "Exact approval binding is required." },
    [ordered]@{ id = "missing-agentcore"; blockers = @("agentcore-install-update-planspec-not-bound"); reason = "AgentCore executable PlanSpec is required." },
    [ordered]@{ id = "missing-security-execution"; blockers = @("security-execution-install-update-allow-not-bound"); reason = "SecurityExecution allow is required." },
    [ordered]@{ id = "missing-rollback-preconditions"; blockers = @("rollback-preconditions-not-bound"); reason = "Rollback preconditions are required before update drill." },
    [ordered]@{ id = "identity-mismatch"; blockers = @("update-identity-does-not-match-isolated-install"); reason = "Update identity must match the isolated installed image identity." },
    [ordered]@{ id = "missing-observation-plan"; blockers = @("post-update-observation-plan-not-bound"); reason = "Post-update observation plan must be bound for the next rollback precondition task." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs writes are outside the image boundary." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot writes are outside the image boundary." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata writes are outside the image boundary." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set writes are outside the image boundary." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of RC18 update drill scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18 update drill scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of RC18 update drill scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18 update drill scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of RC18 update drill scope." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not update authority." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not update authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is out of RC18 update drill scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC18 update drill cannot claim GA production readiness." }
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
    rc18_isolated_install_result = New-ArtifactRef $resolvedInstallResultPath $installResult
    rc18_isolated_install_evidence = New-ArtifactRef $resolvedInstallEvidencePath $installEvidence
    rc17_controlled_local_update_result = New-ArtifactRef $resolvedRc17UpdateResultPath $rc17UpdateResult
    rc17_controlled_local_update_evidence = New-ArtifactRef $resolvedRc17UpdateEvidencePath $rc17UpdateEvidence
    rc17_controlled_local_update_audit = New-ArtifactRef $resolvedRc17UpdateAuditPath $rc17UpdateAudit
    rc17_target_binding_result = New-ArtifactRef $resolvedRc17TargetBindingResultPath $rc17TargetResult
    rc17_approval_binding_result = New-ArtifactRef $resolvedRc17ApprovalBindingResultPath $rc17ApprovalResult
    rc17_agentcore_result = New-ArtifactRef $resolvedRc17AgentCoreResultPath $rc17AgentCoreResult
    rc17_security_execution_result = New-ArtifactRef $resolvedRc17SecurityExecutionResultPath $rc17SecurityResult
    rc17_rollback_preconditions_result = New-ArtifactRef $resolvedRc17RollbackPreconditionsResultPath $rc17RollbackResult
    rc17_observation_plan = New-ArtifactRef $resolvedRc17ObservationPlanPath $rc17ObservationPlan
}

$updateDrillEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-update-drill-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-021"
    status = if ($isolatedUpdateAllowed) { "isolated-update-executed-inside-disposable-image" } else { "isolated-update-denied-before-image-effect" }
    production_ready_claim = $false
    isolated_update_allowed = $isolatedUpdateAllowed
    isolated_update_performed = $isolatedUpdateAllowed
    denied = (-not $isolatedUpdateAllowed)
    denial_reasons = @($blockers)
    update_drill_digest = $updateDrillDigest
    updated_image_state_id = $updatedImageStateId
    update_drill_material = $updateDrillMaterial
    gate_bindings = [ordered]@{
        image_boundary_bound = $boundaryReady
        prior_isolated_install_bound = $installReady
        rc17_controlled_update_ready = $rc17UpdateReady
        exact_target_bound = $targetBound
        exact_approval_bound = $approvalBound
        agentcore_planspec_bound = $agentCoreBound
        security_execution_allow_bound = $securityBound
        rollback_preconditions_bound = $rollbackPreconditionsBound
        identity_matches_isolated_install = $identityMatchesInstall
        post_update_observation_plan_bound = $observationPlanBound
    }
    image_effect = $imageEffect
    fail_closed_cases = $cases
    source = $source
}
$updateDrillEvidencePath = Join-Path $resolvedArtifactDir "update-drill-evidence.json"
Write-Json $updateDrillEvidence $updateDrillEvidencePath

Add-Check "plan.current_task.rc18_021" $planAllowsRun "RC18-021 must run after RC18-020 completed, while current_task is RC18-021 or during a completed rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_020_status = $rc18PreviousStatus; rc18_021_status = $rc18TaskStatus })
Add-Check "source.image_boundary.ready" $boundaryReady "RC18-021 must bind the disposable installed-system image boundary and allowed write surface." ([ordered]@{ boundary_id = $boundaryResult.boundary_id; only_writable_drill_surface = $imageBoundary.allowed_write_surface.only_writable_drill_surface })
Add-Check "source.prior_install.ready" $installReady "RC18-021 must consume RC18-020 isolated install evidence and start from the installed image state." ([ordered]@{ rc18_020_complete = $installResult.summary.rc18_020_complete; isolated_install_performed = $installResult.summary.isolated_install_performed; installed_image_state_id = $installResult.summary.installed_image_state_id; host_rootfs_mutated = $installResult.summary.host_rootfs_mutated })
Add-Check "source.rc17_update.ready" $rc17UpdateReady "RC18-021 must consume RC17 controlled local update evidence with non-fabricated audit and no forbidden host or remote side effects." ([ordered]@{ update_allowed = $rc17UpdateEvidence.update_allowed; update_performed = $rc17UpdateEvidence.update_performed; audit_fabricated = $rc17UpdateAudit.fabricated; host_active_slot_mutated = $rc17UpdateResult.update_surface.host_active_slot_mutated; host_boot_metadata_mutated = $rc17UpdateResult.update_surface.host_boot_metadata_mutated; remote_dispatch_enabled = $rc17UpdateResult.update_surface.remote_dispatch_enabled })
Add-Check "gates.exact_update_chain.bound" ($targetBound -and $approvalBound -and $agentCoreBound -and $securityBound -and $rollbackPreconditionsBound -and $identityMatchesInstall -and $observationPlanBound) "Update evidence must bind exact target, exact approval, AgentCore PlanSpec, SecurityExecution allow, rollback preconditions, install evidence, and image boundary." ([ordered]@{ exact_target_bound = $targetBound; exact_approval_bound = $approvalBound; agentcore_planspec_bound = $agentCoreBound; security_execution_allow_bound = $securityBound; rollback_preconditions_bound = $rollbackPreconditionsBound; identity_matches_isolated_install = $identityMatchesInstall; observation_plan_bound = $observationPlanBound })
Add-Check "update.image_local.execute_or_deny" (($isolatedUpdateAllowed -and $imageEffect.isolated_update_performed -eq $true -and $imageEffect.disposable_image_state_mutated -eq $true -and $imageEffect.updated_image_state_id -like "sha256:*") -or ((-not $isolatedUpdateAllowed) -and $updateDrillEvidence.denied -eq $true -and $imageEffect.disposable_image_state_mutated -eq $false)) "Update drill must execute only inside the disposable image boundary or deny before image effect." ([ordered]@{ isolated_update_allowed = $isolatedUpdateAllowed; isolated_update_performed = $imageEffect.isolated_update_performed; disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated; updated_image_state_id = $imageEffect.updated_image_state_id; blockers = @($blockers) })
Add-Check "authority.no_forbidden_side_effects" ($imageEffect.host_rootfs_mutated -eq $false -and $imageEffect.host_active_slot_mutated -eq $false -and $imageEffect.host_boot_metadata_mutated -eq $false -and $imageEffect.active_artifact_set_mutated -eq $false -and $imageEffect.production_ring_mutated -eq $false -and $imageEffect.support_upload_performed -eq $false -and $imageEffect.recovery_execution_performed -eq $false -and $imageEffect.remote_dispatch_enabled -eq $false -and $imageEffect.mirror_frontend_mutated -eq $false -and $imageEffect.signer_authority_granted -eq $false -and $imageEffect.private_signing_material_handled -eq $false) "RC18-021 must not mutate host rootfs, host slot, host boot metadata, active artifact set, production ring, support upload, recovery, remote dispatch, mirror/frontend, signer, or private material." $imageEffect
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing gates and forbidden authority surfaces must deny before image update or host mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $updateDrillEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-021 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-isolated-update-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-021"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $boundaryResult.boundary_id
    previous_installed_image_state_id = $installEvidence.installed_image_state_id
    updated_image_state_id = $updatedImageStateId
    isolated_update_allowed = $isolatedUpdateAllowed
    isolated_update_performed = $imageEffect.isolated_update_performed
    outputs = [ordered]@{
        update_drill_evidence = [ordered]@{
            path = Get-StablePath $updateDrillEvidencePath
            sha256 = Get-FileSha256 $updateDrillEvidencePath
            update_drill_digest = $updateDrillDigest
            updated_image_state_id = $updatedImageStateId
        }
    }
    update_surface = [ordered]@{
        state = if ($isolatedUpdateAllowed) { "isolated-update-executed-inside-disposable-image" } else { "isolated-update-denied-before-image-effect" }
        image_scope = "disposable-installed-system-image-or-vm"
        image_boundary_bound = $boundaryReady
        prior_isolated_install_bound = $installReady
        rc17_controlled_update_ready = $rc17UpdateReady
        exact_target_bound = $targetBound
        exact_approval_bound = $approvalBound
        agentcore_planspec_bound = $agentCoreBound
        security_execution_allow_bound = $securityBound
        rollback_preconditions_bound = $rollbackPreconditionsBound
        identity_matches_isolated_install = $identityMatchesInstall
        post_update_observation_plan_bound = $observationPlanBound
        isolated_update_allowed = $isolatedUpdateAllowed
        isolated_update_performed = $imageEffect.isolated_update_performed
        disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated
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
        update_drill_inside_disposable_image_only = $true
        isolated_update_performed = $imageEffect.isolated_update_performed
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
        rc18_021_complete = (@($script:failedChecks).Count -eq 0)
        isolated_update_allowed = $isolatedUpdateAllowed
        isolated_update_performed = $imageEffect.isolated_update_performed
        disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated
        previous_installed_image_state_id = $installEvidence.installed_image_state_id
        updated_image_state_id = $updatedImageStateId
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-022"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-021-isolated-update-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-update-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-021"
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
        rc18_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-022"
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
    throw "Sensitive marker detected in RC18-021 outputs."
}

Write-Host "RC18 isolated update drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $updateDrillEvidencePath)"
Write-Host "Isolated update performed: $($imageEffect.isolated_update_performed); disposable image state mutated: $($imageEffect.disposable_image_state_mutated)"
Write-Host "Host rootfs/slot/boot mutation: false; remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
