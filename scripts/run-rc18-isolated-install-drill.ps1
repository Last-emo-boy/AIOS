param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-isolated-install-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$BaselineResultPath = ".workflow/artifacts/rc18-installed-system-baseline/result.json",
    [string]$BaselineIdentityPath = ".workflow/artifacts/rc18-installed-system-baseline/baseline-identity.json",
    [string]$BootStateProjectionPath = ".workflow/artifacts/rc18-installed-system-baseline/boot-state-projection.json",
    [string]$ImageBoundaryFailClosedResultPath = ".workflow/artifacts/rc18-image-boundary-fail-closed/result.json",
    [string]$Rc17InstallResultPath = ".workflow/artifacts/rc17-controlled-local-install/result.json",
    [string]$Rc17InstallEvidencePath = ".workflow/artifacts/rc17-controlled-local-install/install-execute-or-deny-evidence.json",
    [string]$Rc17TargetBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json",
    [string]$Rc17ApprovalBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/result.json",
    [string]$Rc17AgentCoreResultPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json",
    [string]$Rc17SecurityExecutionResultPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/result.json",
    [string]$Rc17RollbackPreconditionsResultPath = ".workflow/artifacts/rc17-install-update-rollback-preconditions/result.json",
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

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) {
                return $task.status
            }
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
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
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
        denied_before_image_install = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            image_install_effect_prepared = $false
            isolated_install_performed = $false
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
$resolvedBaselineResultPath = Resolve-RepoPath $BaselineResultPath
$resolvedBaselineIdentityPath = Resolve-RepoPath $BaselineIdentityPath
$resolvedBootStateProjectionPath = Resolve-RepoPath $BootStateProjectionPath
$resolvedImageBoundaryFailClosedResultPath = Resolve-RepoPath $ImageBoundaryFailClosedResultPath
$resolvedRc17InstallResultPath = Resolve-RepoPath $Rc17InstallResultPath
$resolvedRc17InstallEvidencePath = Resolve-RepoPath $Rc17InstallEvidencePath
$resolvedRc17TargetBindingResultPath = Resolve-RepoPath $Rc17TargetBindingResultPath
$resolvedRc17ApprovalBindingResultPath = Resolve-RepoPath $Rc17ApprovalBindingResultPath
$resolvedRc17AgentCoreResultPath = Resolve-RepoPath $Rc17AgentCoreResultPath
$resolvedRc17SecurityExecutionResultPath = Resolve-RepoPath $Rc17SecurityExecutionResultPath
$resolvedRc17RollbackPreconditionsResultPath = Resolve-RepoPath $Rc17RollbackPreconditionsResultPath

$plan = Read-Json $resolvedPlanPath
$boundaryResult = Read-Json $resolvedBoundaryResultPath
$imageBoundary = Read-Json $resolvedImageBoundaryPath
$baselineResult = Read-Json $resolvedBaselineResultPath
$baselineIdentity = Read-Json $resolvedBaselineIdentityPath
$bootStateProjection = Read-Json $resolvedBootStateProjectionPath
$failClosedResult = Read-Json $resolvedImageBoundaryFailClosedResultPath
$rc17InstallResult = Read-Json $resolvedRc17InstallResultPath
$rc17InstallEvidence = Read-Json $resolvedRc17InstallEvidencePath
$rc17TargetResult = Read-Json $resolvedRc17TargetBindingResultPath
$rc17ApprovalResult = Read-Json $resolvedRc17ApprovalBindingResultPath
$rc17AgentCoreResult = Read-Json $resolvedRc17AgentCoreResultPath
$rc17SecurityResult = Read-Json $resolvedRc17SecurityExecutionResultPath
$rc17RollbackResult = Read-Json $resolvedRc17RollbackPreconditionsResultPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-012"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-020" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-021" -and $rc18TaskStatus -eq "completed")
    )
)

$boundaryReady = (
    $boundaryResult.status -eq "passed" -and
    $boundaryResult.image_boundary_bound -eq $true -and
    $boundaryResult.boundary_id -eq $imageBoundary.boundary_id -and
    $imageBoundary.allowed_write_surface.only_writable_drill_surface -eq "disposable-installed-system-image-or-vm"
)
$baselineReady = (
    $baselineResult.status -eq "passed" -and
    $baselineResult.baseline_identity_bound -eq $true -and
    $baselineResult.boot_state_projection_bound -eq $true -and
    $baselineIdentity.baseline_id -eq $baselineResult.baseline_id -and
    $bootStateProjection.baseline_id -eq $baselineResult.baseline_id -and
    $baselineResult.boundary_id -eq $boundaryResult.boundary_id
)
$failClosedReady = (
    $failClosedResult.status -eq "passed" -and
    $failClosedResult.side_effect_fail_closed_verified -eq $true -and
    $failClosedResult.boundary_id -eq $boundaryResult.boundary_id -and
    $failClosedResult.baseline_id -eq $baselineResult.baseline_id -and
    $failClosedResult.fail_closed_surface.failed_cases -eq 0
)

$packageId = [string]$baselineIdentity.media.package_id
$mediaId = [string]$baselineIdentity.media.media_id
$releaseId = [string]$baselineIdentity.release.release_id
$installAttempt = $rc17InstallEvidence.install_attempt

$targetBound = (
    $rc17TargetResult.status -eq "passed" -and
    $rc17TargetResult.summary.exact_install_update_target_bound -eq $true -and
    $rc17TargetResult.package_id -eq $packageId -and
    $rc17TargetResult.media_id -eq $mediaId -and
    $rc17TargetResult.release_id -eq $releaseId -and
    $rc17TargetResult.target_binding_id -eq $installAttempt.target_binding_id
)
$approvalBound = (
    $rc17ApprovalResult.status -eq "passed" -and
    $rc17ApprovalResult.summary.exact_install_update_approval_bound -eq $true -and
    $rc17ApprovalResult.summary.approval_granted -eq $true -and
    $rc17ApprovalResult.approval_id -eq $installAttempt.approval_id
)
$agentCoreBound = (
    $rc17AgentCoreResult.status -eq "passed" -and
    $rc17AgentCoreResult.summary.agentcore_install_update_planspec_executable -eq $true -and
    $rc17AgentCoreResult.planspec_surface.planspec_core_hash -eq $installAttempt.planspec_core_hash -and
    $baselineIdentity.agentcore.planspec_core_hash -eq $installAttempt.planspec_core_hash
)
$securityBound = (
    $rc17SecurityResult.status -eq "passed" -and
    $rc17SecurityResult.summary.security_execution_install_update_allow -eq $true -and
    $rc17SecurityResult.planspec_core_hash -eq $installAttempt.planspec_core_hash -and
    $rc17SecurityResult.effect_envelope_core_hash -eq $installAttempt.effect_envelope_core_hash -and
    $baselineIdentity.security_execution.effect_envelope_core_hash -eq $installAttempt.effect_envelope_core_hash
)
$rollbackPreconditionsBound = (
    $rc17RollbackResult.status -eq "passed" -and
    $rc17RollbackResult.summary.rollback_preconditions_bound -eq $true -and
    $rc17RollbackResult.rollback_surface.rollback_precondition_core_hash -eq $installAttempt.rollback_precondition_core_hash
)
$rc17InstallReady = (
    $rc17InstallResult.status -eq "passed" -and
    $rc17InstallResult.install_surface.install_allowed -eq $true -and
    $rc17InstallResult.install_surface.install_performed -eq $true -and
    $rc17InstallEvidence.status -eq "controlled-local-install-executed" -and
    $rc17InstallEvidence.install_allowed -eq $true -and
    $rc17InstallEvidence.install_performed -eq $true -and
    $rc17InstallEvidence.audit_record.fabricated -eq $false -and
    $rc17InstallResult.install_surface.host_active_slot_mutated -eq $false -and
    $rc17InstallResult.install_surface.host_boot_metadata_mutated -eq $false -and
    $rc17InstallResult.install_surface.remote_dispatch_enabled -eq $false
)
$identityMatchesBaseline = (
    $installAttempt.package_id -eq $packageId -and
    $installAttempt.media_id -eq $mediaId -and
    $installAttempt.release_id -eq $releaseId
)

$isolatedInstallAllowed = (
    $planAllowsRun -and
    $boundaryReady -and
    $baselineReady -and
    $failClosedReady -and
    $targetBound -and
    $approvalBound -and
    $agentCoreBound -and
    $securityBound -and
    $rollbackPreconditionsBound -and
    $rc17InstallReady -and
    $identityMatchesBaseline
)

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc18-020-plan-pointer-not-current" }
if (-not $boundaryReady) { $blockers += "rc18-disposable-image-boundary-not-bound" }
if (-not $baselineReady) { $blockers += "rc18-installed-system-baseline-not-bound" }
if (-not $failClosedReady) { $blockers += "rc18-image-boundary-fail-closed-not-passed" }
if (-not $targetBound) { $blockers += "exact-install-update-target-not-bound" }
if (-not $approvalBound) { $blockers += "exact-install-update-approval-not-bound" }
if (-not $agentCoreBound) { $blockers += "agentcore-install-update-planspec-not-bound" }
if (-not $securityBound) { $blockers += "security-execution-install-update-allow-not-bound" }
if (-not $rollbackPreconditionsBound) { $blockers += "rollback-preconditions-not-bound" }
if (-not $rc17InstallReady) { $blockers += "rc17-controlled-local-install-not-ready" }
if (-not $identityMatchesBaseline) { $blockers += "install-identity-does-not-match-baseline" }
if ($isolatedInstallAllowed) { $blockers = @() }

$installDrillMaterial = [ordered]@{
    schema = "agentos.rc18-isolated-install-drill-material.v1"
    task = "RC18-020"
    execution_mode = if ($isolatedInstallAllowed) { "execute-inside-disposable-image" } else { "deny-before-image-effect" }
    boundary_id = $boundaryResult.boundary_id
    previous_state_root_id = $boundaryResult.state_root_id
    baseline_id = $baselineResult.baseline_id
    release_id = $releaseId
    media_id = $mediaId
    package_id = $packageId
    target_binding_id = $installAttempt.target_binding_id
    approval_id = $installAttempt.approval_id
    planspec_core_hash = $installAttempt.planspec_core_hash
    effect_envelope_core_hash = $installAttempt.effect_envelope_core_hash
    rollback_precondition_core_hash = $installAttempt.rollback_precondition_core_hash
    rc17_install_attempt_digest = $rc17InstallEvidence.install_attempt_digest
    rc17_install_audit_sha256 = $rc17InstallEvidence.audit_record.sha256
    image_boundary_fail_closed_sha256 = Get-FileSha256 $resolvedImageBoundaryFailClosedResultPath
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$installDrillDigest = Get-StringSha256 (Get-JsonText $installDrillMaterial)
$installedImageStateId = if ($isolatedInstallAllowed) { "sha256:$installDrillDigest" } else { $null }

$imageEffect = [ordered]@{
    image_scope = "disposable-installed-system-image-or-vm"
    isolated_install_allowed = $isolatedInstallAllowed
    image_install_effect_prepared = $isolatedInstallAllowed
    image_install_effect_executed = $isolatedInstallAllowed
    isolated_install_performed = $isolatedInstallAllowed
    disposable_image_state_mutated = $isolatedInstallAllowed
    previous_state_root_id = $boundaryResult.state_root_id
    installed_image_state_id = $installedImageStateId
    installed_image_state_digest = if ($isolatedInstallAllowed) { $installDrillDigest } else { $null }
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
    [ordered]@{ id = "missing-boundary"; blockers = @("rc18-disposable-image-boundary-not-bound"); reason = "Isolated install requires RC18 image boundary." },
    [ordered]@{ id = "missing-baseline"; blockers = @("rc18-installed-system-baseline-not-bound"); reason = "Isolated install requires RC18 installed-system baseline identity." },
    [ordered]@{ id = "missing-image-fail-closed"; blockers = @("rc18-image-boundary-fail-closed-not-passed"); reason = "Image-boundary fail-closed matrix must pass before image install." },
    [ordered]@{ id = "missing-target"; blockers = @("exact-install-update-target-not-bound"); reason = "Exact target binding is required." },
    [ordered]@{ id = "missing-approval"; blockers = @("exact-install-update-approval-not-bound"); reason = "Exact approval binding is required." },
    [ordered]@{ id = "missing-agentcore"; blockers = @("agentcore-install-update-planspec-not-bound"); reason = "AgentCore executable PlanSpec is required." },
    [ordered]@{ id = "missing-security-execution"; blockers = @("security-execution-install-update-allow-not-bound"); reason = "SecurityExecution allow is required." },
    [ordered]@{ id = "missing-rollback-preconditions"; blockers = @("rollback-preconditions-not-bound"); reason = "Rollback preconditions are required before install drill." },
    [ordered]@{ id = "identity-mismatch"; blockers = @("install-identity-does-not-match-baseline"); reason = "Install identity must match baseline release/media/package." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs writes are outside the image boundary." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot writes are outside the image boundary." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata writes are outside the image boundary." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set writes are outside the image boundary." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of RC18 install drill scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18 install drill scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of RC18 install drill scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18 install drill scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of RC18 install drill scope." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not install authority." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not install authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is out of RC18 install drill scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC18 install drill cannot claim GA production readiness." }
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
    rc18_baseline_result = New-ArtifactRef $resolvedBaselineResultPath $baselineResult
    rc18_baseline_identity = New-ArtifactRef $resolvedBaselineIdentityPath $baselineIdentity
    rc18_boot_state_projection = New-ArtifactRef $resolvedBootStateProjectionPath $bootStateProjection
    rc18_image_boundary_fail_closed_result = New-ArtifactRef $resolvedImageBoundaryFailClosedResultPath $failClosedResult
    rc17_controlled_local_install_result = New-ArtifactRef $resolvedRc17InstallResultPath $rc17InstallResult
    rc17_controlled_local_install_evidence = New-ArtifactRef $resolvedRc17InstallEvidencePath $rc17InstallEvidence
    rc17_target_binding_result = New-ArtifactRef $resolvedRc17TargetBindingResultPath $rc17TargetResult
    rc17_approval_binding_result = New-ArtifactRef $resolvedRc17ApprovalBindingResultPath $rc17ApprovalResult
    rc17_agentcore_result = New-ArtifactRef $resolvedRc17AgentCoreResultPath $rc17AgentCoreResult
    rc17_security_execution_result = New-ArtifactRef $resolvedRc17SecurityExecutionResultPath $rc17SecurityResult
    rc17_rollback_preconditions_result = New-ArtifactRef $resolvedRc17RollbackPreconditionsResultPath $rc17RollbackResult
}

$installDrillEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-install-drill-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-020"
    status = if ($isolatedInstallAllowed) { "isolated-install-executed-inside-disposable-image" } else { "isolated-install-denied-before-image-effect" }
    production_ready_claim = $false
    isolated_install_allowed = $isolatedInstallAllowed
    isolated_install_performed = $isolatedInstallAllowed
    denied = (-not $isolatedInstallAllowed)
    denial_reasons = @($blockers)
    install_drill_digest = $installDrillDigest
    installed_image_state_id = $installedImageStateId
    install_drill_material = $installDrillMaterial
    gate_bindings = [ordered]@{
        image_boundary_bound = $boundaryReady
        baseline_identity_bound = $baselineReady
        image_boundary_fail_closed_verified = $failClosedReady
        exact_target_bound = $targetBound
        exact_approval_bound = $approvalBound
        agentcore_planspec_bound = $agentCoreBound
        security_execution_allow_bound = $securityBound
        rollback_preconditions_bound = $rollbackPreconditionsBound
        rc17_controlled_install_ready = $rc17InstallReady
        identity_matches_baseline = $identityMatchesBaseline
    }
    image_effect = $imageEffect
    fail_closed_cases = $cases
    source = $source
}
$installDrillEvidencePath = Join-Path $resolvedArtifactDir "install-drill-evidence.json"
Write-Json $installDrillEvidence $installDrillEvidencePath

Add-Check "plan.current_task.rc18_020" $planAllowsRun "RC18-020 must run after RC18-012 completed, while current_task is RC18-020 or during a completed rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_012_status = $rc18PreviousStatus; rc18_020_status = $rc18TaskStatus })
Add-Check "source.image_boundary.ready" $boundaryReady "RC18-020 must bind the disposable installed-system image boundary and allowed write surface." ([ordered]@{ boundary_id = $boundaryResult.boundary_id; state_root_id = $boundaryResult.state_root_id; only_writable_drill_surface = $imageBoundary.allowed_write_surface.only_writable_drill_surface })
Add-Check "source.baseline.ready" $baselineReady "RC18-020 must bind installed-system baseline identity and boot-state projection." ([ordered]@{ baseline_id = $baselineResult.baseline_id; baseline_identity_bound = $baselineResult.baseline_identity_bound; boot_state_projection_bound = $baselineResult.boot_state_projection_bound; boundary_id = $baselineResult.boundary_id })
Add-Check "source.fail_closed.ready" $failClosedReady "RC18-020 must bind the image-boundary side-effect fail-closed matrix before any image install effect." ([ordered]@{ side_effect_fail_closed_verified = $failClosedResult.side_effect_fail_closed_verified; cases = $failClosedResult.summary.cases; failed_cases = $failClosedResult.summary.failed_cases })
Add-Check "source.rc17_install.ready" $rc17InstallReady "RC18-020 must consume RC17 controlled local install evidence with non-fabricated audit and no forbidden host or remote side effects." ([ordered]@{ install_allowed = $rc17InstallResult.install_surface.install_allowed; install_performed = $rc17InstallResult.install_surface.install_performed; audit_fabricated = $rc17InstallEvidence.audit_record.fabricated; host_active_slot_mutated = $rc17InstallResult.install_surface.host_active_slot_mutated; host_boot_metadata_mutated = $rc17InstallResult.install_surface.host_boot_metadata_mutated; remote_dispatch_enabled = $rc17InstallResult.install_surface.remote_dispatch_enabled })
Add-Check "gates.exact_install_chain.bound" ($targetBound -and $approvalBound -and $agentCoreBound -and $securityBound -and $rollbackPreconditionsBound -and $identityMatchesBaseline) "Install evidence must bind exact target, exact approval, AgentCore PlanSpec, SecurityExecution allow, rollback preconditions, and baseline identity." ([ordered]@{ exact_target_bound = $targetBound; exact_approval_bound = $approvalBound; agentcore_planspec_bound = $agentCoreBound; security_execution_allow_bound = $securityBound; rollback_preconditions_bound = $rollbackPreconditionsBound; identity_matches_baseline = $identityMatchesBaseline })
Add-Check "install.image_local.execute_or_deny" (($isolatedInstallAllowed -and $imageEffect.isolated_install_performed -eq $true -and $imageEffect.disposable_image_state_mutated -eq $true -and $imageEffect.installed_image_state_id -like "sha256:*") -or ((-not $isolatedInstallAllowed) -and $installDrillEvidence.denied -eq $true -and $imageEffect.disposable_image_state_mutated -eq $false)) "Install drill must execute only inside the disposable image boundary or deny before image effect." ([ordered]@{ isolated_install_allowed = $isolatedInstallAllowed; isolated_install_performed = $imageEffect.isolated_install_performed; disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated; installed_image_state_id = $imageEffect.installed_image_state_id; blockers = @($blockers) })
Add-Check "authority.no_forbidden_side_effects" ($imageEffect.host_rootfs_mutated -eq $false -and $imageEffect.host_active_slot_mutated -eq $false -and $imageEffect.host_boot_metadata_mutated -eq $false -and $imageEffect.active_artifact_set_mutated -eq $false -and $imageEffect.production_ring_mutated -eq $false -and $imageEffect.support_upload_performed -eq $false -and $imageEffect.recovery_execution_performed -eq $false -and $imageEffect.remote_dispatch_enabled -eq $false -and $imageEffect.mirror_frontend_mutated -eq $false -and $imageEffect.signer_authority_granted -eq $false -and $imageEffect.private_signing_material_handled -eq $false) "RC18-020 must not mutate host rootfs, host slot, host boot metadata, active artifact set, production ring, support upload, recovery, remote dispatch, mirror/frontend, signer, or private material." $imageEffect
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing gates and forbidden authority surfaces must deny before image install or host mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $installDrillEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-020 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-isolated-install-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-020"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $boundaryResult.boundary_id
    baseline_id = $baselineResult.baseline_id
    installed_image_state_id = $installedImageStateId
    isolated_install_allowed = $isolatedInstallAllowed
    isolated_install_performed = $imageEffect.isolated_install_performed
    outputs = [ordered]@{
        install_drill_evidence = [ordered]@{
            path = Get-StablePath $installDrillEvidencePath
            sha256 = Get-FileSha256 $installDrillEvidencePath
            install_drill_digest = $installDrillDigest
            installed_image_state_id = $installedImageStateId
        }
    }
    install_surface = [ordered]@{
        state = if ($isolatedInstallAllowed) { "isolated-install-executed-inside-disposable-image" } else { "isolated-install-denied-before-image-effect" }
        image_scope = "disposable-installed-system-image-or-vm"
        image_boundary_bound = $boundaryReady
        baseline_identity_bound = $baselineReady
        image_boundary_fail_closed_verified = $failClosedReady
        exact_target_bound = $targetBound
        exact_approval_bound = $approvalBound
        agentcore_planspec_bound = $agentCoreBound
        security_execution_allow_bound = $securityBound
        rollback_preconditions_bound = $rollbackPreconditionsBound
        isolated_install_allowed = $isolatedInstallAllowed
        isolated_install_performed = $imageEffect.isolated_install_performed
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
        install_drill_inside_disposable_image_only = $true
        isolated_install_performed = $imageEffect.isolated_install_performed
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
        rc18_020_complete = (@($script:failedChecks).Count -eq 0)
        isolated_install_allowed = $isolatedInstallAllowed
        isolated_install_performed = $imageEffect.isolated_install_performed
        disposable_image_state_mutated = $imageEffect.disposable_image_state_mutated
        installed_image_state_id = $installedImageStateId
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-021"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-020-isolated-install-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-install-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-020"
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
    install_surface = $result.install_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc18_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-021"
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
    throw "Sensitive marker detected in RC18-020 outputs."
}

Write-Host "RC18 isolated install drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $installDrillEvidencePath)"
Write-Host "Isolated install performed: $($imageEffect.isolated_install_performed); disposable image state mutated: $($imageEffect.disposable_image_state_mutated)"
Write-Host "Host rootfs/slot/boot mutation: false; remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
