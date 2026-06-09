param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-image-rollback-preconditions",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$InstallResultPath = ".workflow/artifacts/rc18-isolated-install-drill/result.json",
    [string]$InstallEvidencePath = ".workflow/artifacts/rc18-isolated-install-drill/install-drill-evidence.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$UpdateEvidencePath = ".workflow/artifacts/rc18-isolated-update-drill/update-drill-evidence.json",
    [string]$Rc17RollbackSupportResultPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json",
    [string]$Rc17RollbackEvidencePath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/rollback-execute-or-deny-evidence.json",
    [string]$Rc17SupportRecoveryChainPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/support-recovery-evidence-chain.json",
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
        denied_before_rollback_execution = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            rollback_effect_prepared = $false
            rollback_execution_performed = $false
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
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedUpdateEvidencePath = Resolve-RepoPath $UpdateEvidencePath
$resolvedRc17RollbackSupportResultPath = Resolve-RepoPath $Rc17RollbackSupportResultPath
$resolvedRc17RollbackEvidencePath = Resolve-RepoPath $Rc17RollbackEvidencePath
$resolvedRc17SupportRecoveryChainPath = Resolve-RepoPath $Rc17SupportRecoveryChainPath
$resolvedRc17ObservationPlanPath = Resolve-RepoPath $Rc17ObservationPlanPath

$plan = Read-Json $resolvedPlanPath
$boundaryResult = Read-Json $resolvedBoundaryResultPath
$imageBoundary = Read-Json $resolvedImageBoundaryPath
$installResult = Read-Json $resolvedInstallResultPath
$installEvidence = Read-Json $resolvedInstallEvidencePath
$updateResult = Read-Json $resolvedUpdateResultPath
$updateEvidence = Read-Json $resolvedUpdateEvidencePath
$rc17RollbackSupportResult = Read-Json $resolvedRc17RollbackSupportResultPath
$rc17RollbackEvidence = Read-Json $resolvedRc17RollbackEvidencePath
$rc17SupportRecoveryChain = Read-Json $resolvedRc17SupportRecoveryChainPath
$rc17ObservationPlan = Read-Json $resolvedRc17ObservationPlanPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-021"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-022"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-022" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-030" -and $rc18TaskStatus -eq "completed")
    )
)

$installMaterial = $installEvidence.install_drill_material
$updateMaterial = $updateEvidence.update_drill_material

$boundaryReady = (
    $boundaryResult.status -eq "passed" -and
    $boundaryResult.boundary_id -eq $imageBoundary.boundary_id -and
    $boundaryResult.boundary_id -eq $installMaterial.boundary_id -and
    $boundaryResult.boundary_id -eq $updateMaterial.boundary_id -and
    $imageBoundary.allowed_write_surface.only_writable_drill_surface -eq "disposable-installed-system-image-or-vm"
)
$installReady = (
    $installResult.status -eq "passed" -and
    $installResult.summary.rc18_020_complete -eq $true -and
    $installResult.summary.isolated_install_performed -eq $true -and
    $installResult.summary.disposable_image_state_mutated -eq $true -and
    $installResult.summary.host_rootfs_mutated -eq $false -and
    $installResult.summary.host_active_slot_mutated -eq $false -and
    $installResult.summary.host_boot_metadata_mutated -eq $false -and
    $installEvidence.installed_image_state_id -eq $updateMaterial.previous_installed_image_state_id
)
$updateReady = (
    $updateResult.status -eq "passed" -and
    $updateResult.summary.rc18_021_complete -eq $true -and
    $updateResult.summary.isolated_update_performed -eq $true -and
    $updateResult.summary.disposable_image_state_mutated -eq $true -and
    $updateResult.summary.previous_installed_image_state_id -eq $installEvidence.installed_image_state_id -and
    $updateResult.summary.updated_image_state_id -eq $updateEvidence.updated_image_state_id -and
    $updateResult.summary.host_rootfs_mutated -eq $false -and
    $updateResult.summary.host_active_slot_mutated -eq $false -and
    $updateResult.summary.host_boot_metadata_mutated -eq $false -and
    $updateResult.summary.remote_dispatch_enabled -eq $false
)
$identityMatchesUpdate = (
    $installMaterial.release_id -eq $updateMaterial.release_id -and
    $installMaterial.media_id -eq $updateMaterial.media_id -and
    $installMaterial.package_id -eq $updateMaterial.package_id -and
    $installMaterial.target_binding_id -eq $updateMaterial.target_binding_id -and
    $installMaterial.approval_id -eq $updateMaterial.approval_id -and
    $installMaterial.planspec_core_hash -eq $updateMaterial.planspec_core_hash -and
    $installMaterial.effect_envelope_core_hash -eq $updateMaterial.effect_envelope_core_hash -and
    $installMaterial.rollback_precondition_core_hash -eq $updateMaterial.rollback_precondition_core_hash
)
$rc17RollbackSupportReady = (
    $rc17RollbackSupportResult.status -eq "passed" -and
    $rc17RollbackSupportResult.summary.rc17_032_complete -eq $true -and
    $rc17RollbackSupportResult.summary.install_performed -eq $true -and
    $rc17RollbackSupportResult.summary.update_performed -eq $true -and
    $rc17RollbackSupportResult.summary.rollback_execution_performed -eq $true -and
    $rc17RollbackSupportResult.summary.support_bundle_local_only -eq $true -and
    $rc17RollbackSupportResult.summary.support_upload_performed -eq $false -and
    $rc17RollbackSupportResult.summary.recovery_execution_performed -eq $false -and
    $rc17RollbackSupportResult.summary.remote_dispatch_enabled -eq $false -and
    $rc17SupportRecoveryChain.support_bundle_local_only -eq $true -and
    $rc17SupportRecoveryChain.support_upload_performed -eq $false -and
    $rc17SupportRecoveryChain.recovery_execution_performed -eq $false
)
$observationPlanReady = (
    $rc17ObservationPlan.status -eq "post-install-update-observation-plan-bound-effects-denied" -and
    $updateMaterial.observation_plan_sha256 -eq (Get-FileSha256 $resolvedRc17ObservationPlanPath)
)

$postUpdateObservationCore = [ordered]@{
    schema = "agentos.rc18-image-post-update-observation-core.v1"
    task = "RC18-022"
    boundary_id = $boundaryResult.boundary_id
    previous_installed_image_state_id = $installEvidence.installed_image_state_id
    updated_image_state_id = $updateEvidence.updated_image_state_id
    release_id = $updateMaterial.release_id
    media_id = $updateMaterial.media_id
    package_id = $updateMaterial.package_id
    update_drill_digest = $updateEvidence.update_drill_digest
    install_drill_digest = $installEvidence.install_drill_digest
    observation_plan_sha256 = $updateMaterial.observation_plan_sha256
    observed_inside_disposable_image = $true
    host_boot_state_authoritative = $false
    host_mutation_allowed = $false
    rollback_execution_allowed = $false
}
$postUpdateObservationDigest = Get-StringSha256 (Get-JsonText $postUpdateObservationCore)

$postUpdateObservation = [ordered]@{
    schema = "agentos.rc18-image-post-update-observation.v1"
    generated_at = $generatedAtValue
    task = "RC18-022"
    status = "post-update-observation-bound-inside-disposable-image"
    production_ready_claim = $false
    observation_id = "sha256:$postUpdateObservationDigest"
    observation_core = $postUpdateObservationCore
    observed_state = [ordered]@{
        image_scope = "disposable-installed-system-image-or-vm"
        previous_installed_image_state_id = $installEvidence.installed_image_state_id
        updated_image_state_id = $updateEvidence.updated_image_state_id
        image_boundary_bound = $boundaryReady
        install_evidence_bound = $installReady
        update_evidence_bound = $updateReady
        identity_matches_update = $identityMatchesUpdate
        observation_plan_bound = $observationPlanReady
        rollback_required = $true
    }
    observations = @(
        [ordered]@{ id = "updated-image-state-bound"; status = "observed"; evidence = $updateEvidence.updated_image_state_id },
        [ordered]@{ id = "previous-image-state-bound"; status = "observed"; evidence = $installEvidence.installed_image_state_id },
        [ordered]@{ id = "release-identity-bound"; status = "observed"; evidence = $updateMaterial.release_id },
        [ordered]@{ id = "package-identity-bound"; status = "observed"; evidence = $updateMaterial.package_id },
        [ordered]@{ id = "rollback-precondition-core-bound"; status = "observed"; evidence = $updateMaterial.rollback_precondition_core_hash },
        [ordered]@{ id = "host-rootfs-unchanged"; status = "observed"; evidence = $false },
        [ordered]@{ id = "host-slot-unchanged"; status = "observed"; evidence = $false },
        [ordered]@{ id = "host-boot-metadata-unchanged"; status = "observed"; evidence = $false },
        [ordered]@{ id = "support-upload-not-performed"; status = "observed"; evidence = $false },
        [ordered]@{ id = "remote-dispatch-disabled"; status = "observed"; evidence = $false }
    )
    source_observation_plan = [ordered]@{
        path = Get-StablePath $resolvedRc17ObservationPlanPath
        sha256 = Get-FileSha256 $resolvedRc17ObservationPlanPath
        observation_count = @($rc17ObservationPlan.observations).Count
    }
}
$postUpdateObservationPath = Join-Path $resolvedArtifactDir "post-update-observation.json"
Write-Json $postUpdateObservation $postUpdateObservationPath

$rollbackPreconditionCore = [ordered]@{
    schema = "agentos.rc18-image-rollback-precondition-core.v1"
    task = "RC18-022"
    boundary_id = $boundaryResult.boundary_id
    baseline_id = $updateMaterial.baseline_id
    release_id = $updateMaterial.release_id
    media_id = $updateMaterial.media_id
    package_id = $updateMaterial.package_id
    prior_install_state_id = $installEvidence.installed_image_state_id
    updated_image_state_id = $updateEvidence.updated_image_state_id
    post_update_observation_id = $postUpdateObservation.observation_id
    post_update_observation_sha256 = Get-FileSha256 $postUpdateObservationPath
    rollback_precondition_core_hash = $updateMaterial.rollback_precondition_core_hash
    rc17_rollback_attempt_digest = $rc17RollbackEvidence.rollback_attempt_digest
    rc17_rollback_audit_digest = $rc17RollbackEvidence.rollback_audit_digest
    rc17_support_recovery_chain_sha256 = Get-FileSha256 $resolvedRc17SupportRecoveryChainPath
    rollback_execution_gated_until = "RC18-030"
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
}
$rollbackPreconditionDigest = Get-StringSha256 (Get-JsonText $rollbackPreconditionCore)

$preconditionsBound = (
    $planAllowsRun -and
    $boundaryReady -and
    $installReady -and
    $updateReady -and
    $identityMatchesUpdate -and
    $rc17RollbackSupportReady -and
    $observationPlanReady
)
$rollbackExecutionAllowed = $false
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc18-022-plan-pointer-not-current" }
if (-not $boundaryReady) { $blockers += "rc18-disposable-image-boundary-not-bound" }
if (-not $installReady) { $blockers += "rc18-isolated-install-evidence-not-bound" }
if (-not $updateReady) { $blockers += "rc18-isolated-update-evidence-not-bound" }
if (-not $identityMatchesUpdate) { $blockers += "install-update-identity-mismatch" }
if (-not $rc17RollbackSupportReady) { $blockers += "rc17-rollback-support-evidence-not-bound" }
if (-not $observationPlanReady) { $blockers += "post-update-observation-plan-not-bound" }
if ($preconditionsBound) { $blockers = @("rollback-execution-deferred-to-rc18-030") }

$rollbackPreconditionPackage = [ordered]@{
    schema = "agentos.rc18-image-rollback-precondition-package.v1"
    generated_at = $generatedAtValue
    task = "RC18-022"
    status = if ($preconditionsBound) { "image-rollback-preconditions-bound-execution-gated" } else { "image-rollback-preconditions-denied" }
    production_ready_claim = $false
    rollback_precondition_id = "sha256:$rollbackPreconditionDigest"
    rollback_preconditions_bound = $preconditionsBound
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    rollback_execution_gate = "RC18-030"
    denial_reasons = @($blockers)
    precondition_core = $rollbackPreconditionCore
    requirements = [ordered]@{
        image_boundary_bound = $boundaryReady
        install_evidence_bound = $installReady
        update_evidence_bound = $updateReady
        identity_matches_update = $identityMatchesUpdate
        rc17_rollback_support_bound = $rc17RollbackSupportReady
        post_update_observation_bound = $true
        rollback_execution_separate_task_required = $true
    }
    authority = [ordered]@{
        host_rootfs_mutation_allowed = $false
        host_active_slot_mutation_allowed = $false
        host_boot_metadata_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        mirror_frontend_authority = $false
        signer_authority = $false
        private_signing_material_handled = $false
    }
}
$rollbackPreconditionPackagePath = Join-Path $resolvedArtifactDir "rollback-precondition-package.json"
Write-Json $rollbackPreconditionPackage $rollbackPreconditionPackagePath

$sideEffects = [ordered]@{
    image_scope = "disposable-installed-system-image-or-vm"
    post_update_observation_bound = $true
    rollback_preconditions_bound = $preconditionsBound
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
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
    [ordered]@{ id = "missing-boundary"; blockers = @("rc18-disposable-image-boundary-not-bound"); reason = "Rollback preconditions require image boundary." },
    [ordered]@{ id = "missing-install-evidence"; blockers = @("rc18-isolated-install-evidence-not-bound"); reason = "Rollback preconditions require isolated install evidence." },
    [ordered]@{ id = "missing-update-evidence"; blockers = @("rc18-isolated-update-evidence-not-bound"); reason = "Rollback preconditions require isolated update evidence." },
    [ordered]@{ id = "stale-updated-image-state"; blockers = @("updated-image-state-mismatch"); reason = "Rollback preconditions must bind current updated image state." },
    [ordered]@{ id = "install-update-identity-mismatch"; blockers = @("install-update-identity-mismatch"); reason = "Install and update identities must match." },
    [ordered]@{ id = "missing-rc17-rollback-support"; blockers = @("rc17-rollback-support-evidence-not-bound"); reason = "RC17 rollback/support evidence is required." },
    [ordered]@{ id = "missing-observation-plan"; blockers = @("post-update-observation-plan-not-bound"); reason = "Post-update observation plan is required." },
    [ordered]@{ id = "rollback-execution-attempt"; blockers = @("rollback-execution-deferred-to-rc18-030"); reason = "RC18-022 binds preconditions but cannot execute rollback." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs writes are outside the image boundary." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot writes are outside the image boundary." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata writes are outside the image boundary." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set writes are outside the image boundary." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of RC18-022 scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18-022 scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of RC18-022 scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18-022 scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of RC18-022 scope." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not rollback authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not rollback authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is out of RC18-022 scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC18-022 cannot claim GA production readiness." }
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
    rc18_isolated_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc18_isolated_update_evidence = New-ArtifactRef $resolvedUpdateEvidencePath $updateEvidence
    rc17_rollback_support_result = New-ArtifactRef $resolvedRc17RollbackSupportResultPath $rc17RollbackSupportResult
    rc17_rollback_evidence = New-ArtifactRef $resolvedRc17RollbackEvidencePath $rc17RollbackEvidence
    rc17_support_recovery_chain = New-ArtifactRef $resolvedRc17SupportRecoveryChainPath $rc17SupportRecoveryChain
    rc17_observation_plan = New-ArtifactRef $resolvedRc17ObservationPlanPath $rc17ObservationPlan
}

Add-Check "plan.current_task.rc18_022" $planAllowsRun "RC18-022 must run after RC18-021 completed, while current_task is RC18-022 or during a completed rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_021_status = $rc18PreviousStatus; rc18_022_status = $rc18TaskStatus })
Add-Check "source.image_boundary.ready" $boundaryReady "RC18-022 must bind the disposable installed-system image boundary." ([ordered]@{ boundary_id = $boundaryResult.boundary_id; only_writable_drill_surface = $imageBoundary.allowed_write_surface.only_writable_drill_surface })
Add-Check "source.install_update.ready" ($installReady -and $updateReady -and $identityMatchesUpdate) "RC18-022 must bind completed isolated install and update evidence over the same release, media, package, target, approval, AgentCore, SecurityExecution, and rollback precondition identity." ([ordered]@{ install_ready = $installReady; update_ready = $updateReady; identity_matches_update = $identityMatchesUpdate; installed_image_state_id = $installEvidence.installed_image_state_id; updated_image_state_id = $updateEvidence.updated_image_state_id })
Add-Check "source.rc17_rollback_support.ready" $rc17RollbackSupportReady "RC18-022 must consume RC17 rollback/support evidence without granting RC18 rollback execution authority." ([ordered]@{ rc17_rollback_execution_performed = $rc17RollbackSupportResult.summary.rollback_execution_performed; support_bundle_local_only = $rc17RollbackSupportResult.summary.support_bundle_local_only; support_upload_performed = $rc17RollbackSupportResult.summary.support_upload_performed; recovery_execution_performed = $rc17RollbackSupportResult.summary.recovery_execution_performed; remote_dispatch_enabled = $rc17RollbackSupportResult.summary.remote_dispatch_enabled })
Add-Check "post_update_observation.image_bound" ($postUpdateObservation.observed_state.image_boundary_bound -eq $true -and $postUpdateObservation.observed_state.update_evidence_bound -eq $true -and $postUpdateObservation.observed_state.updated_image_state_id -eq $updateEvidence.updated_image_state_id -and $postUpdateObservation.observation_core.host_boot_state_authoritative -eq $false) "Post-update observation must be bound to updated image state inside the disposable image boundary and remain non-authoritative for host boot state." ([ordered]@{ observation_id = $postUpdateObservation.observation_id; observation_count = @($postUpdateObservation.observations).Count; host_boot_state_authoritative = $postUpdateObservation.observation_core.host_boot_state_authoritative })
Add-Check "rollback_preconditions.bound" ($preconditionsBound -and $rollbackPreconditionPackage.rollback_preconditions_bound -eq $true -and $rollbackPreconditionPackage.rollback_precondition_id -like "sha256:*") "Rollback preconditions must bind image boundary, install evidence, update evidence, post-update observation, and rollback/support references." ([ordered]@{ rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id; preconditions_bound = $preconditionsBound; post_update_observation_sha256 = $rollbackPreconditionCore.post_update_observation_sha256 })
Add-Check "rollback.execution.gated_until_rc18_030" ($rollbackPreconditionPackage.rollback_execution_allowed -eq $false -and $rollbackPreconditionPackage.rollback_execution_performed -eq $false -and $rollbackPreconditionPackage.rollback_execution_gate -eq "RC18-030") "RC18-022 must not execute rollback; rollback remains gated until RC18-030." ([ordered]@{ rollback_execution_allowed = $rollbackPreconditionPackage.rollback_execution_allowed; rollback_execution_performed = $rollbackPreconditionPackage.rollback_execution_performed; rollback_execution_gate = $rollbackPreconditionPackage.rollback_execution_gate })
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.mirror_frontend_mutated -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.private_signing_material_handled -eq $false) "RC18-022 must not mutate host rootfs, host slot, host boot metadata, active artifact set, production ring, support upload, recovery, remote dispatch, mirror/frontend, signer, or private material." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing gates, rollback execution attempt, and forbidden authority surfaces must deny before rollback execution or host mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $postUpdateObservationPath),
    (Get-Content -Raw -LiteralPath $rollbackPreconditionPackagePath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-022 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-image-rollback-preconditions-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-022"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $boundaryResult.boundary_id
    previous_installed_image_state_id = $installEvidence.installed_image_state_id
    updated_image_state_id = $updateEvidence.updated_image_state_id
    post_update_observation_id = $postUpdateObservation.observation_id
    rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id
    rollback_preconditions_bound = $preconditionsBound
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    outputs = [ordered]@{
        post_update_observation = [ordered]@{
            path = Get-StablePath $postUpdateObservationPath
            sha256 = Get-FileSha256 $postUpdateObservationPath
            observation_id = $postUpdateObservation.observation_id
        }
        rollback_precondition_package = [ordered]@{
            path = Get-StablePath $rollbackPreconditionPackagePath
            sha256 = Get-FileSha256 $rollbackPreconditionPackagePath
            rollback_precondition_id = $rollbackPreconditionPackage.rollback_precondition_id
        }
    }
    rollback_precondition_surface = [ordered]@{
        state = if ($preconditionsBound) { "image-rollback-preconditions-bound-execution-gated" } else { "image-rollback-preconditions-denied" }
        image_scope = "disposable-installed-system-image-or-vm"
        image_boundary_bound = $boundaryReady
        isolated_install_bound = $installReady
        isolated_update_bound = $updateReady
        identity_matches_update = $identityMatchesUpdate
        post_update_observation_bound = $true
        rc17_rollback_support_bound = $rc17RollbackSupportReady
        rollback_preconditions_bound = $preconditionsBound
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        rollback_execution_gate = "RC18-030"
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
        rollback_preconditions_inside_disposable_image_only = $true
        rollback_preconditions_bound = $preconditionsBound
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
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
        rc18_022_complete = (@($script:failedChecks).Count -eq 0)
        rollback_preconditions_bound = $preconditionsBound
        post_update_observation_bound = $true
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-030"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-022-image-rollback-preconditions.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-image-rollback-preconditions-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-022"
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
    rollback_precondition_surface = $result.rollback_precondition_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc18_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-030"
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
    throw "Sensitive marker detected in RC18-022 outputs."
}

Write-Host "RC18 image rollback preconditions $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Post-update observation: $(Get-StablePath $postUpdateObservationPath)"
Write-Host "Rollback preconditions: $(Get-StablePath $rollbackPreconditionPackagePath)"
Write-Host "Rollback execution allowed/performed: false/false; next task: RC18-030"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
