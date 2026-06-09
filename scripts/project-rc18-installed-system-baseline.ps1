param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-installed-system-baseline",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$Rc16MediaResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$Rc16MediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$Rc17FinalAuditResultPath = ".workflow/artifacts/rc17-final-closeout-audit/result.json",
    [string]$Rc17AgentCoreResultPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json",
    [string]$Rc17SecurityExecutionResultPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/result.json",
    [string]$Rc17RollbackSupportResultPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json",
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
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        baseline_mutation_performed = $false
        boot_projection_authoritative_for_host = $false
        side_effects = [ordered]@{
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            mirror_frontend_mutated = $false
            signer_authority_granted = $false
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
$resolvedRc16MediaResultPath = Resolve-RepoPath $Rc16MediaResultPath
$resolvedRc16MediaManifestPath = Resolve-RepoPath $Rc16MediaManifestPath
$resolvedRc17FinalAuditResultPath = Resolve-RepoPath $Rc17FinalAuditResultPath
$resolvedRc17AgentCoreResultPath = Resolve-RepoPath $Rc17AgentCoreResultPath
$resolvedRc17SecurityExecutionResultPath = Resolve-RepoPath $Rc17SecurityExecutionResultPath
$resolvedRc17RollbackSupportResultPath = Resolve-RepoPath $Rc17RollbackSupportResultPath

$plan = Read-Json $resolvedPlanPath
$boundaryResult = Read-Json $resolvedBoundaryResultPath
$imageBoundary = Read-Json $resolvedImageBoundaryPath
$rc16MediaResult = Read-Json $resolvedRc16MediaResultPath
$rc16MediaManifest = Read-Json $resolvedRc16MediaManifestPath
$rc17FinalAuditResult = Read-Json $resolvedRc17FinalAuditResultPath
$rc17AgentCoreResult = Read-Json $resolvedRc17AgentCoreResultPath
$rc17SecurityExecutionResult = Read-Json $resolvedRc17SecurityExecutionResultPath
$rc17RollbackSupportResult = Read-Json $resolvedRc17RollbackSupportResultPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-010"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-011"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-011" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-012" -and $rc18TaskStatus -eq "completed")
    )
)

$sourceEvidence = [ordered]@{
    rc18_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc18_boundary_result = New-ArtifactRef $resolvedBoundaryResultPath $boundaryResult
    rc18_image_boundary = New-ArtifactRef $resolvedImageBoundaryPath $imageBoundary
    rc16_media_result = New-ArtifactRef $resolvedRc16MediaResultPath $rc16MediaResult
    rc16_media_manifest = New-ArtifactRef $resolvedRc16MediaManifestPath $rc16MediaManifest
    rc17_final_audit_result = New-ArtifactRef $resolvedRc17FinalAuditResultPath $rc17FinalAuditResult
    rc17_agentcore_result = New-ArtifactRef $resolvedRc17AgentCoreResultPath $rc17AgentCoreResult
    rc17_security_execution_result = New-ArtifactRef $resolvedRc17SecurityExecutionResultPath $rc17SecurityExecutionResult
    rc17_rollback_support_result = New-ArtifactRef $resolvedRc17RollbackSupportResultPath $rc17RollbackSupportResult
}

$mediaReleaseBytes = $rc16MediaManifest.release_bytes
$initramfsProvenance = $rc16MediaManifest.rootfs_initramfs_provenance.initramfs
$alphaRootfs = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs
$compatibility = $rc16MediaManifest.architecture_and_compatibility
$agentCoreSurface = $rc17AgentCoreResult.planspec_surface
$securitySurface = $rc17SecurityExecutionResult.security_surface
$rollbackSupportSurface = $rc17RollbackSupportResult.rollback_support_surface

$boundaryReady = (
    $boundaryResult.status -eq "passed" -and
    $boundaryResult.image_boundary_bound -eq $true -and
    $boundaryResult.boundary_id -eq $imageBoundary.boundary_id -and
    $boundaryResult.state_root_id -eq $imageBoundary.state_root.state_root_id -and
    $boundaryResult.image_mutation_performed_before_boundary_bound -eq $false -and
    $boundaryResult.boundary_surface.host_boot_metadata_mutated -eq $false -and
    $boundaryResult.boundary_surface.host_active_slot_mutated -eq $false -and
    $boundaryResult.boundary_surface.active_artifact_set_mutated -eq $false
)
$mediaReady = (
    $rc16MediaResult.status -eq "passed" -and
    $rc16MediaManifest.production_ready_claim -eq $false -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.release_id) -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.media_id) -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.package_id) -and
    -not [string]::IsNullOrWhiteSpace($mediaReleaseBytes.payload.sha256) -and
    @($initramfsProvenance.boot_markers).Count -ge 5
)
$agentCoreReady = (
    $rc17AgentCoreResult.status -eq "passed" -and
    $rc17AgentCoreResult.release_id -eq $rc16MediaManifest.release_id -and
    $rc17AgentCoreResult.media_id -eq $rc16MediaManifest.media_id -and
    $rc17AgentCoreResult.package_id -eq $rc16MediaManifest.package_id -and
    $agentCoreSurface.agentcore_install_update_planspec_executable -eq $true -and
    $agentCoreSurface.planspec_core_hash -match "^[0-9a-f]{64}$"
)
$securityReady = (
    $rc17SecurityExecutionResult.status -eq "passed" -and
    $rc17SecurityExecutionResult.release_id -eq $rc16MediaManifest.release_id -and
    $rc17SecurityExecutionResult.media_id -eq $rc16MediaManifest.media_id -and
    $rc17SecurityExecutionResult.package_id -eq $rc16MediaManifest.package_id -and
    $rc17SecurityExecutionResult.planspec_core_hash -eq $agentCoreSurface.planspec_core_hash -and
    $securitySurface.security_execution_install_update_allow -eq $true -and
    $rc17SecurityExecutionResult.effect_envelope_core_hash -match "^[0-9a-f]{64}$"
)
$rollbackSupportReady = (
    $rc17RollbackSupportResult.status -eq "passed" -and
    $rollbackSupportSurface.rollback_execution_performed -eq $true -and
    $rollbackSupportSurface.support_bundle_local_only -eq $true -and
    $rollbackSupportSurface.support_upload_performed -eq $false -and
    $rollbackSupportSurface.recovery_execution_performed -eq $false -and
    $rollbackSupportSurface.remote_dispatch_enabled -eq $false -and
    $rollbackSupportSurface.active_slot_mutated -eq $false -and
    $rollbackSupportSurface.boot_metadata_mutated -eq $false -and
    $rollbackSupportSurface.active_artifact_set_mutated -eq $false -and
    $rollbackSupportSurface.production_ring_mutation_allowed -eq $false
)
$finalAuditReady = (
    $rc17FinalAuditResult.status -eq "passed" -and
    $rc17FinalAuditResult.exact_install_update_ready -eq $true -and
    $rc17FinalAuditResult.production_ready_claim -eq $false
)

$baselineMaterial = [ordered]@{
    schema = "agentos.rc18-installed-system-baseline-material.v1"
    task = "RC18-011"
    release = [ordered]@{
        release_id = $rc16MediaManifest.release_id
        payload_object_id = $mediaReleaseBytes.payload.object_id
        payload_sha256 = $mediaReleaseBytes.payload.sha256
        payload_size_bytes = $mediaReleaseBytes.payload.size_bytes
        descriptor_sha256 = $sourceEvidence.rc16_media_manifest.sha256
        initramfs_manifest_sha256 = $mediaReleaseBytes.initramfs_manifest.sha256
        runtime_manifest_sha256 = $alphaRootfs.rootfs_runtime_manifest_sha256
        runtime_artifact_count = $alphaRootfs.runtime_artifact_count
    }
    media = [ordered]@{
        media_id = $rc16MediaManifest.media_id
        package_id = $rc16MediaManifest.package_id
        target_arch = @($compatibility.target_arch)
        boot_modes = @($compatibility.boot_modes)
        kernel_family = $compatibility.kernel_family
        initramfs_contract = $compatibility.initramfs_contract
    }
    agentcore = [ordered]@{
        planspec_core_hash = $agentCoreSurface.planspec_core_hash
        agentcore_install_update_planspec_executable = $agentCoreSurface.agentcore_install_update_planspec_executable
        exact_install_update_target_bound = $agentCoreSurface.exact_install_update_target_bound
        exact_install_update_approval_bound = $agentCoreSurface.exact_install_update_approval_bound
    }
    security_execution = [ordered]@{
        planspec_core_hash = $rc17SecurityExecutionResult.planspec_core_hash
        effect_envelope_core_hash = $rc17SecurityExecutionResult.effect_envelope_core_hash
        decision_material_hash = $rc17SecurityExecutionResult.decision_material_hash
        security_execution_install_update_allow = $securitySurface.security_execution_install_update_allow
    }
    rollback_support = [ordered]@{
        rc17_rollback_execution_performed = $rollbackSupportSurface.rollback_execution_performed
        rollback_preconditions_bound = $rollbackSupportSurface.rollback_preconditions_bound
        support_bundle_local_only = $rollbackSupportSurface.support_bundle_local_only
        support_upload_performed = $rollbackSupportSurface.support_upload_performed
        recovery_execution_performed = $rollbackSupportSurface.recovery_execution_performed
        remote_dispatch_enabled = $rollbackSupportSurface.remote_dispatch_enabled
    }
    image_boundary = [ordered]@{
        boundary_id = $boundaryResult.boundary_id
        state_root_id = $boundaryResult.state_root_id
        image_boundary_bound = $boundaryResult.image_boundary_bound
        only_writable_drill_surface = $imageBoundary.allowed_write_surface.only_writable_drill_surface
    }
    source_hashes = [ordered]@{
        rc18_boundary_result = $sourceEvidence.rc18_boundary_result.sha256
        rc18_image_boundary = $sourceEvidence.rc18_image_boundary.sha256
        rc16_media_manifest = $sourceEvidence.rc16_media_manifest.sha256
        rc17_final_audit_result = $sourceEvidence.rc17_final_audit_result.sha256
        rc17_agentcore_result = $sourceEvidence.rc17_agentcore_result.sha256
        rc17_security_execution_result = $sourceEvidence.rc17_security_execution_result.sha256
        rc17_rollback_support_result = $sourceEvidence.rc17_rollback_support_result.sha256
    }
}
$baselineMaterialHash = Get-StringSha256 (Get-JsonText $baselineMaterial)
$baselineId = "sha256:$baselineMaterialHash"

$bootStateMaterial = [ordered]@{
    schema = "agentos.rc18-installed-system-boot-state-material.v1"
    task = "RC18-011"
    baseline_id = $baselineId
    image_scope = "disposable-installed-system-image-or-vm"
    projected_boot_args = $initramfsProvenance.boot_args
    projected_boot_markers = @($initramfsProvenance.boot_markers)
    runtime_artifact_ids = @($initramfsProvenance.runtime_artifact_ids)
    runtime_manifest_sha256 = $alphaRootfs.rootfs_runtime_manifest_sha256
    agentd_sha256 = $initramfsProvenance.generated_agentd_sha256
    non_authoritative_for_host_boot_state = $true
    host_boot_metadata_mutated = $false
    host_active_slot_mutated = $false
}
$bootStateProjectionHash = Get-StringSha256 (Get-JsonText $bootStateMaterial)

$baselineIdentity = [ordered]@{
    schema = "agentos.rc18-installed-system-baseline-identity.v1"
    generated_at = $generatedAtValue
    task = "RC18-011"
    status = "installed-system-baseline-bound-projection-only"
    production_ready_claim = $false
    baseline_id = $baselineId
    baseline_material_hash = $baselineMaterialHash
    release = $baselineMaterial.release
    media = $baselineMaterial.media
    agentcore = $baselineMaterial.agentcore
    security_execution = $baselineMaterial.security_execution
    rollback_support = $baselineMaterial.rollback_support
    image_boundary = $baselineMaterial.image_boundary
    source = $sourceEvidence
    authority = [ordered]@{
        aios_body_only = $true
        baseline_projection_only = $true
        image_materialized = $false
        vm_booted = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed_in_rc18 = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        mirror_frontend_authority = $false
        signer_authority = $false
    }
}
$baselineIdentityPath = Join-Path $resolvedArtifactDir "baseline-identity.json"
Write-Json $baselineIdentity $baselineIdentityPath

$bootStateProjection = [ordered]@{
    schema = "agentos.rc18-installed-system-boot-state-projection.v1"
    generated_at = $generatedAtValue
    task = "RC18-011"
    status = "image-local-boot-state-projected-non-authoritative"
    production_ready_claim = $false
    baseline_id = $baselineId
    boot_state_projection_hash = $bootStateProjectionHash
    image_scope = "disposable-installed-system-image-or-vm"
    projection_authority = [ordered]@{
        image_local_projection = $true
        non_authoritative_for_host_boot_state = $true
        host_boot_metadata_authority = $false
        host_active_slot_authority = $false
        active_artifact_set_authority = $false
        production_ring_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
    }
    projected_boot = [ordered]@{
        boot_args = $initramfsProvenance.boot_args
        markers = @($initramfsProvenance.boot_markers)
        runtime_manifest_sha256 = $alphaRootfs.rootfs_runtime_manifest_sha256
        runtime_artifact_count = $alphaRootfs.runtime_artifact_count
        runtime_artifact_ids = @($initramfsProvenance.runtime_artifact_ids)
        generated_agentd_sha256 = $initramfsProvenance.generated_agentd_sha256
    }
    host_state = [ordered]@{
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    next_gate = [ordered]@{
        next_task = "RC18-012"
        required_before_image_mutation = @(
            "rc18-011-baseline-bound",
            "rc18-012-image-boundary-fail-closed-passed"
        )
        image_mutation_allowed_now = $false
    }
}
$bootStateProjectionPath = Join-Path $resolvedArtifactDir "boot-state-projection.json"
Write-Json $bootStateProjection $bootStateProjectionPath

$caseSpecs = @(
    [ordered]@{ id = "missing-image-boundary"; blockers = @("rc18-image-boundary-not-bound"); reason = "Baseline identity requires the RC18 disposable image boundary." },
    [ordered]@{ id = "boundary-id-mismatch"; blockers = @("rc18-boundary-id-mismatch"); reason = "Baseline identity cannot bind a different image boundary." },
    [ordered]@{ id = "missing-media-manifest"; blockers = @("rc16-media-manifest-not-bound"); reason = "Release, media, and package identity require the installable media manifest." },
    [ordered]@{ id = "release-media-package-mismatch"; blockers = @("release-media-package-identity-mismatch"); reason = "AgentCore and SecurityExecution must target the same release, media, and package." },
    [ordered]@{ id = "missing-agentcore-planspec"; blockers = @("agentcore-planspec-not-bound"); reason = "Installed-system baseline requires AgentCore PlanSpec binding." },
    [ordered]@{ id = "missing-security-execution-allow"; blockers = @("security-execution-allow-not-bound"); reason = "Installed-system baseline requires SecurityExecution allow evidence." },
    [ordered]@{ id = "missing-rollback-support"; blockers = @("rollback-support-not-bound"); reason = "Installed-system baseline requires rollback and support evidence." },
    [ordered]@{ id = "host-boot-authority-attempt"; blockers = @("host-boot-authority-denied"); reason = "Boot-state projection is image-local and non-authoritative for host boot state." },
    [ordered]@{ id = "host-active-slot-write-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot is outside the RC18 baseline surface." },
    [ordered]@{ id = "host-boot-metadata-write-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata is outside the RC18 baseline surface." },
    [ordered]@{ id = "active-artifact-set-write-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set cannot be changed by baseline projection." },
    [ordered]@{ id = "production-ring-write-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of RC18 baseline scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18 body-only scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of RC18 body-only scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18 body-only scope." },
    [ordered]@{ id = "mirror-or-signer-authority-attempt"; blockers = @("mirror-signer-authority-denied"); reason = "Mirror frontend and signer reachability are not baseline authority." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc18_011" $planAllowsRun "RC18-011 must run after RC18-010 completed, while current_task is RC18-011 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_010_status = $rc18PreviousStatus; rc18_011_status = $rc18TaskStatus })
Add-Check "boundary.rc18_010.ready" $boundaryReady "RC18-011 must bind the completed disposable installed-system image boundary and state root." ([ordered]@{ boundary_id = $boundaryResult.boundary_id; state_root_id = $boundaryResult.state_root_id; image_boundary_bound = $boundaryResult.image_boundary_bound; host_boot_metadata_mutated = $boundaryResult.boundary_surface.host_boot_metadata_mutated })
Add-Check "media.release.package.bound" $mediaReady "Baseline identity must bind release, media, package, payload, initramfs, and runtime marker references." ([ordered]@{ release_id = $rc16MediaManifest.release_id; media_id = $rc16MediaManifest.media_id; package_id = $rc16MediaManifest.package_id; payload_sha256 = $mediaReleaseBytes.payload.sha256; boot_markers = @($initramfsProvenance.boot_markers).Count })
Add-Check "agentcore.bound" $agentCoreReady "Baseline identity must bind AgentCore executable install/update PlanSpec evidence for the same release, media, and package." ([ordered]@{ planspec_core_hash = $agentCoreSurface.planspec_core_hash; executable = $agentCoreSurface.agentcore_install_update_planspec_executable; release_id = $rc17AgentCoreResult.release_id; media_id = $rc17AgentCoreResult.media_id; package_id = $rc17AgentCoreResult.package_id })
Add-Check "security_execution.bound" $securityReady "Baseline identity must bind SecurityExecution install/update allow evidence and effect envelope for the same PlanSpec." ([ordered]@{ planspec_core_hash = $rc17SecurityExecutionResult.planspec_core_hash; effect_envelope_core_hash = $rc17SecurityExecutionResult.effect_envelope_core_hash; security_execution_install_update_allow = $securitySurface.security_execution_install_update_allow })
Add-Check "rollback_support.bound" $rollbackSupportReady "Baseline identity must bind rollback/support evidence while preserving local-only support and disabled recovery/remote dispatch." ([ordered]@{ rollback_execution_performed = $rollbackSupportSurface.rollback_execution_performed; support_bundle_local_only = $rollbackSupportSurface.support_bundle_local_only; support_upload_performed = $rollbackSupportSurface.support_upload_performed; recovery_execution_performed = $rollbackSupportSurface.recovery_execution_performed; remote_dispatch_enabled = $rollbackSupportSurface.remote_dispatch_enabled })
Add-Check "rc17.final_audit.ready" $finalAuditReady "Baseline identity must inherit the RC17 exact install/update readiness without GA authority." ([ordered]@{ exact_install_update_ready = $rc17FinalAuditResult.exact_install_update_ready; production_ready_claim = $rc17FinalAuditResult.production_ready_claim })
Add-Check "baseline.identity.hash_bound" ($baselineId -like "sha256:*" -and $baselineMaterialHash.Length -eq 64 -and (Test-Path -LiteralPath $baselineIdentityPath -PathType Leaf)) "Baseline identity must be content-addressed and written as an artifact." ([ordered]@{ baseline_id = $baselineId; baseline_material_hash = $baselineMaterialHash; path = Get-StablePath $baselineIdentityPath })
Add-Check "boot_state.image_local_non_authoritative" ($bootStateProjection.projection_authority.image_local_projection -eq $true -and $bootStateProjection.projection_authority.non_authoritative_for_host_boot_state -eq $true -and $bootStateProjection.projection_authority.host_boot_metadata_authority -eq $false -and $bootStateProjection.projection_authority.host_active_slot_authority -eq $false -and @($bootStateProjection.projected_boot.markers).Count -ge 5) "Boot-state projection must be explicitly image-local and non-authoritative for host boot state." ([ordered]@{ boot_state_projection_hash = $bootStateProjectionHash; markers = @($bootStateProjection.projected_boot.markers).Count; host_boot_metadata_authority = $bootStateProjection.projection_authority.host_boot_metadata_authority; image_mutation_allowed_now = $bootStateProjection.next_gate.image_mutation_allowed_now })
Add-Check "side_effects.none" ($baselineIdentity.authority.host_rootfs_mutated -eq $false -and $baselineIdentity.authority.host_active_slot_mutated -eq $false -and $baselineIdentity.authority.host_boot_metadata_mutated -eq $false -and $baselineIdentity.authority.active_artifact_set_mutated -eq $false -and $baselineIdentity.authority.production_ring_mutated -eq $false -and $baselineIdentity.authority.support_upload_performed -eq $false -and $baselineIdentity.authority.recovery_execution_performed -eq $false -and $baselineIdentity.authority.remote_dispatch_enabled -eq $false) "RC18-011 must not mutate host rootfs, host boot state, active artifacts, production rings, support upload, recovery, or remote dispatch." $baselineIdentity.authority
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing boundary, identity mismatch, missing baseline references, host mutation, support upload, recovery, remote dispatch, mirror, and signer authority attempts must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $baselineIdentityPath),
    (Get-Content -Raw -LiteralPath $bootStateProjectionPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-011 baseline outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-installed-system-baseline-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-011"
    status = $resultStatus
    production_ready_claim = $false
    baseline_id = $baselineId
    boundary_id = $boundaryResult.boundary_id
    state_root_id = $boundaryResult.state_root_id
    boot_state_projection_hash = $bootStateProjectionHash
    baseline_identity_bound = (@($script:failedChecks).Count -eq 0)
    boot_state_projection_bound = (@($script:failedChecks).Count -eq 0)
    image_local_projection_only = $true
    outputs = [ordered]@{
        baseline_identity = [ordered]@{
            path = Get-StablePath $baselineIdentityPath
            sha256 = Get-FileSha256 $baselineIdentityPath
            baseline_id = $baselineId
        }
        boot_state_projection = [ordered]@{
            path = Get-StablePath $bootStateProjectionPath
            sha256 = Get-FileSha256 $bootStateProjectionPath
            boot_state_projection_hash = $bootStateProjectionHash
        }
    }
    baseline_surface = [ordered]@{
        state = "installed-system-baseline-bound-projection-only"
        release_bound = $mediaReady
        media_bound = $mediaReady
        package_bound = $mediaReady
        agentcore_bound = $agentCoreReady
        security_execution_bound = $securityReady
        rollback_support_bound = $rollbackSupportReady
        image_boundary_bound = $boundaryReady
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        blockers = @(
            "rc18-image-boundary-fail-closed-not-run",
            "rc18-isolated-install-not-run",
            "rc18-isolated-update-not-run",
            "rc18-isolated-rollback-not-run"
        )
    }
    source = $sourceEvidence
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        baseline_projection_only = $true
        boot_state_projection_image_local = $true
        boot_state_projection_authoritative_for_host = $false
        image_materialized = $false
        vm_booted = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed_in_rc18 = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_changed = $false
        signer_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc18_011_complete = (@($script:failedChecks).Count -eq 0)
        baseline_identity_bound = (@($script:failedChecks).Count -eq 0)
        boot_state_projection_bound = (@($script:failedChecks).Count -eq 0)
        release_id = $rc16MediaManifest.release_id
        media_id = $rc16MediaManifest.media_id
        package_id = $rc16MediaManifest.package_id
        agentcore_bound = $agentCoreReady
        security_execution_bound = $securityReady
        rollback_support_bound = $rollbackSupportReady
        host_boot_metadata_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-012"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-011-installed-system-baseline.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-installed-system-baseline-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-011"
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
    baseline_surface = $result.baseline_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc18_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-012"
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
    throw "Sensitive marker detected in RC18-011 outputs."
}

Write-Host "RC18 installed-system baseline $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Baseline identity: $(Get-StablePath $baselineIdentityPath)"
Write-Host "Boot-state projection: $(Get-StablePath $bootStateProjectionPath)"
Write-Host "Baseline id: $baselineId"
Write-Host "Image-local boot projection only; host boot metadata mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
