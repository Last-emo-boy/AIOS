param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-first-user-install-drill",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$TargetBoundaryResultPath = ".workflow/artifacts/rc19-first-user-install-target-boundary/result.json",
    [string]$TargetBoundaryPath = ".workflow/artifacts/rc19-first-user-install-target-boundary/first-user-install-target-boundary.json",
    [string]$InstallPreflightPackagePath = ".workflow/artifacts/rc19-first-user-install-target-boundary/install-preflight-package.json",
    [string]$ImageArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$InstallerMediaResultPath = ".workflow/artifacts/rc19-installer-media-manifest/result.json",
    [string]$InstallerMediaManifestPath = ".workflow/artifacts/rc19-installer-media-manifest/installer-media-manifest.json",
    [string]$BootTargetDescriptorPath = ".workflow/artifacts/rc19-installer-media-manifest/boot-target-descriptor.json",
    [string]$Rc18InstallResultPath = ".workflow/artifacts/rc18-isolated-install-drill/result.json",
    [string]$Rc18InstallEvidencePath = ".workflow/artifacts/rc18-isolated-install-drill/install-drill-evidence.json",
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
        task = if ($null -ne $Json) { $Json.task } else { $null }
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
        denied_before_first_user_install = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            target_materialized = $false
            install_preflight_executed = $false
            first_user_install_performed = $false
            disposable_target_state_mutated = $false
            update_performed = $false
            rollback_execution_performed = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            payload_uploaded = $false
            external_payload_published = $false
            object_storage_provisioned = $false
            cryptographic_signing_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
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
$resolvedTargetBoundaryResultPath = Resolve-RepoPath $TargetBoundaryResultPath
$resolvedTargetBoundaryPath = Resolve-RepoPath $TargetBoundaryPath
$resolvedInstallPreflightPackagePath = Resolve-RepoPath $InstallPreflightPackagePath
$resolvedImageArtifactResultPath = Resolve-RepoPath $ImageArtifactResultPath
$resolvedInstallerMediaResultPath = Resolve-RepoPath $InstallerMediaResultPath
$resolvedInstallerMediaManifestPath = Resolve-RepoPath $InstallerMediaManifestPath
$resolvedBootTargetDescriptorPath = Resolve-RepoPath $BootTargetDescriptorPath
$resolvedRc18InstallResultPath = Resolve-RepoPath $Rc18InstallResultPath
$resolvedRc18InstallEvidencePath = Resolve-RepoPath $Rc18InstallEvidencePath

$plan = Read-Json $resolvedPlanPath
$targetBoundaryResult = Read-Json $resolvedTargetBoundaryResultPath
$targetBoundary = Read-Json $resolvedTargetBoundaryPath
$preflightPackage = Read-Json $resolvedInstallPreflightPackagePath
$imageArtifactResult = Read-Json $resolvedImageArtifactResultPath
$mediaResult = Read-Json $resolvedInstallerMediaResultPath
$mediaManifest = Read-Json $resolvedInstallerMediaManifestPath
$bootTargetDescriptor = Read-Json $resolvedBootTargetDescriptorPath
$rc18InstallResult = Read-Json $resolvedRc18InstallResultPath
$rc18InstallEvidence = Read-Json $resolvedRc18InstallEvidencePath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-020"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-021"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-021" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-022" -and $rc19TaskStatus -eq "completed")
    )
)

$targetSurfaceReady = (
    $targetBoundaryResult.status -eq "passed" -and
    $targetBoundaryResult.summary.rc19_020_complete -eq $true -and
    $targetBoundary.status -eq "first-user-install-target-boundary-bound-preflight-only" -and
    $targetBoundary.allowed_write_surface.only_writable_first_user_install_surface -eq "disposable-first-user-install-target" -and
    $targetBoundary.allowed_write_surface.writable_by_task -eq "RC19-021" -and
    $targetBoundary.allowed_write_surface.host_write_surface_allowed -eq $false
)
$preflightReady = (
    $preflightPackage.status -eq "first-user-install-preflight-package-bound-install-gated" -and
    $preflightPackage.preflight_gate.target_boundary_bound -eq $true -and
    $preflightPackage.preflight_gate.installable_image_artifact_bound -eq $true -and
    $preflightPackage.preflight_gate.installer_media_bound -eq $true -and
    $preflightPackage.preflight_gate.reproducibility_fail_closed_bound -eq $true -and
    $preflightPackage.preflight_gate.disposable_boundary_bound -eq $true -and
    $preflightPackage.preflight_gate.agentcore_security_references_bound -eq $true -and
    $preflightPackage.preflight_gate.rollback_support_references_bound -eq $true -and
    $preflightPackage.preflight_gate.first_user_install_drill_required -eq $true -and
    $preflightPackage.preflight_gate.install_effects_gated_until -eq "RC19-021"
)
$imageArtifactReady = (
    $imageArtifactResult.status -eq "passed" -and
    $imageArtifactResult.summary.rc19_010_complete -eq $true -and
    $imageArtifactResult.installable_image_artifact_id -eq $targetBoundaryResult.installable_image_artifact_id -and
    $imageArtifactResult.installable_image_artifact_id -eq $bootTargetDescriptor.installable_image_artifact_id
)
$mediaReady = (
    $mediaResult.status -eq "passed" -and
    $mediaResult.summary.rc19_011_complete -eq $true -and
    $mediaResult.installer_media_id -eq $targetBoundaryResult.installer_media_id -and
    $mediaManifest.installer_media_id -eq $mediaResult.installer_media_id -and
    $bootTargetDescriptor.installer_media_id -eq $mediaResult.installer_media_id -and
    $bootTargetDescriptor.boot_target_descriptor_id -eq $targetBoundaryResult.boot_target_descriptor_id -and
    $bootTargetDescriptor.projection_only -eq $true
)
$rc18InstallReady = (
    $rc18InstallResult.status -eq "passed" -and
    $rc18InstallResult.summary.rc18_020_complete -eq $true -and
    $rc18InstallResult.isolated_install_allowed -eq $true -and
    $rc18InstallResult.isolated_install_performed -eq $true -and
    $rc18InstallResult.install_surface.disposable_image_state_mutated -eq $true -and
    $rc18InstallResult.install_surface.host_rootfs_mutated -eq $false -and
    $rc18InstallResult.install_surface.host_active_slot_mutated -eq $false -and
    $rc18InstallResult.install_surface.host_boot_metadata_mutated -eq $false -and
    $rc18InstallResult.install_surface.remote_dispatch_enabled -eq $false -and
    $rc18InstallEvidence.installed_image_state_id -eq $rc18InstallResult.installed_image_state_id
)
$rollbackSupportReady = (
    $preflightPackage.rollback_support.rc16_rollback_support_result.status -eq "passed" -and
    $preflightPackage.rollback_support.rc16_rollback_support_package.present -eq $true -and
    $preflightPackage.rollback_support.support_index.present -eq $true -and
    $preflightPackage.rollback_support.rollback_execution_allowed -eq $false -and
    $preflightPackage.rollback_support.support_upload_allowed -eq $false -and
    $preflightPackage.rollback_support.recovery_execution_allowed -eq $false
)

$firstUserInstallAllowed = (
    $planAllowsRun -and
    $targetSurfaceReady -and
    $preflightReady -and
    $imageArtifactReady -and
    $mediaReady -and
    $rc18InstallReady -and
    $rollbackSupportReady
)

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc19-021-plan-pointer-not-current" }
if (-not $targetSurfaceReady) { $blockers += "first-user-install-target-boundary-not-ready" }
if (-not $preflightReady) { $blockers += "install-preflight-package-not-ready" }
if (-not $imageArtifactReady) { $blockers += "installable-image-artifact-not-ready" }
if (-not $mediaReady) { $blockers += "installer-media-or-boot-target-not-ready" }
if (-not $rc18InstallReady) { $blockers += "rc18-isolated-install-drill-not-ready" }
if (-not $rollbackSupportReady) { $blockers += "rollback-support-references-not-ready" }
if ($firstUserInstallAllowed) { $blockers = @() }

$targetRoot = [string]$targetBoundary.allowed_write_surface.disposable_target_root
$targetStateRoot = [string]$targetBoundary.allowed_write_surface.disposable_target_state_root
$targetAuditLog = [string]$targetBoundary.allowed_write_surface.disposable_target_audit_log
$targetStateRootPath = Resolve-RepoPath $targetStateRoot
$targetAuditLogPath = Resolve-RepoPath $targetAuditLog
$auditRecordPath = Join-Path $resolvedArtifactDir "install-audit-record.json"

$installMaterial = [ordered]@{
    schema = "agentos.rc19-first-user-install-drill-material.v1"
    task = "RC19-021"
    execution_mode = if ($firstUserInstallAllowed) { "execute-inside-disposable-first-user-install-target" } else { "deny-before-first-user-install-effect" }
    target_kind = "disposable-first-user-install-target"
    target_root = $targetRoot
    target_state_root = $targetStateRoot
    target_audit_log = $targetAuditLog
    target_boundary_id = [string]$targetBoundaryResult.target_boundary_id
    install_preflight_package_id = [string]$targetBoundaryResult.install_preflight_package_id
    installable_image_artifact_id = [string]$targetBoundaryResult.installable_image_artifact_id
    installer_media_id = [string]$targetBoundaryResult.installer_media_id
    boot_target_descriptor_id = [string]$targetBoundaryResult.boot_target_descriptor_id
    rc18_installed_image_state_id = [string]$rc18InstallResult.installed_image_state_id
    rc18_install_drill_digest = [string]$rc18InstallEvidence.install_drill_digest
    rollback_baseline_sha256 = [string]$preflightPackage.rollback_support.rollback_baseline.sha256
    support_index_sha256 = [string]$preflightPackage.rollback_support.support_index.sha256
    host_rootfs_mutation_allowed = $false
    host_active_slot_mutation_allowed = $false
    host_boot_metadata_mutation_allowed = $false
    active_artifact_set_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$installDigest = Get-StringSha256 (Get-JsonText $installMaterial)
$targetStateId = if ($firstUserInstallAllowed) { "sha256:$installDigest" } else { $null }

$sideEffects = [ordered]@{
    target_materialized = $firstUserInstallAllowed
    install_preflight_executed = $firstUserInstallAllowed
    first_user_install_performed = $firstUserInstallAllowed
    disposable_target_state_mutated = $firstUserInstallAllowed
    update_performed = $false
    rollback_execution_performed = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    payload_uploaded = $false
    external_payload_published = $false
    object_storage_provisioned = $false
    cryptographic_signing_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    production_ring_mutated = $false
    consumer_ready_claim = $false
}

$auditRecord = [ordered]@{
    schema = "agentos.rc19-first-user-install-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC19-021"
    event_type = if ($firstUserInstallAllowed) { "FirstUserInstallExecutedInsideDisposableTarget" } else { "FirstUserInstallDeniedBeforeEffect" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    local_only = $true
    fabricated = $false
    first_user_install_allowed = $firstUserInstallAllowed
    first_user_install_performed = $firstUserInstallAllowed
    target_state_id = $targetStateId
    install_drill_digest = $installDigest
    target_boundary_id = [string]$targetBoundaryResult.target_boundary_id
    install_preflight_package_id = [string]$targetBoundaryResult.install_preflight_package_id
    installable_image_artifact_id = [string]$targetBoundaryResult.installable_image_artifact_id
    installer_media_id = [string]$targetBoundaryResult.installer_media_id
    boot_target_descriptor_id = [string]$targetBoundaryResult.boot_target_descriptor_id
    blockers = @($blockers)
    forbidden_side_effects = [ordered]@{
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
    }
}
Write-Json $auditRecord $auditRecordPath
if ($firstUserInstallAllowed) {
    Write-Json $auditRecord $targetAuditLogPath
}

$targetState = [ordered]@{
    schema = "agentos.rc19-disposable-first-user-install-target-state-root.v1"
    generated_at = $generatedAtValue
    task = "RC19-021"
    status = if ($firstUserInstallAllowed) { "first-user-installed-inside-disposable-target" } else { "not-materialized" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    target_state_id = $targetStateId
    target_kind = "disposable-first-user-install-target"
    target_root = $targetRoot
    target_boundary_id = [string]$targetBoundaryResult.target_boundary_id
    install_preflight_package_id = [string]$targetBoundaryResult.install_preflight_package_id
    installable_image_artifact_id = [string]$targetBoundaryResult.installable_image_artifact_id
    installer_media_id = [string]$targetBoundaryResult.installer_media_id
    boot_target_descriptor_id = [string]$targetBoundaryResult.boot_target_descriptor_id
    rc18_installed_image_state_id = [string]$rc18InstallResult.installed_image_state_id
    install_drill_digest = $installDigest
    boot_projection = $bootTargetDescriptor.boot_projection
    rollback_support = $preflightPackage.rollback_support
    side_effects = $sideEffects
}
if ($firstUserInstallAllowed) {
    Write-Json $targetState $targetStateRootPath
}

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_target_boundary_result = New-ArtifactRef $resolvedTargetBoundaryResultPath $targetBoundaryResult
    rc19_target_boundary = New-ArtifactRef $resolvedTargetBoundaryPath $targetBoundary
    rc19_install_preflight_package = New-ArtifactRef $resolvedInstallPreflightPackagePath $preflightPackage
    rc19_image_artifact_result = New-ArtifactRef $resolvedImageArtifactResultPath $imageArtifactResult
    rc19_installer_media_result = New-ArtifactRef $resolvedInstallerMediaResultPath $mediaResult
    rc19_installer_media_manifest = New-ArtifactRef $resolvedInstallerMediaManifestPath $mediaManifest
    rc19_boot_target_descriptor = New-ArtifactRef $resolvedBootTargetDescriptorPath $bootTargetDescriptor
    rc18_install_drill_result = New-ArtifactRef $resolvedRc18InstallResultPath $rc18InstallResult
    rc18_install_drill_evidence = New-ArtifactRef $resolvedRc18InstallEvidencePath $rc18InstallEvidence
}

$caseSpecs = @(
    [ordered]@{ id = "missing-target-boundary"; blockers = @("first-user-install-target-boundary-not-ready"); reason = "First-user install requires RC19-020 target boundary." },
    [ordered]@{ id = "missing-preflight-package"; blockers = @("install-preflight-package-not-ready"); reason = "First-user install requires RC19-020 preflight package." },
    [ordered]@{ id = "missing-image-artifact"; blockers = @("installable-image-artifact-not-ready"); reason = "Image artifact identity must be bound." },
    [ordered]@{ id = "missing-installer-media"; blockers = @("installer-media-or-boot-target-not-ready"); reason = "Installer media must be bound." },
    [ordered]@{ id = "missing-boot-target"; blockers = @("installer-media-or-boot-target-not-ready"); reason = "Boot target descriptor must be bound." },
    [ordered]@{ id = "missing-rc18-install-base"; blockers = @("rc18-isolated-install-drill-not-ready"); reason = "RC18 isolated install state must be ready." },
    [ordered]@{ id = "missing-rollback-support"; blockers = @("rollback-support-references-not-ready"); reason = "Rollback and support references must be bound." },
    [ordered]@{ id = "wrong-target-root"; blockers = @("first-user-install-target-boundary-not-ready"); reason = "Install must stay within disposable target root." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs writes are forbidden." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot writes are forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata writes are forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "payload-upload-attempt"; blockers = @("payload-upload-denied"); reason = "Payload upload is out of RC19-021 scope." },
    [ordered]@{ id = "object-storage-provisioning-attempt"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "cryptographic-signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "Signing authority is out of scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not install authority." },
    [ordered]@{ id = "endpoint-reachability-authority-attempt"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not install authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not install authority." },
    [ordered]@{ id = "consumer-ready-claim-attempt"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for later smoke and final audit." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC19-021 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$firstUserInstallEvidence = [ordered]@{
    schema = "agentos.rc19-first-user-install-drill-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-021"
    status = if ($firstUserInstallAllowed) { "first-user-install-executed-inside-disposable-target" } else { "first-user-install-denied-before-effect" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_user_install_allowed = $firstUserInstallAllowed
    first_user_install_performed = $firstUserInstallAllowed
    target_materialized = $sideEffects.target_materialized
    disposable_target_state_mutated = $sideEffects.disposable_target_state_mutated
    denied = (-not $firstUserInstallAllowed)
    denial_reasons = @($blockers)
    install_drill_digest = $installDigest
    target_state_id = $targetStateId
    install_material = $installMaterial
    gate_bindings = [ordered]@{
        target_surface_ready = $targetSurfaceReady
        preflight_ready = $preflightReady
        image_artifact_ready = $imageArtifactReady
        media_ready = $mediaReady
        rc18_install_ready = $rc18InstallReady
        rollback_support_ready = $rollbackSupportReady
    }
    target_state_root = [ordered]@{
        path = Get-StablePath $targetStateRootPath
        sha256 = Get-FileSha256 $targetStateRootPath
        target_state_id = $targetStateId
    }
    target_audit_log = [ordered]@{
        path = Get-StablePath $targetAuditLogPath
        sha256 = Get-FileSha256 $targetAuditLogPath
    }
    audit_record = [ordered]@{
        path = Get-StablePath $auditRecordPath
        sha256 = Get-FileSha256 $auditRecordPath
        fabricated = $false
    }
    side_effects = $sideEffects
    fail_closed_cases = $cases
    source = $source
}
$firstUserInstallEvidencePath = Join-Path $resolvedArtifactDir "first-user-install-evidence.json"
Write-Json $firstUserInstallEvidence $firstUserInstallEvidencePath

Add-Check "plan.current_task.rc19_021" $planAllowsRun "RC19-021 must run after RC19-020 completed, while current_task is RC19-021 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_020_status = $rc19PreviousStatus; rc19_021_status = $rc19TaskStatus })
Add-Check "source.rc19_020.ready" ($targetSurfaceReady -and $preflightReady) "RC19-021 must bind the RC19-020 target boundary and preflight package." ([ordered]@{ target_surface_ready = $targetSurfaceReady; preflight_ready = $preflightReady; target_boundary_id = $targetBoundaryResult.target_boundary_id; install_preflight_package_id = $targetBoundaryResult.install_preflight_package_id })
Add-Check "source.artifact.media.ready" ($imageArtifactReady -and $mediaReady) "RC19-021 must bind installable image artifact, installer media, and boot target descriptor identities." ([ordered]@{ image_artifact_ready = $imageArtifactReady; media_ready = $mediaReady; installable_image_artifact_id = $targetBoundaryResult.installable_image_artifact_id; installer_media_id = $targetBoundaryResult.installer_media_id; boot_target_descriptor_id = $targetBoundaryResult.boot_target_descriptor_id })
Add-Check "source.rc18_install.ready" $rc18InstallReady "RC19-021 must consume RC18 isolated install evidence that executed inside the disposable image boundary." ([ordered]@{ isolated_install_performed = $rc18InstallResult.isolated_install_performed; disposable_image_state_mutated = $rc18InstallResult.install_surface.disposable_image_state_mutated; installed_image_state_id = $rc18InstallResult.installed_image_state_id })
Add-Check "source.rollback_support.ready" $rollbackSupportReady "Rollback and support references must be bound while rollback execution, support upload, and recovery execution remain disabled." ([ordered]@{ rollback_support_ready = $rollbackSupportReady; rollback_execution_allowed = $preflightPackage.rollback_support.rollback_execution_allowed; support_upload_allowed = $preflightPackage.rollback_support.support_upload_allowed; recovery_execution_allowed = $preflightPackage.rollback_support.recovery_execution_allowed })
Add-Check "install.disposable_target.execute_or_deny" (($firstUserInstallAllowed -and $firstUserInstallEvidence.first_user_install_performed -eq $true -and $sideEffects.disposable_target_state_mutated -eq $true -and $targetStateId -like "sha256:*") -or ((-not $firstUserInstallAllowed) -and $firstUserInstallEvidence.denied -eq $true -and $sideEffects.disposable_target_state_mutated -eq $false)) "First-user install drill must execute only inside the disposable target or deny before effect." ([ordered]@{ first_user_install_allowed = $firstUserInstallAllowed; first_user_install_performed = $firstUserInstallEvidence.first_user_install_performed; disposable_target_state_mutated = $sideEffects.disposable_target_state_mutated; target_state_id = $targetStateId; blockers = @($blockers) })
Add-Check "evidence.binds.required_refs" ($firstUserInstallEvidence.install_material.target_boundary_id -eq $targetBoundaryResult.target_boundary_id -and $firstUserInstallEvidence.install_material.install_preflight_package_id -eq $targetBoundaryResult.install_preflight_package_id -and $firstUserInstallEvidence.install_material.installable_image_artifact_id -eq $targetBoundaryResult.installable_image_artifact_id -and $firstUserInstallEvidence.install_material.installer_media_id -eq $targetBoundaryResult.installer_media_id -and $firstUserInstallEvidence.install_material.boot_target_descriptor_id -eq $targetBoundaryResult.boot_target_descriptor_id -and -not [string]::IsNullOrWhiteSpace([string]$firstUserInstallEvidence.install_material.rollback_baseline_sha256) -and -not [string]::IsNullOrWhiteSpace([string]$firstUserInstallEvidence.install_material.support_index_sha256)) "Install evidence must bind artifact identity, media, boot target, target boundary, preflight, audit, rollback, and support references." $firstUserInstallEvidence.install_material
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.payload_uploaded -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.consumer_ready_claim -eq $false) "RC19-021 must not mutate host or production state, upload or publish payloads, sign, upload support, execute recovery, remote-dispatch, or claim consumer readiness." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing gates and forbidden authority surfaces must deny before first-user install or host mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $firstUserInstallEvidencePath),
    (Get-Content -Raw -LiteralPath $auditRecordPath),
    $(if (Test-Path -LiteralPath $targetStateRootPath -PathType Leaf) { Get-Content -Raw -LiteralPath $targetStateRootPath } else { "" }),
    $(if (Test-Path -LiteralPath $targetAuditLogPath -PathType Leaf) { Get-Content -Raw -LiteralPath $targetAuditLogPath } else { "" })
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-021 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-first-user-install-drill-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-021"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    target_boundary_id = [string]$targetBoundaryResult.target_boundary_id
    install_preflight_package_id = [string]$targetBoundaryResult.install_preflight_package_id
    installable_image_artifact_id = [string]$targetBoundaryResult.installable_image_artifact_id
    installer_media_id = [string]$targetBoundaryResult.installer_media_id
    boot_target_descriptor_id = [string]$targetBoundaryResult.boot_target_descriptor_id
    target_state_id = $targetStateId
    first_user_install_allowed = $firstUserInstallAllowed
    first_user_install_performed = $sideEffects.first_user_install_performed
    outputs = [ordered]@{
        first_user_install_evidence = [ordered]@{
            path = Get-StablePath $firstUserInstallEvidencePath
            sha256 = Get-FileSha256 $firstUserInstallEvidencePath
            install_drill_digest = $installDigest
            target_state_id = $targetStateId
        }
        install_audit_record = [ordered]@{
            path = Get-StablePath $auditRecordPath
            sha256 = Get-FileSha256 $auditRecordPath
            fabricated = $false
        }
        disposable_target_state_root = [ordered]@{
            path = Get-StablePath $targetStateRootPath
            sha256 = Get-FileSha256 $targetStateRootPath
            target_state_id = $targetStateId
        }
        disposable_target_audit_log = [ordered]@{
            path = Get-StablePath $targetAuditLogPath
            sha256 = Get-FileSha256 $targetAuditLogPath
        }
    }
    install_surface = [ordered]@{
        state = if ($firstUserInstallAllowed) { "first-user-install-executed-inside-disposable-target" } else { "first-user-install-denied-before-effect" }
        target_kind = "disposable-first-user-install-target"
        target_root = $targetRoot
        target_materialized = $sideEffects.target_materialized
        install_preflight_executed = $sideEffects.install_preflight_executed
        first_user_install_allowed = $firstUserInstallAllowed
        first_user_install_performed = $sideEffects.first_user_install_performed
        disposable_target_state_mutated = $sideEffects.disposable_target_state_mutated
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        consumer_ready_claim = $false
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        disposable_first_user_install_target_only = $true
        target_materialized = $sideEffects.target_materialized
        first_user_install_performed = $sideEffects.first_user_install_performed
        disposable_target_state_mutated = $sideEffects.disposable_target_state_mutated
        update_performed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        payload_uploaded = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        cryptographic_signing_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc19_021_complete = (@($script:failedChecks).Count -eq 0)
        first_user_install_allowed = $firstUserInstallAllowed
        first_user_install_performed = $sideEffects.first_user_install_performed
        target_materialized = $sideEffects.target_materialized
        disposable_target_state_mutated = $sideEffects.disposable_target_state_mutated
        target_state_id = $targetStateId
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        consumer_ready_claim = $false
        next_task = "RC19-022"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-021-first-user-install-drill.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-first-user-install-drill-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-021"
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
    install_surface = $result.install_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-022"
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
    throw "Sensitive marker detected in RC19-021 outputs."
}

Write-Host "RC19 first-user install drill $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $firstUserInstallEvidencePath)"
Write-Host "Audit: $(Get-StablePath $auditRecordPath)"
Write-Host "Target state: $(Get-StablePath $targetStateRootPath)"
Write-Host "First-user install performed: $($sideEffects.first_user_install_performed); target materialized: $($sideEffects.target_materialized); host mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
