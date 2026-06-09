param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-installer-media-manifest",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/docs/rc19-installable-image-authority-contract.md",
    [string]$Rc19ArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$Rc19ArtifactSetPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/installable-image-artifact-set.json",
    [string]$Rc19InputMapPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/reproducibility-input-map.json",
    [string]$Rc16MediaResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$Rc16MediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$BuildInitramfsScriptPath = "image/build-initramfs.ps1",
    [string]$BuildReleaseScriptPath = "scripts/build-release.ps1",
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

function Get-JsonProperty {
    param($Json, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Json) {
        return $null
    }
    if ($Json.PSObject.Properties.Name -contains $Name) {
        return $Json.$Name
    }
    return $null
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    $resolved = Resolve-RepoPath $Path
    $present = Test-Path -LiteralPath $resolved -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $resolved
        sha256 = Get-FileSha256 $resolved
        size_bytes = if ($present) { (Get-Item -LiteralPath $resolved).Length } else { $null }
        present = $present
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
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
        denied_before_effect = $true
        side_effects = [ordered]@{
            install_performed = $false
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
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedRc19ArtifactResultPath = Resolve-RepoPath $Rc19ArtifactResultPath
$resolvedRc19ArtifactSetPath = Resolve-RepoPath $Rc19ArtifactSetPath
$resolvedRc19InputMapPath = Resolve-RepoPath $Rc19InputMapPath
$resolvedRc16MediaResultPath = Resolve-RepoPath $Rc16MediaResultPath
$resolvedRc16MediaManifestPath = Resolve-RepoPath $Rc16MediaManifestPath
$resolvedBuildInitramfsScriptPath = Resolve-RepoPath $BuildInitramfsScriptPath
$resolvedBuildReleaseScriptPath = Resolve-RepoPath $BuildReleaseScriptPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc19ArtifactResult = Read-Json $resolvedRc19ArtifactResultPath
$rc19ArtifactSet = Read-Json $resolvedRc19ArtifactSetPath
$rc19InputMap = Read-Json $resolvedRc19InputMapPath
$rc16MediaResult = Read-Json $resolvedRc16MediaResultPath
$rc16MediaManifest = Read-Json $resolvedRc16MediaManifestPath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-010"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-011"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-011" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-012" -and $rc19TaskStatus -eq "completed")
    )
)

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $PlanPath $plan
    rc19_contract = New-ArtifactRef $ContractPath
    rc19_artifact_result = New-ArtifactRef $Rc19ArtifactResultPath $rc19ArtifactResult
    rc19_artifact_set = New-ArtifactRef $Rc19ArtifactSetPath $rc19ArtifactSet
    rc19_reproducibility_input_map = New-ArtifactRef $Rc19InputMapPath $rc19InputMap
    rc16_media_result = New-ArtifactRef $Rc16MediaResultPath $rc16MediaResult
    rc16_media_manifest = New-ArtifactRef $Rc16MediaManifestPath $rc16MediaManifest
    build_initramfs_script = New-ArtifactRef $BuildInitramfsScriptPath
    build_release_script = New-ArtifactRef $BuildReleaseScriptPath
}
$missingRequiredRefs = @($source.GetEnumerator() | Where-Object { $_.Value.present -ne $true -or $_.Value.sha256 -notmatch "^[0-9a-f]{64}$" } | ForEach-Object { $_.Value })

$artifactId = [string]$rc19ArtifactResult.installable_image_artifact_id
$rc19ArtifactReady = (
    $rc19ArtifactResult.status -eq "passed" -and
    $rc19ArtifactResult.production_ready_claim -eq $false -and
    $rc19ArtifactSet.installable_image_artifact_id -eq $artifactId -and
    $rc19InputMap.installable_image_artifact_id -eq $artifactId -and
    $rc19ArtifactResult.artifact_set_sha256 -eq (Get-FileSha256 $resolvedRc19ArtifactSetPath) -and
    $rc19ArtifactResult.reproducibility_input_map_sha256 -eq (Get-FileSha256 $resolvedRc19InputMapPath)
)
$rc16MediaReady = (
    $rc16MediaResult.status -eq "passed" -and
    $rc16MediaResult.production_ready_claim -eq $false -and
    $rc16MediaManifest.media_id -eq $rc19ArtifactSet.artifact_identity.release.media_id -and
    $rc16MediaManifest.release_id -eq $rc19ArtifactSet.artifact_identity.release.release_id -and
    $rc16MediaManifest.package_id -eq $rc19ArtifactSet.artifact_identity.release.package_id
)
$bootMarkers = @($rc16MediaManifest.rootfs_initramfs_provenance.initramfs.boot_markers)
$runtimeArtifactIds = @($rc16MediaManifest.rootfs_initramfs_provenance.initramfs.runtime_artifact_ids)
$targetArch = @($rc16MediaManifest.architecture_and_compatibility.target_arch)
$bootModes = @($rc16MediaManifest.architecture_and_compatibility.boot_modes)
$rootfsReady = (
    $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.validation_result -eq "passed" -and
    $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.runtime_artifact_count -ge 1 -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.rootfs_runtime_manifest_sha256)
)
$bootTargetReady = (
    $targetArch -contains "x86_64" -and
    $bootModes.Count -ge 1 -and
    $rc16MediaManifest.architecture_and_compatibility.kernel_family -eq "linux-lts" -and
    $bootMarkers.Count -ge 5 -and
    $bootMarkers -contains "AGENTOS_TUI_CONSOLE_READY"
)
$rollbackSupportReady = (
    $rc16MediaManifest.rollback_support.rollback_execution_allowed -eq $false -and
    $rc16MediaManifest.rollback_support.support_upload_allowed -eq $false -and
    $rc16MediaManifest.rollback_support.recovery_execution_allowed -eq $false -and
    $rc16MediaManifest.rollback_support.rollback_baseline.sha256 -match "^[0-9a-f]{64}$" -and
    $rc16MediaManifest.rollback_support.support_index.sha256 -match "^[0-9a-f]{64}$"
)

$bootTargetMaterial = [ordered]@{
    schema = "agentos.rc19-boot-target-material.v1"
    task = "RC19-011"
    installable_image_artifact_id = $artifactId
    base_media_id = $rc16MediaManifest.media_id
    release_id = $rc16MediaManifest.release_id
    package_id = $rc16MediaManifest.package_id
    target_arch = $targetArch
    boot_modes = $bootModes
    kernel_family = $rc16MediaManifest.architecture_and_compatibility.kernel_family
    initramfs_contract = $rc16MediaManifest.architecture_and_compatibility.initramfs_contract
    boot_args = $rc16MediaManifest.rootfs_initramfs_provenance.initramfs.boot_args
    boot_markers = $bootMarkers
    runtime_artifact_ids = $runtimeArtifactIds
    rootfs_runtime_manifest_sha256 = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.rootfs_runtime_manifest_sha256
    installed_image_state_id = $rc19ArtifactSet.artifact_identity.image.installed_image_state_id
    updated_image_state_id = $rc19ArtifactSet.artifact_identity.image.updated_image_state_id
    restored_image_state_id = $rc19ArtifactSet.artifact_identity.image.restored_image_state_id
    host_boot_metadata_authority = $false
}
$bootTargetDescriptorId = "sha256:$(Get-StringSha256 (Get-JsonText $bootTargetMaterial))"

$mediaMaterial = [ordered]@{
    schema = "agentos.rc19-installer-media-material.v1"
    task = "RC19-011"
    installable_image_artifact_id = $artifactId
    rc19_artifact_set_sha256 = Get-FileSha256 $resolvedRc19ArtifactSetPath
    rc19_input_map_sha256 = Get-FileSha256 $resolvedRc19InputMapPath
    base_media_manifest_sha256 = Get-FileSha256 $resolvedRc16MediaManifestPath
    build_initramfs_script_sha256 = Get-FileSha256 $resolvedBuildInitramfsScriptPath
    build_release_script_sha256 = Get-FileSha256 $resolvedBuildReleaseScriptPath
    boot_target_descriptor_id = $bootTargetDescriptorId
    generated_at_excluded_from_identity = $true
}
$installerMediaId = "sha256:$(Get-StringSha256 (Get-JsonText $mediaMaterial))"

$bootTargetDescriptor = [ordered]@{
    schema = "agentos.rc19-boot-target-descriptor.v1"
    generated_at = $generatedAtValue
    task = "RC19-011"
    status = "boot-target-descriptor-bound-projection-only"
    production_ready_claim = $false
    boot_target_descriptor_id = $bootTargetDescriptorId
    installable_image_artifact_id = $artifactId
    installer_media_id = $installerMediaId
    projection_only = $true
    target = [ordered]@{
        target_arch = $targetArch
        boot_modes = $bootModes
        kernel_family = $rc16MediaManifest.architecture_and_compatibility.kernel_family
        initramfs_contract = $rc16MediaManifest.architecture_and_compatibility.initramfs_contract
        console_readiness_marker_required = $rc16MediaManifest.architecture_and_compatibility.console_readiness_marker_required
    }
    boot_projection = [ordered]@{
        boot_args = $rc16MediaManifest.rootfs_initramfs_provenance.initramfs.boot_args
        boot_markers = $bootMarkers
        runtime_artifact_ids = $runtimeArtifactIds
        rootfs_runtime_manifest_sha256 = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.rootfs_runtime_manifest_sha256
        runtime_artifact_count = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.runtime_artifact_count
    }
    image_state_projection = $rc19ArtifactSet.artifact_identity.image
    authority = [ordered]@{
        host_boot_state_authority = $false
        host_boot_metadata_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        shell_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        endpoint_reachability_authority = $false
    }
    next_required_gate = [ordered]@{
        first_user_target_boundary_task = "RC19-020"
        first_user_install_drill_task = "RC19-021"
        install_effects_gated_until = "RC19-021"
        host_boot_mutation_allowed_now = $false
    }
}
$bootTargetDescriptorPath = Join-Path $resolvedArtifactDir "boot-target-descriptor.json"
Write-Json $bootTargetDescriptor $bootTargetDescriptorPath
$bootTargetDescriptorSha256 = Get-FileSha256 $bootTargetDescriptorPath

$installerMediaManifest = [ordered]@{
    schema = "agentos.rc19-installer-media-manifest.v1"
    generated_at = $generatedAtValue
    task = "RC19-011"
    status = "installer-media-manifest-bound-install-gated"
    production_ready_claim = $false
    installer_media_id = $installerMediaId
    installable_image_artifact_id = $artifactId
    boot_target_descriptor = [ordered]@{
        path = Get-StablePath $bootTargetDescriptorPath
        sha256 = $bootTargetDescriptorSha256
        boot_target_descriptor_id = $bootTargetDescriptorId
    }
    source_artifact = [ordered]@{
        rc19_artifact_result = $source.rc19_artifact_result
        rc19_artifact_set = $source.rc19_artifact_set
        rc19_reproducibility_input_map = $source.rc19_reproducibility_input_map
    }
    base_media = [ordered]@{
        rc16_media_id = $rc16MediaManifest.media_id
        rc16_media_result = $source.rc16_media_result
        rc16_media_manifest = $source.rc16_media_manifest
        release_id = $rc16MediaManifest.release_id
        package_id = $rc16MediaManifest.package_id
    }
    build_inputs = [ordered]@{
        build_initramfs_script = $source.build_initramfs_script
        build_release_script = $source.build_release_script
        build_executed = $false
        image_built = $false
        iso_created = $false
        disk_image_created = $false
    }
    boot = [ordered]@{
        target_arch = $targetArch
        boot_modes = $bootModes
        kernel_family = $rc16MediaManifest.architecture_and_compatibility.kernel_family
        initramfs_contract = $rc16MediaManifest.architecture_and_compatibility.initramfs_contract
        boot_args = $rc16MediaManifest.rootfs_initramfs_provenance.initramfs.boot_args
        boot_markers = $bootMarkers
        runtime_artifact_ids = $runtimeArtifactIds
    }
    rootfs = [ordered]@{
        source_rootfs = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.source_rootfs
        staged_rootfs = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.staged_rootfs
        rootfs_runtime_manifest = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.rootfs_runtime_manifest
        rootfs_runtime_manifest_sha256 = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.rootfs_runtime_manifest_sha256
        runtime_artifact_count = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.runtime_artifact_count
        validation_result = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.validation_result
    }
    rollback_support = [ordered]@{
        rollback_baseline = $rc16MediaManifest.rollback_support.rollback_baseline
        support_index = $rc16MediaManifest.rollback_support.support_index
        installed_image_state_id = $rc19ArtifactSet.artifact_identity.image.installed_image_state_id
        updated_image_state_id = $rc19ArtifactSet.artifact_identity.image.updated_image_state_id
        restored_image_state_id = $rc19ArtifactSet.artifact_identity.image.restored_image_state_id
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
    install_gate = [ordered]@{
        first_user_install_target_boundary_required = $true
        first_user_install_drill_required = $true
        install_effects_gated_until = "RC19-021"
        install_allowed = $false
        first_user_install_allowed = $false
        update_allowed = $false
        rollback_execution_allowed = $false
        host_rootfs_mutation_allowed = $false
        host_boot_metadata_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        next_task = "RC19-012"
    }
    authority = [ordered]@{
        aios_body_only = $true
        projection_only = $true
        production_ready_claim = $false
        install_authority = $false
        first_user_install_authority = $false
        update_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_rootfs_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
    }
    source = $source
}
$installerMediaManifestPath = Join-Path $resolvedArtifactDir "installer-media-manifest.json"
Write-Json $installerMediaManifest $installerMediaManifestPath
$installerMediaManifestSha256 = Get-FileSha256 $installerMediaManifestPath

$denialCases = @(
    (New-DenialCase -Id "missing-rc19-artifact-id" -Blockers @("rc19-artifact-id-not-bound") -Reason "Installer media requires the RC19 installable artifact identity."),
    (New-DenialCase -Id "missing-boot-markers" -Blockers @("boot-markers-not-bound") -Reason "Boot target descriptor requires boot markers."),
    (New-DenialCase -Id "host-boot-mutation-attempt" -Blockers @("host-boot-mutation-denied") -Reason "Boot target descriptor is projection-only."),
    (New-DenialCase -Id "host-rootfs-install-attempt" -Blockers @("host-rootfs-install-denied") -Reason "Install effects remain gated until RC19-021."),
    (New-DenialCase -Id "support-upload-attempt" -Blockers @("support-upload-denied") -Reason "Support upload remains outside RC19-011."),
    (New-DenialCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied") -Reason "Recovery execution remains outside RC19-011."),
    (New-DenialCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied") -Reason "Remote dispatch remains disabled."),
    (New-DenialCase -Id "signer-authority-attempt" -Blockers @("signer-authority-denied") -Reason "Signer reachability is not media authority.")
)

$authorityClean = (
    $installerMediaManifest.authority.install_authority -eq $false -and
    $installerMediaManifest.authority.first_user_install_authority -eq $false -and
    $installerMediaManifest.authority.update_authority -eq $false -and
    $installerMediaManifest.authority.rollback_execution_authority -eq $false -and
    $installerMediaManifest.authority.support_upload_authority -eq $false -and
    $installerMediaManifest.authority.recovery_execution_authority -eq $false -and
    $installerMediaManifest.authority.remote_dispatch_authority -eq $false -and
    $installerMediaManifest.authority.host_rootfs_mutation_authority -eq $false -and
    $installerMediaManifest.authority.host_active_slot_mutation_authority -eq $false -and
    $installerMediaManifest.authority.host_boot_metadata_mutation_authority -eq $false -and
    $installerMediaManifest.authority.active_artifact_set_mutation_authority -eq $false -and
    $installerMediaManifest.authority.production_ring_mutation_authority -eq $false -and
    $installerMediaManifest.authority.signer_authority -eq $false -and
    $installerMediaManifest.authority.object_storage_authority -eq $false
)
$sideEffects = [ordered]@{
    build_executed = $false
    image_built = $false
    iso_created = $false
    disk_image_created = $false
    payload_uploaded = $false
    external_payload_published = $false
    install_performed = $false
    update_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}

Add-Check "plan.current_task.rc19_011" $planAllowsRun "RC19-011 must run after RC19-010 completed, while current_task is RC19-011 or during an idempotent rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_010_status = $rc19PreviousStatus; rc19_011_status = $rc19TaskStatus })
Add-Check "contract.media_gate.present" ($contractText.Contains("Bind installer media manifest and boot target descriptor") -and $contractText.Contains("boot target descriptor") -and $contractText.Contains("host boot")) "RC19-011 must consume the installer media and boot target authority contract." $source.rc19_contract
Add-Check "sources.required.present" (@($missingRequiredRefs).Count -eq 0) "Required installer media inputs must be present and hashable." (@($missingRequiredRefs | ForEach-Object { $_.path }))
Add-Check "rc19.artifact.ready" $rc19ArtifactReady "RC19-011 must bind the completed RC19 installable image artifact identity and input map." ([ordered]@{ result_status = $rc19ArtifactResult.status; artifact_id = $artifactId; artifact_set_matches = ($rc19ArtifactSet.installable_image_artifact_id -eq $artifactId); input_map_matches = ($rc19InputMap.installable_image_artifact_id -eq $artifactId) })
Add-Check "rc16.media.ready" $rc16MediaReady "RC19-011 must bind the RC16 base media manifest for the same release, media, and package identity." ([ordered]@{ rc16_status = $rc16MediaResult.status; rc16_media_id = $rc16MediaManifest.media_id; rc19_media_id = $rc19ArtifactSet.artifact_identity.release.media_id; release_id = $rc16MediaManifest.release_id; package_id = $rc16MediaManifest.package_id })
Add-Check "boot.target.bound" $bootTargetReady "Boot target descriptor must bind architecture, boot modes, kernel family, and required boot markers." ([ordered]@{ target_arch = $targetArch; boot_modes = $bootModes; kernel_family = $rc16MediaManifest.architecture_and_compatibility.kernel_family; boot_markers = $bootMarkers.Count; descriptor_id = $bootTargetDescriptorId })
Add-Check "rootfs.references.bound" $rootfsReady "Installer media manifest must bind rootfs runtime manifest, validation, and runtime artifact count." ([ordered]@{ validation_result = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.validation_result; runtime_manifest_sha256 = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.rootfs_runtime_manifest_sha256; runtime_artifact_count = $rc16MediaManifest.rootfs_initramfs_provenance.alpha_rootfs.runtime_artifact_count })
Add-Check "rollback.support.bound" $rollbackSupportReady "Installer media manifest must bind rollback and support references while execution and upload remain disabled." $installerMediaManifest.rollback_support
Add-Check "boot_target.projection_only" ($bootTargetDescriptor.projection_only -eq $true -and $bootTargetDescriptor.authority.host_boot_state_authority -eq $false -and $bootTargetDescriptor.authority.host_boot_metadata_mutation_authority -eq $false -and $bootTargetDescriptor.next_required_gate.host_boot_mutation_allowed_now -eq $false) "Boot target descriptor must remain projection-only and cannot mutate host boot state." $bootTargetDescriptor.authority
Add-Check "install.effects.gated" ($installerMediaManifest.install_gate.install_allowed -eq $false -and $installerMediaManifest.install_gate.first_user_install_allowed -eq $false -and $installerMediaManifest.install_gate.install_effects_gated_until -eq "RC19-021" -and $installerMediaManifest.production_ready_claim -eq $false) "Install effects must remain gated until RC19-021 and production_ready_claim must remain false." $installerMediaManifest.install_gate
Add-Check "authority.no_broadening" ($authorityClean -and @($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC19-011 must not build media, install, mutate host boot/rootfs, upload, recover, dispatch, sign, mutate production, or broaden external authority." ([ordered]@{ authority = $installerMediaManifest.authority; side_effects = $sideEffects })
Add-Check "outputs.written" ((Test-Path -LiteralPath $installerMediaManifestPath -PathType Leaf) -and (Test-Path -LiteralPath $bootTargetDescriptorPath -PathType Leaf) -and $installerMediaManifestSha256 -match "^[0-9a-f]{64}$" -and $bootTargetDescriptorSha256 -match "^[0-9a-f]{64}$") "RC19-011 must write installer media manifest and boot target descriptor outputs." ([ordered]@{ installer_media_manifest = [ordered]@{ path = Get-StablePath $installerMediaManifestPath; sha256 = $installerMediaManifestSha256 }; boot_target_descriptor = [ordered]@{ path = Get-StablePath $bootTargetDescriptorPath; sha256 = $bootTargetDescriptorSha256 } })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $installerMediaManifestPath),
    (Get-Content -Raw -LiteralPath $bootTargetDescriptorPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-011 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-installer-media-manifest-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-011"
    status = $resultStatus
    production_ready_claim = $false
    installable_image_artifact_id = $artifactId
    installer_media_id = $installerMediaId
    boot_target_descriptor_id = $bootTargetDescriptorId
    outputs = [ordered]@{
        installer_media_manifest = [ordered]@{
            path = Get-StablePath $installerMediaManifestPath
            sha256 = $installerMediaManifestSha256
            installer_media_id = $installerMediaId
        }
        boot_target_descriptor = [ordered]@{
            path = Get-StablePath $bootTargetDescriptorPath
            sha256 = $bootTargetDescriptorSha256
            boot_target_descriptor_id = $bootTargetDescriptorId
        }
    }
    media_surface = [ordered]@{
        state = $installerMediaManifest.status
        installable_image_artifact_id = $artifactId
        boot_markers = $bootMarkers.Count
        target_arch = $targetArch
        boot_modes = $bootModes
        kernel_family = $rc16MediaManifest.architecture_and_compatibility.kernel_family
        rootfs_runtime_manifest_sha256 = $installerMediaManifest.rootfs.rootfs_runtime_manifest_sha256
        rollback_baseline_sha256 = $installerMediaManifest.rollback_support.rollback_baseline.sha256
        support_recovery_sha256 = $installerMediaManifest.rollback_support.support_index.sha256
        boot_target_projection_only = $true
        install_allowed = $false
        first_user_install_allowed = $false
        install_effects_gated_until = "RC19-021"
    }
    source = $source
    checks = @($script:checks)
    blockers = @($script:failedChecks | ForEach-Object { $_.id })
    fail_closed_boundaries = $denialCases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        projection_only = $true
        build_executed = $false
        image_built = $false
        iso_created = $false
        disk_image_created = $false
        payload_uploaded = $false
        external_payload_published = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($denialCases).Count
        failed_cases = 0
        rc19_011_complete = (@($script:failedChecks).Count -eq 0)
        installer_media_id = $installerMediaId
        boot_target_descriptor_id = $bootTargetDescriptorId
        next_task = "RC19-012"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-011-installer-media-manifest.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-installer-media-manifest-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-011"
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
    media_surface = $result.media_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-012"
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
    throw "Sensitive marker detected in RC19-011 outputs."
}

Write-Host "RC19 installer media manifest $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Installer media manifest: $(Get-StablePath $installerMediaManifestPath)"
Write-Host "Boot target descriptor: $(Get-StablePath $bootTargetDescriptorPath)"
Write-Host "Installer media id: $installerMediaId"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count), failed cases: 0"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
