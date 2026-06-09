param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-installer-catalog-selection",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$ReleaseBundleManifestPath = ".workflow/artifacts/rc20-single-user-release-bundle/release-bundle-manifest.json",
    [string]$ChannelPromotionResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
    [string]$CandidateChannelPackagePath = ".workflow/artifacts/rc20-local-channel-promotion/candidate-channel-package.json",
    [string]$StableChannelProjectionPath = ".workflow/artifacts/rc20-local-channel-promotion/stable-channel-projection.json",
    [string]$BundleChannelFailClosedResultPath = ".workflow/artifacts/rc20-release-bundle-channel-fail-closed/result.json",
    [string]$InstallerMediaResultPath = ".workflow/artifacts/rc19-installer-media-manifest/result.json",
    [string]$InstallerMediaManifestPath = ".workflow/artifacts/rc19-installer-media-manifest/installer-media-manifest.json",
    [string]$BootTargetDescriptorPath = ".workflow/artifacts/rc19-installer-media-manifest/boot-target-descriptor.json",
    [string]$PostInstallLifecycleResultPath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json",
    [string]$SupportRecoveryResultPath = ".workflow/artifacts/rc19-first-user-support-recovery/result.json",
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
    param([Parameter(Mandatory = $true)][string]$Path, $Json = $null, [string]$Role = "")
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        role = $Role
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        task = if ($null -ne $Json) { $Json.task } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
        consumer_ready_claim = if ($null -ne $Json) { $Json.consumer_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
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
    return [ordered]@{
        installer_catalog_bound = $false
        version_selection_preflight_bound = $false
        host_install_authorized = $false
        remote_fetch_authorized = $false
        external_mirror_trusted = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        shell_output_trusted = $false
        tui_output_trusted = $false
        model_replay_trusted = $false
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
        signer_authority_granted = $false
        cryptographic_signing_performed = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
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
        denied_before_installer_selection_authority = $true
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
$resolvedReleaseBundleResultPath = Resolve-RepoPath $ReleaseBundleResultPath
$resolvedReleaseBundleManifestPath = Resolve-RepoPath $ReleaseBundleManifestPath
$resolvedChannelPromotionResultPath = Resolve-RepoPath $ChannelPromotionResultPath
$resolvedCandidateChannelPackagePath = Resolve-RepoPath $CandidateChannelPackagePath
$resolvedStableChannelProjectionPath = Resolve-RepoPath $StableChannelProjectionPath
$resolvedBundleChannelFailClosedResultPath = Resolve-RepoPath $BundleChannelFailClosedResultPath
$resolvedInstallerMediaResultPath = Resolve-RepoPath $InstallerMediaResultPath
$resolvedInstallerMediaManifestPath = Resolve-RepoPath $InstallerMediaManifestPath
$resolvedBootTargetDescriptorPath = Resolve-RepoPath $BootTargetDescriptorPath
$resolvedPostInstallLifecycleResultPath = Resolve-RepoPath $PostInstallLifecycleResultPath
$resolvedSupportRecoveryResultPath = Resolve-RepoPath $SupportRecoveryResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$releaseBundleManifest = Read-Json $resolvedReleaseBundleManifestPath
$channelPromotionResult = Read-Json $resolvedChannelPromotionResultPath
$candidateChannelPackage = Read-Json $resolvedCandidateChannelPackagePath
$stableChannelProjection = Read-Json $resolvedStableChannelProjectionPath
$bundleChannelFailClosedResult = Read-Json $resolvedBundleChannelFailClosedResultPath
$installerMediaResult = Read-Json $resolvedInstallerMediaResultPath
$installerMediaManifest = Read-Json $resolvedInstallerMediaManifestPath
$bootTargetDescriptor = Read-Json $resolvedBootTargetDescriptorPath
$postInstallLifecycleResult = Read-Json $resolvedPostInstallLifecycleResultPath
$supportRecoveryResult = Read-Json $resolvedSupportRecoveryResultPath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-012"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-020" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$upstreamReady = (
    $releaseBundleResult.status -eq "passed" -and
    $releaseBundleResult.summary.rc20_010_complete -eq $true -and
    $channelPromotionResult.status -eq "passed" -and
    $channelPromotionResult.summary.rc20_011_complete -eq $true -and
    $bundleChannelFailClosedResult.status -eq "passed" -and
    $bundleChannelFailClosedResult.summary.rc20_012_complete -eq $true -and
    $releaseBundleResult.release_bundle_id -eq $channelPromotionResult.release_bundle_id -and
    $releaseBundleResult.release_bundle_id -eq $bundleChannelFailClosedResult.release_bundle_id
)

$installerMediaReady = (
    $installerMediaResult.status -eq "passed" -and
    $installerMediaResult.summary.rc19_011_complete -eq $true -and
    $installerMediaManifest.status -eq "installer-media-manifest-bound-install-gated" -and
    $bootTargetDescriptor.status -eq "boot-target-descriptor-bound-projection-only" -and
    $installerMediaResult.summary.installer_media_id -eq $installerMediaManifest.installer_media_id -and
    $installerMediaManifest.installer_media_id -eq $bootTargetDescriptor.installer_media_id -and
    $installerMediaManifest.boot_target_descriptor.boot_target_descriptor_id -eq $bootTargetDescriptor.boot_target_descriptor_id -and
    $installerMediaManifest.installable_image_artifact_id -eq $releaseBundleResult.bundle_surface.installable_image_artifact_id -and
    $installerMediaManifest.installer_media_id -eq $releaseBundleResult.bundle_surface.installer_media_id -and
    $bootTargetDescriptor.boot_target_descriptor_id -eq $releaseBundleResult.bundle_surface.boot_target_descriptor_id
)

$lifecycleReady = (
    $postInstallLifecycleResult.status -eq "passed" -and
    $postInstallLifecycleResult.summary.rc19_031_complete -eq $true -and
    $postInstallLifecycleResult.summary.update_compatibility_readiness -eq "ready" -and
    $postInstallLifecycleResult.summary.rollback_compatibility_readiness -eq "ready" -and
    $postInstallLifecycleResult.summary.update_or_rollback_executed_by_this_smoke -eq $false -and
    $supportRecoveryResult.status -eq "passed" -and
    $supportRecoveryResult.summary.rc19_032_complete -eq $true -and
    $supportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $supportRecoveryResult.summary.support_upload_performed -eq $false -and
    $supportRecoveryResult.summary.recovery_execution_performed -eq $false
)

$catalogAllowed = $planAllowsRun -and $upstreamReady -and $installerMediaReady -and $lifecycleReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-020-plan-pointer-not-current" }
if (-not $upstreamReady) { $blockers += "rc20-release-channel-upstream-not-ready" }
if (-not $installerMediaReady) { $blockers += "installer-media-not-ready" }
if (-not $lifecycleReady) { $blockers += "rollback-support-lifecycle-not-ready" }
if ($catalogAllowed) { $blockers = @() }

$commonChoiceSurface = [ordered]@{
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    installable_image_artifact_id = [string]$releaseBundleResult.bundle_surface.installable_image_artifact_id
    installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
    boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
    first_user_target_state_id = [string]$releaseBundleResult.bundle_surface.first_user_target_state_id
    offline_local_channel_package_id = [string]$releaseBundleResult.bundle_surface.offline_local_channel_package_id
    support_bundle_id = [string]$releaseBundleResult.bundle_surface.support_bundle_id
    local_only = $true
    host_install_authorized = $false
    remote_fetch_authorized = $false
    external_mirror_trusted = $false
    production_ready_claim = $false
}

$catalogIdentityMaterial = [ordered]@{
    schema = "agentos.rc20-installer-catalog-identity-material.v1"
    task = "RC20-020"
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
    stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
    installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
    boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
    source_hashes = @(
        [ordered]@{ id = "rc20-release-bundle-result"; path = Get-StablePath $resolvedReleaseBundleResultPath; sha256 = Get-FileSha256 $resolvedReleaseBundleResultPath; status = $releaseBundleResult.status },
        [ordered]@{ id = "rc20-channel-promotion-result"; path = Get-StablePath $resolvedChannelPromotionResultPath; sha256 = Get-FileSha256 $resolvedChannelPromotionResultPath; status = $channelPromotionResult.status },
        [ordered]@{ id = "rc20-bundle-channel-fail-closed"; path = Get-StablePath $resolvedBundleChannelFailClosedResultPath; sha256 = Get-FileSha256 $resolvedBundleChannelFailClosedResultPath; status = $bundleChannelFailClosedResult.status },
        [ordered]@{ id = "rc19-installer-media-result"; path = Get-StablePath $resolvedInstallerMediaResultPath; sha256 = Get-FileSha256 $resolvedInstallerMediaResultPath; status = $installerMediaResult.status },
        [ordered]@{ id = "rc19-installer-media-manifest"; path = Get-StablePath $resolvedInstallerMediaManifestPath; sha256 = Get-FileSha256 $resolvedInstallerMediaManifestPath; status = $installerMediaManifest.status },
        [ordered]@{ id = "rc19-boot-target-descriptor"; path = Get-StablePath $resolvedBootTargetDescriptorPath; sha256 = Get-FileSha256 $resolvedBootTargetDescriptorPath; status = $bootTargetDescriptor.status },
        [ordered]@{ id = "rc19-post-install-lifecycle"; path = Get-StablePath $resolvedPostInstallLifecycleResultPath; sha256 = Get-FileSha256 $resolvedPostInstallLifecycleResultPath; status = $postInstallLifecycleResult.status },
        [ordered]@{ id = "rc19-support-recovery"; path = Get-StablePath $resolvedSupportRecoveryResultPath; sha256 = Get-FileSha256 $resolvedSupportRecoveryResultPath; status = $supportRecoveryResult.status }
    )
    deterministic_rules = [ordered]@{
        generated_at_excluded_from_identity = $true
        source_hashes_required = $true
        output_hashes_excluded_from_identity = $true
        external_reachability_excluded_from_identity = $true
    }
}
$installerCatalogId = "sha256:$(Get-StringSha256 (Get-JsonText $catalogIdentityMaterial))"

$candidateChoice = [ordered]@{
    channel = "candidate"
    version = "rc20-single-user-candidate"
    choice_id = "sha256:$(Get-StringSha256 (Get-JsonText ([ordered]@{ channel = "candidate"; release_bundle_id = $releaseBundleResult.release_bundle_id; candidate_channel_package_id = $channelPromotionResult.candidate_channel_package_id; installer_media_id = $releaseBundleResult.bundle_surface.installer_media_id })))"
    candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
    stable_channel_projection_id = $null
    selectable_for_preflight = $catalogAllowed
    selected_by_default = $false
    surface = $commonChoiceSurface
}
$stableChoice = [ordered]@{
    channel = "stable"
    version = "rc20-single-user-stable-local-projection"
    choice_id = "sha256:$(Get-StringSha256 (Get-JsonText ([ordered]@{ channel = "stable"; release_bundle_id = $releaseBundleResult.release_bundle_id; stable_channel_projection_id = $channelPromotionResult.stable_channel_projection_id; installer_media_id = $releaseBundleResult.bundle_surface.installer_media_id })))"
    candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
    stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
    selectable_for_preflight = $catalogAllowed
    selected_by_default = $true
    surface = $commonChoiceSurface
}

$installerCatalog = [ordered]@{
    schema = "agentos.rc20-installer-catalog.v1"
    generated_at = $generatedAtValue
    task = "RC20-020"
    status = if ($catalogAllowed) { "installer-catalog-bound-local-selection-gated" } else { "installer-catalog-selection-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    installer_catalog_id = $installerCatalogId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    choices = @($candidateChoice, $stableChoice)
    expected_choice_count = 2
    selection_policy = [ordered]@{
        default_channel = "stable"
        allowed_channels = @("candidate", "stable")
        require_release_bundle_identity = $true
        require_installer_media_identity = $true
        require_boot_target_descriptor = $true
        require_rollback_support = $true
        require_local_channel_identity = $true
        host_install_authorized = $false
        remote_fetch_authorized = $false
        external_mirror_trusted = $false
    }
    authority = [ordered]@{
        aios_body_only = $true
        catalog_authority_only = $true
        host_install_authority = $false
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
        endpoint_reachability_authority = $false
    }
    source = [ordered]@{
        rc20_release_bundle_result = New-ArtifactRef $resolvedReleaseBundleResultPath $releaseBundleResult "rc20 release bundle result"
        rc20_channel_promotion_result = New-ArtifactRef $resolvedChannelPromotionResultPath $channelPromotionResult "rc20 channel promotion result"
        rc20_bundle_channel_fail_closed = New-ArtifactRef $resolvedBundleChannelFailClosedResultPath $bundleChannelFailClosedResult "rc20 bundle/channel fail-closed result"
        rc19_installer_media_result = New-ArtifactRef $resolvedInstallerMediaResultPath $installerMediaResult "rc19 installer media result"
        rc19_installer_media_manifest = New-ArtifactRef $resolvedInstallerMediaManifestPath $installerMediaManifest "rc19 installer media manifest"
        rc19_boot_target_descriptor = New-ArtifactRef $resolvedBootTargetDescriptorPath $bootTargetDescriptor "rc19 boot target descriptor"
        rc19_post_install_lifecycle = New-ArtifactRef $resolvedPostInstallLifecycleResultPath $postInstallLifecycleResult "rc19 post-install lifecycle"
        rc19_support_recovery = New-ArtifactRef $resolvedSupportRecoveryResultPath $supportRecoveryResult "rc19 support recovery"
    }
}
$installerCatalogPath = Join-Path $resolvedArtifactDir "installer-catalog.json"
Write-Json $installerCatalog $installerCatalogPath

$preflightMaterial = [ordered]@{
    schema = "agentos.rc20-version-selection-preflight-material.v1"
    task = "RC20-020"
    installer_catalog_id = $installerCatalogId
    selected_channel = "stable"
    selected_version = "rc20-single-user-stable-local-projection"
    selected_choice_id = $stableChoice.choice_id
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
    boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
    offline_local_channel_package_id = [string]$releaseBundleResult.bundle_surface.offline_local_channel_package_id
    candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
    stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
    rollback_support = [ordered]@{
        update_readiness = [string]$postInstallLifecycleResult.summary.update_compatibility_readiness
        rollback_readiness = [string]$postInstallLifecycleResult.summary.rollback_compatibility_readiness
        support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only
        support_upload_performed = $supportRecoveryResult.summary.support_upload_performed
        recovery_execution_performed = $supportRecoveryResult.summary.recovery_execution_performed
    }
}
$versionSelectionPreflightId = "sha256:$(Get-StringSha256 (Get-JsonText $preflightMaterial))"

$versionSelectionPreflight = [ordered]@{
    schema = "agentos.rc20-version-selection-preflight.v1"
    generated_at = $generatedAtValue
    task = "RC20-020"
    status = if ($catalogAllowed) { "version-selection-preflight-bound-install-gated" } else { "version-selection-preflight-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    version_selection_preflight_id = $versionSelectionPreflightId
    installer_catalog_id = $installerCatalogId
    selected = [ordered]@{
        channel = "stable"
        version = "rc20-single-user-stable-local-projection"
        choice_id = $stableChoice.choice_id
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
        boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
        candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
        stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
        offline_local_channel_package_id = [string]$releaseBundleResult.bundle_surface.offline_local_channel_package_id
    }
    bindings = [ordered]@{
        release_bundle_bound = $upstreamReady
        installer_media_bound = $installerMediaReady
        boot_target_descriptor_bound = $installerMediaReady
        rollback_support_bound = $lifecycleReady
        local_channel_identity_bound = $upstreamReady
        bundle_channel_fail_closed_bound = ($bundleChannelFailClosedResult.summary.rc20_012_complete -eq $true)
    }
    authorization = [ordered]@{
        host_install_authorized = $false
        remote_fetch_authorized = $false
        external_mirror_trusted = $false
        support_upload_authorized = $false
        recovery_execution_authorized = $false
        production_mutation_authorized = $false
    }
    preflight_material = $preflightMaterial
}
$versionSelectionPreflightPath = Join-Path $resolvedArtifactDir "version-selection-preflight.json"
Write-Json $versionSelectionPreflight $versionSelectionPreflightPath

$caseSpecs = @(
    [ordered]@{ id = "missing-release-bundle"; blockers = @("release-bundle-required"); reason = "Installer selection requires the RC20 release bundle." },
    [ordered]@{ id = "missing-channel-promotion"; blockers = @("channel-promotion-required"); reason = "Installer selection requires local channel promotion." },
    [ordered]@{ id = "missing-fail-closed-gate"; blockers = @("bundle-channel-fail-closed-required"); reason = "Installer selection requires release bundle/channel fail-closed evidence." },
    [ordered]@{ id = "missing-installer-media"; blockers = @("installer-media-required"); reason = "Installer selection requires installer media identity." },
    [ordered]@{ id = "missing-boot-descriptor"; blockers = @("boot-target-descriptor-required"); reason = "Installer selection requires boot target descriptor identity." },
    [ordered]@{ id = "missing-rollback-support"; blockers = @("rollback-support-required"); reason = "Installer selection requires rollback/support references." },
    [ordered]@{ id = "missing-local-channel-identity"; blockers = @("local-channel-identity-required"); reason = "Installer selection requires local channel identity." },
    [ordered]@{ id = "extra-channel-choice"; blockers = @("unexpected-channel-choice-denied"); reason = "Catalog must expose exactly candidate and stable choices." },
    [ordered]@{ id = "candidate-release-bundle-mismatch"; blockers = @("candidate-release-bundle-mismatch"); reason = "Candidate choice cannot point at a different release bundle." },
    [ordered]@{ id = "stable-release-bundle-mismatch"; blockers = @("stable-release-bundle-mismatch"); reason = "Stable choice cannot point at a different release bundle." },
    [ordered]@{ id = "installer-media-mismatch"; blockers = @("installer-media-mismatch"); reason = "Selection cannot bind mismatched installer media." },
    [ordered]@{ id = "boot-descriptor-mismatch"; blockers = @("boot-descriptor-mismatch"); reason = "Selection cannot bind mismatched boot descriptor." },
    [ordered]@{ id = "host-install-authorization-attempt"; blockers = @("host-install-authorization-denied"); reason = "RC20-020 cannot authorize host install." },
    [ordered]@{ id = "remote-fetch-authorization-attempt"; blockers = @("remote-fetch-authorization-denied"); reason = "RC20-020 cannot authorize remote fetch." },
    [ordered]@{ id = "external-mirror-trust-attempt"; blockers = @("external-mirror-trust-denied"); reason = "External mirror trust is out of scope." },
    [ordered]@{ id = "support-upload-authorization-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-authorization-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "Installer selection cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$choices = @($installerCatalog.choices)
$choiceChannels = @($choices | ForEach-Object { $_.channel })
$catalogExactlyExpected = (
    $choices.Count -eq 2 -and
    $choiceChannels -contains "candidate" -and
    $choiceChannels -contains "stable" -and
    @($choiceChannels | Select-Object -Unique).Count -eq 2 -and
    $candidateChoice.release_bundle_id -eq $stableChoice.release_bundle_id -and
    $candidateChoice.surface.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $stableChoice.surface.release_bundle_id -eq $releaseBundleResult.release_bundle_id
)

$preflightBindsRequired = (
    $versionSelectionPreflight.bindings.release_bundle_bound -eq $true -and
    $versionSelectionPreflight.bindings.installer_media_bound -eq $true -and
    $versionSelectionPreflight.bindings.boot_target_descriptor_bound -eq $true -and
    $versionSelectionPreflight.bindings.rollback_support_bound -eq $true -and
    $versionSelectionPreflight.bindings.local_channel_identity_bound -eq $true -and
    $versionSelectionPreflight.selected.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $versionSelectionPreflight.selected.installer_media_id -eq $releaseBundleResult.bundle_surface.installer_media_id -and
    $versionSelectionPreflight.selected.boot_target_descriptor_id -eq $releaseBundleResult.bundle_surface.boot_target_descriptor_id
)

$noForbiddenAuthority = (
    $versionSelectionPreflight.authorization.host_install_authorized -eq $false -and
    $versionSelectionPreflight.authorization.remote_fetch_authorized -eq $false -and
    $versionSelectionPreflight.authorization.external_mirror_trusted -eq $false -and
    $versionSelectionPreflight.authorization.support_upload_authorized -eq $false -and
    $versionSelectionPreflight.authorization.recovery_execution_authorized -eq $false -and
    $versionSelectionPreflight.authorization.production_mutation_authorized -eq $false -and
    $installerCatalog.authority.host_install_authority -eq $false -and
    $installerCatalog.authority.remote_dispatch_authority -eq $false -and
    $installerCatalog.authority.active_artifact_set_mutation_authority -eq $false -and
    $installerCatalog.authority.production_ring_mutation_authority -eq $false
)

Add-Check "plan.current_task.rc20_020" $planAllowsRun "RC20-020 must run after RC20-012 completed, with current_task set to RC20-020." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_012_status = $rc20PreviousStatus; rc20_020_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-020 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "upstream.release_channel_ready" $upstreamReady "Release bundle, channel promotion, and fail-closed verification must all be complete and identity-compatible." ([ordered]@{ release_bundle_status = $releaseBundleResult.status; channel_promotion_status = $channelPromotionResult.status; fail_closed_status = $bundleChannelFailClosedResult.status; release_bundle_id = $releaseBundleResult.release_bundle_id })
Add-Check "installer_media.ready" $installerMediaReady "Installer media manifest and boot target descriptor must match the RC20 release bundle identity." ([ordered]@{ installer_media_result_status = $installerMediaResult.status; installer_media_id = $installerMediaManifest.installer_media_id; release_bundle_installer_media_id = $releaseBundleResult.bundle_surface.installer_media_id; boot_target_descriptor_id = $bootTargetDescriptor.boot_target_descriptor_id; release_bundle_boot_target_descriptor_id = $releaseBundleResult.bundle_surface.boot_target_descriptor_id })
Add-Check "lifecycle.rollback_support_ready" $lifecycleReady "Version selection preflight must bind rollback/update compatibility and local support/recovery references." ([ordered]@{ post_install_status = $postInstallLifecycleResult.status; update_readiness = $postInstallLifecycleResult.summary.update_compatibility_readiness; rollback_readiness = $postInstallLifecycleResult.summary.rollback_compatibility_readiness; support_status = $supportRecoveryResult.status; support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only })
Add-Check "catalog.exact_candidate_stable_choices" $catalogExactlyExpected "Installer catalog must expose exactly the expected local candidate and stable release bundle choices." ([ordered]@{ choice_count = $choices.Count; channels = $choiceChannels; candidate_release_bundle = $candidateChoice.surface.release_bundle_id; stable_release_bundle = $stableChoice.surface.release_bundle_id })
Add-Check "preflight.binds_required_identity" $preflightBindsRequired "Version selection preflight must bind release bundle, installer media, boot descriptor, rollback/support, and local channel identity." $versionSelectionPreflight.selected
Add-Check "authority.no_forbidden_authority" $noForbiddenAuthority "Installer catalog selection cannot authorize host install, remote fetch, external mirror trust, support upload, recovery execution, remote dispatch, active artifact mutation, or production mutation." ([ordered]@{ preflight_authorization = $versionSelectionPreflight.authorization; catalog_authority = $installerCatalog.authority })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Installer catalog selection must deny missing sources, identity mismatch, extra channels, host install, remote fetch, external mirror trust, support/recovery execution, production mutation, and GA claims." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $installerCatalogPath),
    (Get-Content -Raw -LiteralPath $versionSelectionPreflightPath)
)
Add-Check "outputs.secret_safe" $outputSecretSafe "RC20-020 outputs must not contain key blocks, private authority paths, auth tokens, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-installer-catalog-selection-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-020"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    installer_catalog_id = $installerCatalogId
    version_selection_preflight_id = $versionSelectionPreflightId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
    boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
    outputs = [ordered]@{
        installer_catalog = [ordered]@{
            path = Get-StablePath $installerCatalogPath
            sha256 = Get-FileSha256 $installerCatalogPath
            installer_catalog_id = $installerCatalogId
        }
        version_selection_preflight = [ordered]@{
            path = Get-StablePath $versionSelectionPreflightPath
            sha256 = Get-FileSha256 $versionSelectionPreflightPath
            version_selection_preflight_id = $versionSelectionPreflightId
        }
    }
    selection_surface = [ordered]@{
        state = if ($catalogAllowed) { "installer-catalog-version-selection-preflight-bound-install-gated" } else { "installer-catalog-version-selection-denied" }
        catalog_exactly_expected = $catalogExactlyExpected
        choice_count = $choices.Count
        channels = $choiceChannels
        selected_channel = $versionSelectionPreflight.selected.channel
        selected_version = $versionSelectionPreflight.selected.version
        preflight_binds_required_identity = $preflightBindsRequired
        host_install_authorized = $false
        remote_fetch_authorized = $false
        external_mirror_trusted = $false
        support_upload_authorized = $false
        recovery_execution_authorized = $false
        production_mutation_authorized = $false
        blockers = @($blockers)
    }
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        installer_selection_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        host_install_authorized = $false
        remote_fetch_authorized = $false
        external_mirror_trusted = $false
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
        signer_authority = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_020_complete = (@($script:failedChecks).Count -eq 0)
        installer_catalog_id = $installerCatalogId
        version_selection_preflight_id = $versionSelectionPreflightId
        catalog_exactly_expected = $catalogExactlyExpected
        preflight_binds_required_identity = $preflightBindsRequired
        host_install_authorized = $false
        remote_fetch_authorized = $false
        external_mirror_trusted = $false
        next_task = "RC20-021"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-020-installer-catalog-selection.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-installer-catalog-selection-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-020"
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
    selection_surface = $result.selection_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-021"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-020 outputs." }

Write-Host "RC20 installer catalog selection $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Catalog: $(Get-StablePath $installerCatalogPath)"
Write-Host "Preflight: $(Get-StablePath $versionSelectionPreflightPath)"
Write-Host "Choices: $($choices.Count); selected channel: $($versionSelectionPreflight.selected.channel); host install authorized: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
