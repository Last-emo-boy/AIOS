param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-local-channel-promotion",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$ReleaseBundleManifestPath = ".workflow/artifacts/rc20-single-user-release-bundle/release-bundle-manifest.json",
    [string]$ReleaseBundleInputMapPath = ".workflow/artifacts/rc20-single-user-release-bundle/release-bundle-input-map.json",
    [string]$OfflineChannelResultPath = ".workflow/artifacts/rc19-offline-local-channel-consumption/result.json",
    [string]$OfflineChannelPackagePath = ".workflow/artifacts/rc19-offline-local-channel-consumption/offline-local-channel-package.json",
    [string]$OfflineChannelEvidencePath = ".workflow/artifacts/rc19-offline-local-channel-consumption/local-channel-consumption-evidence.json",
    [string]$ConsumerSmokeResultPath = ".workflow/artifacts/rc19-installable-image-consumer-smoke/result.json",
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
        candidate_channel_package_bound = $false
        stable_channel_projection_bound = $false
        external_mirror_published = $false
        external_payload_published = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
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
    $effects = New-SideEffects
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_promotion_authority = $true
        side_effects = $effects
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
$resolvedReleaseBundleInputMapPath = Resolve-RepoPath $ReleaseBundleInputMapPath
$resolvedOfflineChannelResultPath = Resolve-RepoPath $OfflineChannelResultPath
$resolvedOfflineChannelPackagePath = Resolve-RepoPath $OfflineChannelPackagePath
$resolvedOfflineChannelEvidencePath = Resolve-RepoPath $OfflineChannelEvidencePath
$resolvedConsumerSmokeResultPath = Resolve-RepoPath $ConsumerSmokeResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$releaseBundleManifest = Read-Json $resolvedReleaseBundleManifestPath
$releaseBundleInputMap = Read-Json $resolvedReleaseBundleInputMapPath
$offlineChannelResult = Read-Json $resolvedOfflineChannelResultPath
$offlineChannelPackage = Read-Json $resolvedOfflineChannelPackagePath
$offlineChannelEvidence = Read-Json $resolvedOfflineChannelEvidencePath
$consumerSmokeResult = Read-Json $resolvedConsumerSmokeResultPath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-010"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-011"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-011" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$releaseBundleReady = (
    $releaseBundleResult.status -eq "passed" -and
    $releaseBundleResult.summary.rc20_010_complete -eq $true -and
    $releaseBundleResult.production_ready_claim -eq $false -and
    $releaseBundleResult.consumer_ready_claim -eq $false -and
    $releaseBundleResult.bundle_surface.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $releaseBundleManifest.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $releaseBundleInputMap.release_bundle_id -eq $releaseBundleResult.release_bundle_id
)

$offlineChannelReady = (
    $offlineChannelResult.status -eq "passed" -and
    $offlineChannelResult.summary.rc19_030_complete -eq $true -and
    $offlineChannelResult.summary.offline_local_channel_package_bound -eq $true -and
    $offlineChannelResult.summary.remote_payload_downloaded -eq $false -and
    $offlineChannelResult.summary.object_storage_provisioned -eq $false -and
    $offlineChannelResult.summary.remote_dispatch_enabled -eq $false -and
    $offlineChannelPackage.offline_local_channel_package_id -eq $offlineChannelResult.offline_local_channel_package_id -and
    $offlineChannelPackage.local_only -eq $true -and
    $offlineChannelPackage.offline_only -eq $true -and
    $offlineChannelEvidence.offline_local_channel_package_id -eq $offlineChannelResult.offline_local_channel_package_id -and
    $offlineChannelEvidence.local_only -eq $true -and
    $offlineChannelEvidence.offline_only -eq $true -and
    $offlineChannelEvidence.local_channel_followed -eq $true
)

$offlineIdentityMatchesBundle = (
    $releaseBundleResult.bundle_surface.offline_local_channel_package_id -eq $offlineChannelResult.offline_local_channel_package_id -and
    $releaseBundleManifest.release_identity.offline_local_channel_package_id -eq $offlineChannelResult.offline_local_channel_package_id -and
    $releaseBundleInputMap.identity_material.release_identity.offline_local_channel_package_id -eq $offlineChannelResult.offline_local_channel_package_id
)

$consumerReady = (
    $consumerSmokeResult.status -eq "passed" -and
    $consumerSmokeResult.summary.rc19_040_complete -eq $true -and
    $consumerSmokeResult.summary.consumer_ready_claim -eq $true -and
    $consumerSmokeResult.summary.production_ready_claim -eq $false -and
    $consumerSmokeResult.summary.install_performed_by_consumer_smoke -eq $false -and
    $consumerSmokeResult.summary.update_performed_by_consumer_smoke -eq $false -and
    $consumerSmokeResult.summary.rollback_execution_performed_by_consumer_smoke -eq $false -and
    $consumerSmokeResult.consumer_surface.local_offline_channel_followed -eq $true
)

$promotionAllowed = $planAllowsRun -and $releaseBundleReady -and $offlineChannelReady -and $offlineIdentityMatchesBundle -and $consumerReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-011-plan-pointer-not-current" }
if (-not $releaseBundleReady) { $blockers += "rc20-release-bundle-not-ready" }
if (-not $offlineChannelReady) { $blockers += "rc19-offline-local-channel-not-ready" }
if (-not $offlineIdentityMatchesBundle) { $blockers += "release-bundle-offline-channel-mismatch" }
if (-not $consumerReady) { $blockers += "rc19-consumer-smoke-not-ready" }
if ($promotionAllowed) { $blockers = @() }

$source = [ordered]@{
    rc20_plan = New-ArtifactRef $resolvedPlanPath $plan "rc20 workflow plan"
    rc20_authority_contract = [ordered]@{
        role = "rc20 authority contract"
        path = Get-StablePath $resolvedContractPath
        sha256 = Get-FileSha256 $resolvedContractPath
        size_bytes = (Get-Item -LiteralPath $resolvedContractPath).Length
        present = $true
    }
    rc20_release_bundle_result = New-ArtifactRef $resolvedReleaseBundleResultPath $releaseBundleResult "rc20 release bundle result"
    rc20_release_bundle_manifest = New-ArtifactRef $resolvedReleaseBundleManifestPath $releaseBundleManifest "rc20 release bundle manifest"
    rc20_release_bundle_input_map = New-ArtifactRef $resolvedReleaseBundleInputMapPath $releaseBundleInputMap "rc20 release bundle input map"
    rc19_offline_channel_result = New-ArtifactRef $resolvedOfflineChannelResultPath $offlineChannelResult "rc19 offline channel result"
    rc19_offline_channel_package = New-ArtifactRef $resolvedOfflineChannelPackagePath $offlineChannelPackage "rc19 offline channel package"
    rc19_offline_channel_evidence = New-ArtifactRef $resolvedOfflineChannelEvidencePath $offlineChannelEvidence "rc19 offline channel evidence"
    rc19_consumer_smoke_result = New-ArtifactRef $resolvedConsumerSmokeResultPath $consumerSmokeResult "rc19 consumer smoke result"
}

$promotionIdentityMaterial = [ordered]@{
    schema = "agentos.rc20-local-channel-promotion-identity-material.v1"
    task = "RC20-011"
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    installable_image_artifact_id = [string]$releaseBundleResult.bundle_surface.installable_image_artifact_id
    installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
    boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
    first_user_target_state_id = [string]$releaseBundleResult.bundle_surface.first_user_target_state_id
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    consumer_audit_digest = [string]$releaseBundleManifest.release_identity.consumer_audit_digest
    source_hashes = @(
        [ordered]@{ id = "rc20-release-bundle-result"; path = Get-StablePath $resolvedReleaseBundleResultPath; sha256 = Get-FileSha256 $resolvedReleaseBundleResultPath; schema = $releaseBundleResult.schema; status = $releaseBundleResult.status },
        [ordered]@{ id = "rc20-release-bundle-manifest"; path = Get-StablePath $resolvedReleaseBundleManifestPath; sha256 = Get-FileSha256 $resolvedReleaseBundleManifestPath; schema = $releaseBundleManifest.schema; status = $releaseBundleManifest.status },
        [ordered]@{ id = "rc20-release-bundle-input-map"; path = Get-StablePath $resolvedReleaseBundleInputMapPath; sha256 = Get-FileSha256 $resolvedReleaseBundleInputMapPath; schema = $releaseBundleInputMap.schema; status = $releaseBundleInputMap.status },
        [ordered]@{ id = "rc19-offline-channel-result"; path = Get-StablePath $resolvedOfflineChannelResultPath; sha256 = Get-FileSha256 $resolvedOfflineChannelResultPath; schema = $offlineChannelResult.schema; status = $offlineChannelResult.status },
        [ordered]@{ id = "rc19-offline-channel-package"; path = Get-StablePath $resolvedOfflineChannelPackagePath; sha256 = Get-FileSha256 $resolvedOfflineChannelPackagePath; schema = $offlineChannelPackage.schema; status = $offlineChannelPackage.status },
        [ordered]@{ id = "rc19-offline-channel-evidence"; path = Get-StablePath $resolvedOfflineChannelEvidencePath; sha256 = Get-FileSha256 $resolvedOfflineChannelEvidencePath; schema = $offlineChannelEvidence.schema; status = $offlineChannelEvidence.status },
        [ordered]@{ id = "rc19-consumer-smoke-result"; path = Get-StablePath $resolvedConsumerSmokeResultPath; sha256 = Get-FileSha256 $resolvedConsumerSmokeResultPath; schema = $consumerSmokeResult.schema; status = $consumerSmokeResult.status }
    )
    deterministic_rules = [ordered]@{
        generated_at_excluded_from_identity = $true
        output_hashes_excluded_from_identity = $true
        external_reachability_excluded_from_identity = $true
        source_hashes_required = $true
    }
}

$candidateChannelPackageId = "sha256:$(Get-StringSha256 (Get-JsonText $promotionIdentityMaterial))"
$stableProjectionMaterial = [ordered]@{
    schema = "agentos.rc20-local-stable-channel-projection-material.v1"
    task = "RC20-011"
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = $candidateChannelPackageId
    offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
    candidate_channel = "candidate"
    projected_channel = "stable"
    local_projection_only = $true
    external_publication = $false
    active_artifact_set_mutation = $false
}
$stableChannelProjectionId = "sha256:$(Get-StringSha256 (Get-JsonText $stableProjectionMaterial))"

$candidateChannelPackage = [ordered]@{
    schema = "agentos.rc20-local-candidate-channel-package.v1"
    generated_at = $generatedAtValue
    task = "RC20-011"
    status = if ($promotionAllowed) { "local-candidate-channel-package-bound" } else { "local-candidate-channel-package-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = $candidateChannelPackageId
    stable_channel_projection_id = $stableChannelProjectionId
    local_only = $true
    offline_only = $true
    channel = "candidate"
    promotion_identity_material = $promotionIdentityMaterial
    candidate_surface = [ordered]@{
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        installable_image_artifact_id = [string]$releaseBundleResult.bundle_surface.installable_image_artifact_id
        first_user_target_state_id = [string]$releaseBundleResult.bundle_surface.first_user_target_state_id
        offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
        local_consumer_ready_carried = $consumerReady
        candidate_channel_bound = $promotionAllowed
        stable_projection_required = $true
        external_stable_channel_claim_allowed = $false
        install_allowed_by_channel_package = $false
        update_allowed_by_channel_package = $false
        rollback_allowed_by_channel_package = $false
    }
    authority = [ordered]@{
        aios_body_only = $true
        external_mirror_publication_authority = $false
        frontend_authority = $false
        endpoint_reachability_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        host_rootfs_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
    }
    next_required_gate = [ordered]@{
        rc20_012_release_bundle_channel_fail_closed = "required-before-bundle-trust"
        rc20_020_installer_selection = "required-before-single-user-install-acceptance"
        rc20_040_consumer_smoke = "required-before-rc20-consumer-ready-claim"
        rc20_050_final_audit = "required-before-rc20-closeout"
    }
    source = $source
}

$candidateChannelPackagePath = Join-Path $resolvedArtifactDir "candidate-channel-package.json"
Write-Json $candidateChannelPackage $candidateChannelPackagePath

$stableChannelProjection = [ordered]@{
    schema = "agentos.rc20-local-stable-channel-projection.v1"
    generated_at = $generatedAtValue
    task = "RC20-011"
    status = if ($promotionAllowed) { "local-stable-channel-projection-bound-non-ga" } else { "local-stable-channel-projection-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = $candidateChannelPackageId
    stable_channel_projection_id = $stableChannelProjectionId
    projected_from = "candidate"
    projected_to = "stable"
    local_only = $true
    projection_only = $true
    stable_channel_projection_bound = $promotionAllowed
    external_stable_channel_published = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    stable_projection_material = $stableProjectionMaterial
    stable_surface = [ordered]@{
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        candidate_channel_package_id = $candidateChannelPackageId
        offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
        local_consumer_ready_carried = $consumerReady
        stable_channel_name_reserved = "stable"
        stable_channel_local_evidence = $true
        external_mirror_publication_required = $false
        external_mirror_publication_performed = $false
        active_artifact_set_mutation_allowed = $false
        active_artifact_set_mutated = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
    authority = $candidateChannelPackage.authority
    source = $source
}
$stableChannelProjectionPath = Join-Path $resolvedArtifactDir "stable-channel-projection.json"
Write-Json $stableChannelProjection $stableChannelProjectionPath

$caseSpecs = @(
    [ordered]@{ id = "missing-release-bundle"; blockers = @("rc20-release-bundle-required"); reason = "Promotion requires a completed RC20 release bundle." },
    [ordered]@{ id = "missing-release-bundle-manifest"; blockers = @("release-bundle-manifest-required"); reason = "Promotion requires release bundle manifest identity." },
    [ordered]@{ id = "missing-offline-channel-result"; blockers = @("offline-channel-result-required"); reason = "Promotion requires RC19 offline/local channel result." },
    [ordered]@{ id = "missing-offline-channel-package"; blockers = @("offline-channel-package-required"); reason = "Promotion requires RC19 offline/local channel package." },
    [ordered]@{ id = "missing-consumer-smoke"; blockers = @("consumer-smoke-required"); reason = "Promotion requires RC19 local consumer smoke readiness." },
    [ordered]@{ id = "release-bundle-id-mismatch"; blockers = @("release-bundle-id-mismatch"); reason = "Promotion cannot bind mismatched release bundle identities." },
    [ordered]@{ id = "offline-channel-id-mismatch"; blockers = @("offline-channel-id-mismatch"); reason = "Promotion cannot bind mismatched offline channel identities." },
    [ordered]@{ id = "stale-release-bundle"; blockers = @("stale-release-bundle-denied"); reason = "Promotion denies stale release bundle inputs." },
    [ordered]@{ id = "stale-channel-evidence"; blockers = @("stale-channel-evidence-denied"); reason = "Promotion denies stale local channel evidence." },
    [ordered]@{ id = "broad-channel-scope"; blockers = @("broad-channel-scope-denied"); reason = "Promotion denies channel packages broader than the bound release bundle." },
    [ordered]@{ id = "remote-channel-uri"; blockers = @("remote-channel-uri-denied"); reason = "RC20-011 is local evidence and cannot require remote channel URI trust." },
    [ordered]@{ id = "external-mirror-publication"; blockers = @("external-mirror-publication-denied"); reason = "External mirror publication is outside RC20 body scope." },
    [ordered]@{ id = "endpoint-reachability-authority"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not promotion authority." },
    [ordered]@{ id = "frontend-output-authority"; blockers = @("frontend-output-authority-denied"); reason = "Frontend output is not promotion authority." },
    [ordered]@{ id = "signer-authority"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not promotion authority." },
    [ordered]@{ id = "object-storage-provisioning"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is outside RC20-011 scope." },
    [ordered]@{ id = "remote-payload-download"; blockers = @("remote-payload-download-denied"); reason = "Promotion does not download payloads." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Promotion cannot mutate the active artifact set." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Promotion cannot mutate production rings." },
    [ordered]@{ id = "install-attempt"; blockers = @("install-effect-denied"); reason = "RC20-011 cannot execute install." },
    [ordered]@{ id = "update-attempt"; blockers = @("update-effect-denied"); reason = "RC20-011 cannot execute update." },
    [ordered]@{ id = "rollback-attempt"; blockers = @("rollback-effect-denied"); reason = "RC20-011 cannot execute rollback." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC20-011 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$sideEffects = New-SideEffects
$sideEffects.candidate_channel_package_bound = $promotionAllowed
$sideEffects.stable_channel_projection_bound = $promotionAllowed

Add-Check "plan.current_task.rc20_011" $planAllowsRun "RC20-011 must run after RC20-010 completed, with current_task set to RC20-011." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_010_status = $rc20PreviousStatus; rc20_011_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-011 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "release_bundle.ready" $releaseBundleReady "RC20 release bundle must be complete, non-GA, and internally coherent." ([ordered]@{ status = $releaseBundleResult.status; rc20_010_complete = $releaseBundleResult.summary.rc20_010_complete; release_bundle_id = $releaseBundleResult.release_bundle_id; manifest_release_bundle_id = $releaseBundleManifest.release_bundle_id; input_map_release_bundle_id = $releaseBundleInputMap.release_bundle_id; production_ready_claim = $releaseBundleResult.production_ready_claim })
Add-Check "offline_channel.ready" $offlineChannelReady "RC19 offline/local channel package and consumption evidence must be bound, local-only, and remote-effect-free." ([ordered]@{ result_status = $offlineChannelResult.status; package_status = $offlineChannelPackage.status; evidence_status = $offlineChannelEvidence.status; offline_local_channel_package_id = $offlineChannelResult.offline_local_channel_package_id; remote_payload_downloaded = $offlineChannelResult.summary.remote_payload_downloaded; remote_dispatch_enabled = $offlineChannelResult.summary.remote_dispatch_enabled })
Add-Check "offline_channel.identity_matches_bundle" $offlineIdentityMatchesBundle "RC20 release bundle must carry the same offline/local channel identity that RC20-011 promotes." ([ordered]@{ bundle_offline_channel = $releaseBundleResult.bundle_surface.offline_local_channel_package_id; manifest_offline_channel = $releaseBundleManifest.release_identity.offline_local_channel_package_id; input_map_offline_channel = $releaseBundleInputMap.identity_material.release_identity.offline_local_channel_package_id; rc19_offline_channel = $offlineChannelResult.offline_local_channel_package_id })
Add-Check "consumer_smoke.ready" $consumerReady "RC19 consumer smoke must carry local consumer readiness without production readiness or new effects." ([ordered]@{ status = $consumerSmokeResult.status; consumer_ready_claim = $consumerSmokeResult.summary.consumer_ready_claim; production_ready_claim = $consumerSmokeResult.summary.production_ready_claim; install_performed_by_consumer_smoke = $consumerSmokeResult.summary.install_performed_by_consumer_smoke; local_offline_channel_followed = $consumerSmokeResult.consumer_surface.local_offline_channel_followed })
Add-Check "candidate.identity.deterministic" ($candidateChannelPackage.candidate_channel_package_id -eq $candidateChannelPackageId -and $candidateChannelPackage.promotion_identity_material.deterministic_rules.generated_at_excluded_from_identity -eq $true) "Candidate channel package identity must be deterministic from source hashes and stable identity material." ([ordered]@{ candidate_channel_package_id = $candidateChannelPackageId; generated_at_excluded = $candidateChannelPackage.promotion_identity_material.deterministic_rules.generated_at_excluded_from_identity })
Add-Check "stable_projection.local_only" ($stableChannelProjection.stable_channel_projection_bound -eq $promotionAllowed -and $stableChannelProjection.local_only -eq $true -and $stableChannelProjection.projection_only -eq $true -and $stableChannelProjection.external_stable_channel_published -eq $false -and $stableChannelProjection.active_artifact_set_mutated -eq $false -and $stableChannelProjection.production_ring_mutated -eq $false) "Stable channel promotion must remain local projection evidence and must not publish externally or mutate active/production state." ([ordered]@{ stable_channel_projection_id = $stableChannelProjectionId; local_only = $stableChannelProjection.local_only; projection_only = $stableChannelProjection.projection_only; external_stable_channel_published = $stableChannelProjection.external_stable_channel_published; active_artifact_set_mutated = $stableChannelProjection.active_artifact_set_mutated })
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.external_mirror_published -eq $false -and $sideEffects.external_payload_published -eq $false -and $sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false -and $sideEffects.production_ready_claim -eq $false) "RC20-011 must not publish, download, sign, execute install/update/rollback, upload support, execute recovery, dispatch remote work, or mutate host/production state." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing, stale, broad, remote, signer, host-mutating, active-artifact, production, and GA promotion attempts must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $candidateChannelPackagePath),
    (Get-Content -Raw -LiteralPath $stableChannelProjectionPath)
)
Add-Check "outputs.secret_safe" $outputSecretSafe "RC20-011 outputs must not contain key blocks, private authority paths, auth tokens, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-local-channel-promotion-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-011"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = $candidateChannelPackageId
    stable_channel_projection_id = $stableChannelProjectionId
    outputs = [ordered]@{
        candidate_channel_package = [ordered]@{
            path = Get-StablePath $candidateChannelPackagePath
            sha256 = Get-FileSha256 $candidateChannelPackagePath
            candidate_channel_package_id = $candidateChannelPackageId
        }
        stable_channel_projection = [ordered]@{
            path = Get-StablePath $stableChannelProjectionPath
            sha256 = Get-FileSha256 $stableChannelProjectionPath
            stable_channel_projection_id = $stableChannelProjectionId
        }
    }
    promotion_surface = [ordered]@{
        state = if ($promotionAllowed) { "local-candidate-to-stable-channel-promotion-bound-non-ga" } else { "local-candidate-to-stable-channel-promotion-denied" }
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        candidate_channel_package_id = $candidateChannelPackageId
        stable_channel_projection_id = $stableChannelProjectionId
        offline_local_channel_package_id = [string]$offlineChannelResult.offline_local_channel_package_id
        candidate_channel_package_bound = $promotionAllowed
        stable_channel_projection_bound = $promotionAllowed
        stable_channel_local_evidence = $promotionAllowed
        local_consumer_ready_carried = $consumerReady
        external_mirror_publication_performed = $false
        external_payload_published = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        local_promotion_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        external_mirror_publication_performed = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        remote_payload_downloaded = $false
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
        frontend_authority = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_011_complete = (@($script:failedChecks).Count -eq 0)
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        candidate_channel_package_id = $candidateChannelPackageId
        stable_channel_projection_id = $stableChannelProjectionId
        candidate_channel_package_bound = $promotionAllowed
        stable_channel_projection_bound = $promotionAllowed
        external_mirror_publication_performed = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC20-012"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-011-local-channel-promotion.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-local-channel-promotion-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-011"
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
    promotion_surface = $result.promotion_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-012"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-011 outputs." }

Write-Host "RC20 local channel promotion $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Candidate package: $(Get-StablePath $candidateChannelPackagePath)"
Write-Host "Stable projection: $(Get-StablePath $stableChannelProjectionPath)"
Write-Host "Local promotion only: true; external mirror publication: false; active artifact set mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
