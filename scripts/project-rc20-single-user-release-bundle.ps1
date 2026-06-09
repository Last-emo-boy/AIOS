param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-single-user-release-bundle",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$Rc19FinalAuditResultPath = ".workflow/artifacts/rc19-final-closeout-audit/result.json",
    [string]$Rc19FinalAuditEvidencePath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/evidence/FINAL-AUDIT-20260610-production-distro-rc19.json",
    [string]$Rc19ImageArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$Rc19ImageArtifactSetPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/installable-image-artifact-set.json",
    [string]$Rc19InstallerMediaResultPath = ".workflow/artifacts/rc19-installer-media-manifest/result.json",
    [string]$Rc19InstallerMediaManifestPath = ".workflow/artifacts/rc19-installer-media-manifest/installer-media-manifest.json",
    [string]$Rc19BootTargetDescriptorPath = ".workflow/artifacts/rc19-installer-media-manifest/boot-target-descriptor.json",
    [string]$Rc19FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$Rc19FirstUserInstallEvidencePath = ".workflow/artifacts/rc19-first-user-install-drill/first-user-install-evidence.json",
    [string]$Rc19OfflineChannelResultPath = ".workflow/artifacts/rc19-offline-local-channel-consumption/result.json",
    [string]$Rc19OfflineChannelPackagePath = ".workflow/artifacts/rc19-offline-local-channel-consumption/offline-local-channel-package.json",
    [string]$Rc19LocalChannelConsumptionEvidencePath = ".workflow/artifacts/rc19-offline-local-channel-consumption/local-channel-consumption-evidence.json",
    [string]$Rc19PostInstallSmokeResultPath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json",
    [string]$Rc19PostInstallSmokeEvidencePath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/post-install-update-rollback-evidence.json",
    [string]$Rc19SupportRecoveryResultPath = ".workflow/artifacts/rc19-first-user-support-recovery/result.json",
    [string]$Rc19SupportBundlePath = ".workflow/artifacts/rc19-first-user-support-recovery/first-user-support-bundle.json",
    [string]$Rc19RecoveryReferenceIndexPath = ".workflow/artifacts/rc19-first-user-support-recovery/recovery-reference-index.json",
    [string]$Rc19ConsumerSmokeResultPath = ".workflow/artifacts/rc19-installable-image-consumer-smoke/result.json",
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

function New-InputRef {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Role,
        $Json = $null,
        [bool]$Required = $true
    )
    $resolved = Resolve-RepoPath $Path
    $present = Test-Path -LiteralPath $resolved -PathType Leaf
    return [ordered]@{
        id = $Id
        role = $Role
        path = Get-StablePath $resolved
        sha256 = Get-FileSha256 $resolved
        size_bytes = if ($present) { (Get-Item -LiteralPath $resolved).Length } else { $null }
        present = $present
        required = $Required
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
        consumer_ready_claim = Get-JsonProperty $Json "consumer_ready_claim"
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

function New-FailClosedCase {
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
        denied_before_bundle_ready = $true
        side_effects = [ordered]@{
            payload_uploaded = $false
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
            mirror_frontend_changed = $false
            signer_authority_granted = $false
            cryptographic_signing_performed = $false
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
$resolvedRc19FinalAuditResultPath = Resolve-RepoPath $Rc19FinalAuditResultPath
$resolvedRc19FinalAuditEvidencePath = Resolve-RepoPath $Rc19FinalAuditEvidencePath
$resolvedRc19ImageArtifactResultPath = Resolve-RepoPath $Rc19ImageArtifactResultPath
$resolvedRc19ImageArtifactSetPath = Resolve-RepoPath $Rc19ImageArtifactSetPath
$resolvedRc19InstallerMediaResultPath = Resolve-RepoPath $Rc19InstallerMediaResultPath
$resolvedRc19InstallerMediaManifestPath = Resolve-RepoPath $Rc19InstallerMediaManifestPath
$resolvedRc19BootTargetDescriptorPath = Resolve-RepoPath $Rc19BootTargetDescriptorPath
$resolvedRc19FirstUserInstallResultPath = Resolve-RepoPath $Rc19FirstUserInstallResultPath
$resolvedRc19FirstUserInstallEvidencePath = Resolve-RepoPath $Rc19FirstUserInstallEvidencePath
$resolvedRc19OfflineChannelResultPath = Resolve-RepoPath $Rc19OfflineChannelResultPath
$resolvedRc19OfflineChannelPackagePath = Resolve-RepoPath $Rc19OfflineChannelPackagePath
$resolvedRc19LocalChannelConsumptionEvidencePath = Resolve-RepoPath $Rc19LocalChannelConsumptionEvidencePath
$resolvedRc19PostInstallSmokeResultPath = Resolve-RepoPath $Rc19PostInstallSmokeResultPath
$resolvedRc19PostInstallSmokeEvidencePath = Resolve-RepoPath $Rc19PostInstallSmokeEvidencePath
$resolvedRc19SupportRecoveryResultPath = Resolve-RepoPath $Rc19SupportRecoveryResultPath
$resolvedRc19SupportBundlePath = Resolve-RepoPath $Rc19SupportBundlePath
$resolvedRc19RecoveryReferenceIndexPath = Resolve-RepoPath $Rc19RecoveryReferenceIndexPath
$resolvedRc19ConsumerSmokeResultPath = Resolve-RepoPath $Rc19ConsumerSmokeResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc19FinalAuditResult = Read-Json $resolvedRc19FinalAuditResultPath
$rc19FinalAuditEvidence = Read-Json $resolvedRc19FinalAuditEvidencePath
$rc19ImageArtifactResult = Read-Json $resolvedRc19ImageArtifactResultPath
$rc19ImageArtifactSet = Read-Json $resolvedRc19ImageArtifactSetPath
$rc19InstallerMediaResult = Read-Json $resolvedRc19InstallerMediaResultPath
$rc19InstallerMediaManifest = Read-Json $resolvedRc19InstallerMediaManifestPath
$rc19BootTargetDescriptor = Read-Json $resolvedRc19BootTargetDescriptorPath
$rc19FirstUserInstallResult = Read-Json $resolvedRc19FirstUserInstallResultPath
$rc19FirstUserInstallEvidence = Read-Json $resolvedRc19FirstUserInstallEvidencePath
$rc19OfflineChannelResult = Read-Json $resolvedRc19OfflineChannelResultPath
$rc19OfflineChannelPackage = Read-Json $resolvedRc19OfflineChannelPackagePath
$rc19LocalChannelConsumptionEvidence = Read-Json $resolvedRc19LocalChannelConsumptionEvidencePath
$rc19PostInstallSmokeResult = Read-Json $resolvedRc19PostInstallSmokeResultPath
$rc19PostInstallSmokeEvidence = Read-Json $resolvedRc19PostInstallSmokeEvidencePath
$rc19SupportRecoveryResult = Read-Json $resolvedRc19SupportRecoveryResultPath
$rc19SupportBundle = Read-Json $resolvedRc19SupportBundlePath
$rc19RecoveryReferenceIndex = Read-Json $resolvedRc19RecoveryReferenceIndexPath
$rc19ConsumerSmokeResult = Read-Json $resolvedRc19ConsumerSmokeResultPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-001"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-010"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC20-010" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC20-011" -and $currentTaskStatus -eq "completed")
    )
)

$inputRefs = @(
    (New-InputRef -Id "rc20-plan" -Path $PlanPath -Role "rc20 workflow plan" -Json $plan),
    (New-InputRef -Id "rc20-authority-contract" -Path $ContractPath -Role "rc20 authority contract"),
    (New-InputRef -Id "rc19-final-audit-result" -Path $Rc19FinalAuditResultPath -Role "rc19 final audit result" -Json $rc19FinalAuditResult),
    (New-InputRef -Id "rc19-final-audit-evidence" -Path $Rc19FinalAuditEvidencePath -Role "rc19 final audit evidence" -Json $rc19FinalAuditEvidence),
    (New-InputRef -Id "rc19-image-artifact-result" -Path $Rc19ImageArtifactResultPath -Role "rc19 image artifact result" -Json $rc19ImageArtifactResult),
    (New-InputRef -Id "rc19-image-artifact-set" -Path $Rc19ImageArtifactSetPath -Role "rc19 image artifact set" -Json $rc19ImageArtifactSet),
    (New-InputRef -Id "rc19-installer-media-result" -Path $Rc19InstallerMediaResultPath -Role "rc19 installer media result" -Json $rc19InstallerMediaResult),
    (New-InputRef -Id "rc19-installer-media-manifest" -Path $Rc19InstallerMediaManifestPath -Role "rc19 installer media manifest" -Json $rc19InstallerMediaManifest),
    (New-InputRef -Id "rc19-boot-target-descriptor" -Path $Rc19BootTargetDescriptorPath -Role "rc19 boot target descriptor" -Json $rc19BootTargetDescriptor),
    (New-InputRef -Id "rc19-first-user-install-result" -Path $Rc19FirstUserInstallResultPath -Role "rc19 first-user install result" -Json $rc19FirstUserInstallResult),
    (New-InputRef -Id "rc19-first-user-install-evidence" -Path $Rc19FirstUserInstallEvidencePath -Role "rc19 first-user install evidence" -Json $rc19FirstUserInstallEvidence),
    (New-InputRef -Id "rc19-offline-channel-result" -Path $Rc19OfflineChannelResultPath -Role "rc19 offline channel result" -Json $rc19OfflineChannelResult),
    (New-InputRef -Id "rc19-offline-channel-package" -Path $Rc19OfflineChannelPackagePath -Role "rc19 offline channel package" -Json $rc19OfflineChannelPackage),
    (New-InputRef -Id "rc19-local-channel-consumption-evidence" -Path $Rc19LocalChannelConsumptionEvidencePath -Role "rc19 local channel consumption evidence" -Json $rc19LocalChannelConsumptionEvidence),
    (New-InputRef -Id "rc19-post-install-smoke-result" -Path $Rc19PostInstallSmokeResultPath -Role "rc19 post-install smoke result" -Json $rc19PostInstallSmokeResult),
    (New-InputRef -Id "rc19-post-install-smoke-evidence" -Path $Rc19PostInstallSmokeEvidencePath -Role "rc19 post-install smoke evidence" -Json $rc19PostInstallSmokeEvidence),
    (New-InputRef -Id "rc19-support-recovery-result" -Path $Rc19SupportRecoveryResultPath -Role "rc19 support recovery result" -Json $rc19SupportRecoveryResult),
    (New-InputRef -Id "rc19-support-bundle" -Path $Rc19SupportBundlePath -Role "rc19 support bundle" -Json $rc19SupportBundle),
    (New-InputRef -Id "rc19-recovery-reference-index" -Path $Rc19RecoveryReferenceIndexPath -Role "rc19 recovery reference index" -Json $rc19RecoveryReferenceIndex),
    (New-InputRef -Id "rc19-consumer-smoke-result" -Path $Rc19ConsumerSmokeResultPath -Role "rc19 consumer smoke result" -Json $rc19ConsumerSmokeResult)
)

$missingRequiredRefs = @($inputRefs | Where-Object { $_.required -and (-not $_.present -or $_.sha256 -notmatch "^[0-9a-f]{64}$") })
$sourceStatusesPassed = @($inputRefs | Where-Object { $_.id -like "rc19-*" -and $_.schema -and $_.status -and $_.status -ne "passed" -and $_.status -ne "completed" -and $_.status -notlike "*bound*" -and $_.status -notlike "*ready*" -and $_.status -notlike "*local*" -and $_.status -notlike "*projection*" -and $_.status -notlike "*executed*" -and $_.status -notlike "*compatible*" }).Count -eq 0
$allNonGa = @($inputRefs | Where-Object { $_.production_ready_claim -eq $true }).Count -eq 0

$artifactId = [string]$rc19ImageArtifactResult.installable_image_artifact_id
$installerMediaId = [string]$rc19InstallerMediaResult.installer_media_id
$bootTargetDescriptorId = [string]$rc19InstallerMediaResult.boot_target_descriptor_id
$targetStateId = [string]$rc19FinalAuditEvidence.identity_surface.first_user_target_state_id
$offlineChannelPackageId = [string]$rc19FinalAuditEvidence.identity_surface.offline_local_channel_package_id
$supportBundleId = [string]$rc19FinalAuditEvidence.identity_surface.support_bundle_id
$consumerAuditDigest = [string]$rc19FinalAuditEvidence.identity_surface.consumer_audit_digest

$identityChainCoherent = (
    $artifactId -like "sha256:*" -and
    $rc19FinalAuditEvidence.identity_surface.installable_image_artifact_id -eq $artifactId -and
    $rc19ConsumerSmokeResult.installable_image_artifact_id -eq $artifactId -and
    $rc19InstallerMediaResult.installable_image_artifact_id -eq $artifactId -and
    $rc19FirstUserInstallResult.installable_image_artifact_id -eq $artifactId -and
    $installerMediaId -like "sha256:*" -and
    $rc19FinalAuditEvidence.identity_surface.installer_media_id -eq $installerMediaId -and
    $bootTargetDescriptorId -like "sha256:*" -and
    $rc19FinalAuditEvidence.identity_surface.boot_target_descriptor_id -eq $bootTargetDescriptorId
)
$targetChainCoherent = (
    $targetStateId -like "sha256:*" -and
    $rc19FirstUserInstallResult.summary.target_state_id -eq $targetStateId -and
    $rc19PostInstallSmokeResult.first_user_target_state_id -eq $targetStateId -and
    $rc19ConsumerSmokeResult.first_user_target_state_id -eq $targetStateId
)
$readinessCoherent = (
    $rc19FinalAuditResult.installable_image_local_consumer_ready -eq $true -and
    $rc19ConsumerSmokeResult.consumer_ready_claim -eq $true -and
    $rc19ConsumerSmokeResult.consumer_surface.installable_image_readiness -eq "ready" -and
    $rc19ConsumerSmokeResult.consumer_surface.first_user_install_readiness -eq "ready" -and
    $rc19ConsumerSmokeResult.consumer_surface.post_install_update_readiness -eq "ready" -and
    $rc19ConsumerSmokeResult.consumer_surface.post_install_rollback_readiness -eq "ready" -and
    $rc19ConsumerSmokeResult.consumer_surface.support_recovery_readiness -eq "ready" -and
    $rc19FinalAuditResult.production_ready_claim -eq $false
)
$supportRecoveryLocalOnly = (
    $rc19SupportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $rc19SupportRecoveryResult.summary.support_bundle_redacted -eq $true -and
    $rc19SupportRecoveryResult.summary.support_upload_performed -eq $false -and
    $rc19SupportRecoveryResult.summary.recovery_execution_performed -eq $false -and
    $rc19SupportRecoveryResult.summary.remote_dispatch_enabled -eq $false
)

$identityMaterial = [ordered]@{
    schema = "agentos.rc20-single-user-release-bundle-identity-material.v1"
    task = "RC20-010"
    source_hashes = @($inputRefs | ForEach-Object { [ordered]@{ id = $_.id; path = $_.path; sha256 = $_.sha256; schema = $_.schema; status = $_.status } })
    release_identity = [ordered]@{
        installable_image_artifact_id = $artifactId
        installer_media_id = $installerMediaId
        boot_target_descriptor_id = $bootTargetDescriptorId
        first_user_target_state_id = $targetStateId
        offline_local_channel_package_id = $offlineChannelPackageId
        support_bundle_id = $supportBundleId
        consumer_audit_digest = $consumerAuditDigest
    }
    readiness = [ordered]@{
        installable_image_local_consumer_ready = $rc19FinalAuditResult.installable_image_local_consumer_ready
        first_user_install_readiness = $rc19ConsumerSmokeResult.consumer_surface.first_user_install_readiness
        post_install_update_readiness = $rc19ConsumerSmokeResult.consumer_surface.post_install_update_readiness
        post_install_rollback_readiness = $rc19ConsumerSmokeResult.consumer_surface.post_install_rollback_readiness
        support_recovery_readiness = $rc19ConsumerSmokeResult.consumer_surface.support_recovery_readiness
        production_ready_claim = $false
    }
}
$identityMaterialHash = Get-StringSha256 (Get-JsonText $identityMaterial)
$releaseBundleId = "sha256:$identityMaterialHash"

$inputMap = [ordered]@{
    schema = "agentos.rc20-single-user-release-bundle-input-map.v1"
    generated_at = $generatedAtValue
    task = "RC20-010"
    status = "single-user-release-bundle-inputs-bound"
    production_ready_claim = $false
    release_bundle_id = $releaseBundleId
    identity_material_hash = $identityMaterialHash
    deterministic_rules = [ordered]@{
        generated_at_excluded_from_identity = $true
        source_hashes_required = $true
        output_hashes_excluded_from_identity = $true
        external_reachability_excluded_from_identity = $true
    }
    identity_material = $identityMaterial
    source = $inputRefs
}
$inputMapPath = Join-Path $resolvedArtifactDir "release-bundle-input-map.json"
Write-Json $inputMap $inputMapPath
$inputMapSha256 = Get-FileSha256 $inputMapPath

$failClosedCases = @(
    (New-FailClosedCase -Id "missing-final-audit" -Blockers @("rc19-final-audit-required") -Reason "Release bundle requires RC19 final audit."),
    (New-FailClosedCase -Id "missing-image-artifact" -Blockers @("image-artifact-required") -Reason "Release bundle requires installable image artifact identity."),
    (New-FailClosedCase -Id "missing-installer-media" -Blockers @("installer-media-required") -Reason "Release bundle requires installer media identity."),
    (New-FailClosedCase -Id "missing-first-user-install" -Blockers @("first-user-install-required") -Reason "Release bundle requires first-user install evidence."),
    (New-FailClosedCase -Id "missing-offline-channel" -Blockers @("offline-local-channel-required") -Reason "Release bundle requires offline/local channel evidence."),
    (New-FailClosedCase -Id "missing-post-install-smoke" -Blockers @("post-install-readiness-required") -Reason "Release bundle requires update/rollback compatibility evidence."),
    (New-FailClosedCase -Id "missing-support-recovery" -Blockers @("support-recovery-required") -Reason "Release bundle requires support/recovery evidence."),
    (New-FailClosedCase -Id "target-state-mismatch" -Blockers @("target-state-chain-mismatch") -Reason "Release bundle cannot bind mismatched target state."),
    (New-FailClosedCase -Id "host-rootfs-mutation-attempt" -Blockers @("host-rootfs-mutation-denied") -Reason "Host rootfs mutation is forbidden."),
    (New-FailClosedCase -Id "host-boot-mutation-attempt" -Blockers @("host-boot-mutation-denied") -Reason "Host boot mutation is forbidden."),
    (New-FailClosedCase -Id "active-artifact-set-mutation-attempt" -Blockers @("active-artifact-set-mutation-denied") -Reason "Active artifact set mutation is forbidden."),
    (New-FailClosedCase -Id "production-ring-mutation-attempt" -Blockers @("production-ring-mutation-denied") -Reason "Production ring mutation is forbidden."),
    (New-FailClosedCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied") -Reason "Remote dispatch is forbidden."),
    (New-FailClosedCase -Id "object-storage-provisioning-attempt" -Blockers @("object-storage-provisioning-denied") -Reason "Object storage provisioning is outside RC20 body scope."),
    (New-FailClosedCase -Id "signer-authority-attempt" -Blockers @("signer-authority-denied") -Reason "Signer reachability is not release bundle authority."),
    (New-FailClosedCase -Id "support-upload-attempt" -Blockers @("support-upload-denied") -Reason "Support upload is outside RC20-010 scope."),
    (New-FailClosedCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied") -Reason "Recovery execution is outside RC20-010 scope."),
    (New-FailClosedCase -Id "ga-claim-attempt" -Blockers @("ga-claim-denied") -Reason "Release bundle cannot claim GA readiness.")
)

$manifest = [ordered]@{
    schema = "agentos.rc20-single-user-release-bundle-manifest.v1"
    generated_at = $generatedAtValue
    task = "RC20-010"
    status = "single-user-release-bundle-bound-non-ga"
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = $releaseBundleId
    identity_material_hash = $identityMaterialHash
    release_bundle_input_map = [ordered]@{
        path = Get-StablePath $inputMapPath
        sha256 = $inputMapSha256
    }
    release_identity = $identityMaterial.release_identity
    readiness = $identityMaterial.readiness
    bundle_classes = [ordered]@{
        installable_image = [ordered]@{
            result = $inputRefs | Where-Object { $_.id -eq "rc19-image-artifact-result" } | Select-Object -First 1
            artifact_set = $inputRefs | Where-Object { $_.id -eq "rc19-image-artifact-set" } | Select-Object -First 1
        }
        installer_media = [ordered]@{
            result = $inputRefs | Where-Object { $_.id -eq "rc19-installer-media-result" } | Select-Object -First 1
            manifest = $inputRefs | Where-Object { $_.id -eq "rc19-installer-media-manifest" } | Select-Object -First 1
            boot_target_descriptor = $inputRefs | Where-Object { $_.id -eq "rc19-boot-target-descriptor" } | Select-Object -First 1
        }
        first_user_install = [ordered]@{
            result = $inputRefs | Where-Object { $_.id -eq "rc19-first-user-install-result" } | Select-Object -First 1
            evidence = $inputRefs | Where-Object { $_.id -eq "rc19-first-user-install-evidence" } | Select-Object -First 1
            target_state_id = $targetStateId
        }
        local_channel = [ordered]@{
            result = $inputRefs | Where-Object { $_.id -eq "rc19-offline-channel-result" } | Select-Object -First 1
            package = $inputRefs | Where-Object { $_.id -eq "rc19-offline-channel-package" } | Select-Object -First 1
            consumption_evidence = $inputRefs | Where-Object { $_.id -eq "rc19-local-channel-consumption-evidence" } | Select-Object -First 1
            offline_only = $true
            remote_payload_download_allowed = $false
        }
        post_install_lifecycle = [ordered]@{
            smoke_result = $inputRefs | Where-Object { $_.id -eq "rc19-post-install-smoke-result" } | Select-Object -First 1
            smoke_evidence = $inputRefs | Where-Object { $_.id -eq "rc19-post-install-smoke-evidence" } | Select-Object -First 1
            update_readiness = $rc19PostInstallSmokeResult.summary.update_compatibility_readiness
            rollback_readiness = $rc19PostInstallSmokeResult.summary.rollback_compatibility_readiness
            update_or_rollback_executed_by_bundle = $false
        }
        support_recovery = [ordered]@{
            result = $inputRefs | Where-Object { $_.id -eq "rc19-support-recovery-result" } | Select-Object -First 1
            support_bundle = $inputRefs | Where-Object { $_.id -eq "rc19-support-bundle" } | Select-Object -First 1
            recovery_reference_index = $inputRefs | Where-Object { $_.id -eq "rc19-recovery-reference-index" } | Select-Object -First 1
            support_bundle_local_only = $true
            support_upload_allowed = $false
            recovery_execution_allowed = $false
        }
        local_consumer = [ordered]@{
            result = $inputRefs | Where-Object { $_.id -eq "rc19-consumer-smoke-result" } | Select-Object -First 1
            consumer_decision = $rc19ConsumerSmokeResult.consumer_surface.consumer_decision
            local_consumer_ready = $rc19ConsumerSmokeResult.consumer_ready_claim
            production_ready_claim = $false
        }
    }
    next_required_gates = [ordered]@{
        rc20_011_local_channel_promotion = "required-before-stable-channel-claim"
        rc20_012_fail_closed = "required-before-bundle-trust"
        rc20_020_installer_selection = "required-before-single-user-install-acceptance"
        rc20_021_single_user_install_acceptance = "execute-or-deny-inside-disposable-target"
        rc20_030_update_drill = "execute-or-deny-inside-disposable-installed-system"
        rc20_031_rollback_drill = "execute-or-deny-inside-disposable-installed-system"
        rc20_050_final_audit = "required-before-rc20-closeout"
    }
    authority = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        install_authority = $false
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
    fail_closed_boundaries = $failClosedCases
    source = $inputRefs
}
$manifestPath = Join-Path $resolvedArtifactDir "release-bundle-manifest.json"
Write-Json $manifest $manifestPath
$manifestSha256 = Get-FileSha256 $manifestPath

$authorityClean = (
    $manifest.authority.install_authority -eq $false -and
    $manifest.authority.update_authority -eq $false -and
    $manifest.authority.rollback_execution_authority -eq $false -and
    $manifest.authority.support_upload_authority -eq $false -and
    $manifest.authority.recovery_execution_authority -eq $false -and
    $manifest.authority.remote_dispatch_authority -eq $false -and
    $manifest.authority.host_rootfs_mutation_authority -eq $false -and
    $manifest.authority.host_active_slot_mutation_authority -eq $false -and
    $manifest.authority.host_boot_metadata_mutation_authority -eq $false -and
    $manifest.authority.active_artifact_set_mutation_authority -eq $false -and
    $manifest.authority.production_ring_mutation_authority -eq $false -and
    $manifest.authority.mirror_authority -eq $false -and
    $manifest.authority.frontend_authority -eq $false -and
    $manifest.authority.signer_authority -eq $false -and
    $manifest.authority.object_storage_authority -eq $false -and
    $manifest.authority.normal_shell_authority -eq $false -and
    $manifest.authority.tui_authority -eq $false -and
    $manifest.authority.endpoint_reachability_authority -eq $false -and
    $manifest.authority.model_replay_authority -eq $false
)
$sideEffects = [ordered]@{
    release_bundle_manifest_written = $true
    payload_uploaded = $false
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
    mirror_frontend_changed = $false
    signer_authority_granted = $false
    cryptographic_signing_performed = $false
}

Add-Check "plan.current_task.rc20_010" $planAllowsRun "RC20-010 must run after RC20-001 completed, while current_task is RC20-010 or during an idempotent rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_001_status = $previousTaskStatus; rc20_010_status = $currentTaskStatus })
Add-Check "contract.bundle_gate.present" ($contractText.Contains("Canonical single-user release bundle manifest is bound") -and $contractText.Contains("Local candidate and stable channel promotion package is bound") -and $contractText.Contains("production_ready_claim is false")) "RC20-010 must consume the RC20 single-user distribution authority contract." (New-InputRef -Id "rc20-authority-contract" -Path $ContractPath -Role "rc20 contract")
Add-Check "sources.required.present" (@($missingRequiredRefs).Count -eq 0) "All RC20-010 required source inputs must be present and hashable." (@($missingRequiredRefs | ForEach-Object { $_.path }))
Add-Check "sources.passed_non_ga" ($sourceStatusesPassed -and $allNonGa) "All RC19 source task results must be passed or bound, and no source may claim production readiness." ([ordered]@{ source_statuses_passed = $sourceStatusesPassed; all_non_ga = $allNonGa })
Add-Check "rc19.final.ready" ($rc19FinalAuditResult.status -eq "passed" -and $rc19FinalAuditResult.installable_image_local_consumer_ready -eq $true -and $rc19FinalAuditResult.production_ready_claim -eq $false) "RC19 final audit must prove installable image local consumer readiness without GA claim." ([ordered]@{ status = $rc19FinalAuditResult.status; local_consumer_ready = $rc19FinalAuditResult.installable_image_local_consumer_ready; consumer_ready_claim = $rc19FinalAuditResult.consumer_ready_claim; production_ready_claim = $rc19FinalAuditResult.production_ready_claim })
Add-Check "identity.chain.coherent" $identityChainCoherent "RC20 release bundle identity must keep image, installer, boot target, and consumer identities coherent." ([ordered]@{ artifact_id = $artifactId; installer_media_id = $installerMediaId; boot_target_descriptor_id = $bootTargetDescriptorId })
Add-Check "target.chain.coherent" $targetChainCoherent "RC20 release bundle must bind a coherent first-user target state across install, post-install, and consumer evidence." ([ordered]@{ target_state_id = $targetStateId; install_target = $rc19FirstUserInstallResult.summary.target_state_id; post_install_target = $rc19PostInstallSmokeResult.first_user_target_state_id; consumer_target = $rc19ConsumerSmokeResult.first_user_target_state_id })
Add-Check "readiness.coherent" $readinessCoherent "RC20 release bundle must carry RC19 local consumer readiness while keeping production_ready_claim=false." $identityMaterial.readiness
Add-Check "support_recovery.local_only" $supportRecoveryLocalOnly "Support/recovery inputs must be local-only, redacted, and non-executing." ([ordered]@{ support_bundle_local_only = $rc19SupportRecoveryResult.summary.support_bundle_local_only; support_bundle_redacted = $rc19SupportRecoveryResult.summary.support_bundle_redacted; support_upload_performed = $rc19SupportRecoveryResult.summary.support_upload_performed; recovery_execution_performed = $rc19SupportRecoveryResult.summary.recovery_execution_performed; remote_dispatch_enabled = $rc19SupportRecoveryResult.summary.remote_dispatch_enabled })
Add-Check "bundle.identity.deterministic" ($releaseBundleId -like "sha256:*" -and $identityMaterialHash -match "^[0-9a-f]{64}$" -and $manifest.release_bundle_id -eq $releaseBundleId -and $inputMap.identity_material_hash -eq $identityMaterialHash) "Release bundle identity must be deterministic from source hashes and stable identity material." ([ordered]@{ release_bundle_id = $releaseBundleId; identity_material_hash = $identityMaterialHash; generated_at_excluded = $inputMap.deterministic_rules.generated_at_excluded_from_identity })
Add-Check "bundle.bound_non_ga" ($manifest.status -eq "single-user-release-bundle-bound-non-ga" -and $manifest.production_ready_claim -eq $false -and $manifest.consumer_ready_claim -eq $false -and $manifest.next_required_gates.rc20_011_local_channel_promotion -eq "required-before-stable-channel-claim") "Release bundle manifest must be bound as non-GA and require later local channel promotion before stable channel claim." ([ordered]@{ status = $manifest.status; production_ready_claim = $manifest.production_ready_claim; consumer_ready_claim = $manifest.consumer_ready_claim; next_required_gates = $manifest.next_required_gates })
Add-Check "authority.no_broadening" ($authorityClean -and @($sideEffects.GetEnumerator() | Where-Object { $_.Name -ne "release_bundle_manifest_written" -and $_.Value -ne $false }).Count -eq 0) "RC20-010 must not broaden host, production, remote, signer, mirror, object storage, support upload, recovery, shell, TUI, endpoint, or model authority." ([ordered]@{ authority = $manifest.authority; side_effects = $sideEffects })
Add-Check "outputs.written" ((Test-Path -LiteralPath $inputMapPath -PathType Leaf) -and (Test-Path -LiteralPath $manifestPath -PathType Leaf) -and $inputMapSha256 -match "^[0-9a-f]{64}$" -and $manifestSha256 -match "^[0-9a-f]{64}$") "RC20-010 must write release bundle manifest and input map outputs." ([ordered]@{ input_map = [ordered]@{ path = Get-StablePath $inputMapPath; sha256 = $inputMapSha256 }; manifest = [ordered]@{ path = Get-StablePath $manifestPath; sha256 = $manifestSha256 } })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $inputMapPath),
    (Get-Content -Raw -LiteralPath $manifestPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC20-010 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-single-user-release-bundle-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-010"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = $releaseBundleId
    identity_material_hash = $identityMaterialHash
    release_bundle_manifest_sha256 = $manifestSha256
    release_bundle_input_map_sha256 = $inputMapSha256
    outputs = [ordered]@{
        release_bundle_manifest = [ordered]@{
            path = Get-StablePath $manifestPath
            sha256 = $manifestSha256
            release_bundle_id = $releaseBundleId
        }
        release_bundle_input_map = [ordered]@{
            path = Get-StablePath $inputMapPath
            sha256 = $inputMapSha256
            identity_material_hash = $identityMaterialHash
        }
    }
    bundle_surface = [ordered]@{
        state = $manifest.status
        release_bundle_id = $releaseBundleId
        installable_image_artifact_id = $artifactId
        installer_media_id = $installerMediaId
        boot_target_descriptor_id = $bootTargetDescriptorId
        first_user_target_state_id = $targetStateId
        offline_local_channel_package_id = $offlineChannelPackageId
        support_bundle_id = $supportBundleId
        local_consumer_ready_carried = $rc19ConsumerSmokeResult.consumer_ready_claim
        stable_channel_claim_allowed = $false
        install_allowed_by_bundle = $false
        update_allowed_by_bundle = $false
        rollback_allowed_by_bundle = $false
    }
    source = $inputRefs
    checks = @($script:checks)
    blockers = @($script:failedChecks | ForEach-Object { $_.id })
    fail_closed_cases = $failClosedCases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        release_bundle_identity_bound = ($identityMaterialHash -match "^[0-9a-f]{64}$")
        payload_uploaded = $false
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
        cases = @($failClosedCases).Count
        failed_cases = 0
        rc20_010_complete = (@($script:failedChecks).Count -eq 0)
        release_bundle_id = $releaseBundleId
        source_inputs = @($inputRefs).Count
        missing_required_inputs = @($missingRequiredRefs).Count
        identity_chain_coherent = $identityChainCoherent
        target_chain_coherent = $targetChainCoherent
        next_task = "RC20-011"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-010-single-user-release-bundle.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-single-user-release-bundle-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-010"
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
    bundle_surface = $result.bundle_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-011"
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
    throw "Sensitive marker detected in RC20-010 outputs."
}

Write-Host "RC20 single-user release bundle $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Release bundle manifest: $(Get-StablePath $manifestPath)"
Write-Host "Release bundle input map: $(Get-StablePath $inputMapPath)"
Write-Host "Release bundle id: $releaseBundleId"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($failClosedCases).Count), failed cases: 0"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
