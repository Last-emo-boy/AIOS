param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-package-descriptor-fail-closed",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$ReleasePackageResultPath = ".workflow/artifacts/rc16-release-package-artifact-set/result.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$InstallableMediaResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$CurrentPayloadPath = "image/out/agentos-initramfs.cpio.gz",
    [string]$InitramfsManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$AlphaRootfsManifestPath = "image/out/agentos-alpha-rootfs.manifest.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$ObjectChecksumsPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-checksums.json",
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

function Convert-JsonClone {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
}

function Has-Value {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }
    return $true
}

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

function Add-Reason {
    param(
        [System.Collections.Generic.List[string]]$Reasons,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    if (-not $Reasons.Contains($Reason)) {
        $Reasons.Add($Reason)
    }
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

function Test-OldDescriptorDate {
    param($Value)
    if (-not (Has-Value $Value)) {
        return $true
    }
    try {
        return ([DateTimeOffset]::Parse([string]$Value)) -lt [DateTimeOffset]::Parse("2026-06-01T00:00:00+08:00")
    } catch {
        return $true
    }
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
        if ($null -eq $value) {
            continue
        }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function Test-AuthorityBroadening {
    param($Documents)
    $broadeningFields = @(
        "install_allowed",
        "update_allowed",
        "activation_allowed",
        "rollback_execution_allowed",
        "support_upload_allowed",
        "recovery_execution_allowed",
        "remote_dispatch_enabled",
        "production_ring_mutation_allowed",
        "active_slot_mutation_allowed",
        "boot_metadata_mutation_allowed",
        "active_slot_mutated",
        "boot_metadata_mutated",
        "active_artifact_set_mutated",
        "signing_authority",
        "mirror_authority",
        "frontend_authority",
        "nginx_or_tls_authority",
        "signer_reachability_authority",
        "object_storage_ui_authority",
        "normal_shell_authority",
        "model_replay_authority",
        "tui_authority",
        "install_authority",
        "update_authority",
        "activation_authority",
        "rollback_execution_authority",
        "support_upload_authority",
        "recovery_execution_authority",
        "remote_dispatch_authority",
        "production_ring_mutation_authority"
    )
    foreach ($document in @($Documents)) {
        if ($null -eq $document) {
            continue
        }
        foreach ($field in $broadeningFields) {
            if ($document.PSObject.Properties.Name -contains $field -and $document.$field -eq $true) {
                return $true
            }
        }
    }
    return $false
}

function Invoke-PackageDescriptorEvaluation {
    param(
        [Parameter(Mandatory = $true)]$Package,
        [Parameter(Mandatory = $true)]$Media
    )
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($Package.schema -ne "agentos.rc16-release-package-artifact-set.v1") {
        Add-Reason $reasons "bad-package-descriptor-schema"
    }
    if ($Media.schema -ne "agentos.rc16-installable-media-manifest.v1") {
        Add-Reason $reasons "bad-installable-media-manifest-schema"
    }
    if ($Package.production_ready_claim -eq $true -or $Media.production_ready_claim -eq $true) {
        Add-Reason $reasons "production-ready-claim"
    }
    if (-not (Has-Value $Package.package_id)) {
        Add-Reason $reasons "missing-package-id"
    }
    if (-not (Has-Value $Package.release_id)) {
        Add-Reason $reasons "missing-release-id"
    }
    if ((Has-Value $Package.package_id) -and (Has-Value $Media.package_id) -and [string]$Package.package_id -ne [string]$Media.package_id) {
        Add-Reason $reasons "package-media-id-mismatch"
    }
    if ((Has-Value $Package.release_id) -and (Has-Value $Media.release_id) -and [string]$Package.release_id -ne [string]$Media.release_id) {
        Add-Reason $reasons "package-media-release-id-mismatch"
    }
    if (Test-OldDescriptorDate $Package.generated_at) {
        Add-Reason $reasons "stale-package-descriptor"
    }
    if (($Package.PSObject.Properties.Name -contains "package_scope" -and [string]$Package.package_scope -in @("*", "all", "all-releases")) -or
        ($Package.PSObject.Properties.Name -contains "target_release_pattern" -and [string]$Package.target_release_pattern -in @("*", "all", "all-releases"))) {
        Add-Reason $reasons "descriptor-scope-too-broad"
    }
    if ($Package.PSObject.Properties.Name -contains "duplicate_descriptor_entries" -and $Package.duplicate_descriptor_entries -eq $true) {
        Add-Reason $reasons "duplicate-package-descriptor-metadata"
    }
    if ($Package.PSObject.Properties.Name -contains "replay_nonce_seen" -and $Package.replay_nonce_seen -eq $true) {
        Add-Reason $reasons "replayed-package-descriptor"
    }

    $surface = $Package.package_surface
    if ($null -eq $surface) {
        Add-Reason $reasons "missing-package-surface"
    } else {
        if (-not (Has-Value $surface.current_payload_sha256)) {
            Add-Reason $reasons "missing-current-payload-sha256"
        } elseif ([string]$surface.current_payload_sha256 -ne $script:payloadSha256) {
            Add-Reason $reasons "current-payload-digest-mismatch"
        }
        if (-not (Has-Value $surface.current_payload_size_bytes) -or [int64]$surface.current_payload_size_bytes -le 0) {
            Add-Reason $reasons "missing-current-payload-size"
        } elseif ([int64]$surface.current_payload_size_bytes -gt 1073741824) {
            Add-Reason $reasons "oversized-payload-size"
        } elseif ([int64]$surface.current_payload_size_bytes -ne [int64]$script:payloadSize) {
            Add-Reason $reasons "payload-size-mismatch"
        }
        if ((Has-Value $surface.object_id) -and (Has-Value $surface.current_payload_sha256) -and [string]$surface.object_id -ne "sha256:$($surface.current_payload_sha256)") {
            Add-Reason $reasons "object-id-mismatch"
        }
        if (-not (Has-Value $surface.manifest_sha256)) {
            Add-Reason $reasons "missing-manifest-sha256"
        } elseif ([string]$surface.manifest_sha256 -ne $script:initramfsManifestSha256) {
            Add-Reason $reasons "manifest-digest-mismatch"
        }
        if (-not (Has-Value $surface.checksum_set_sha256)) {
            Add-Reason $reasons "missing-checksum-set-sha256"
        } elseif ([string]$surface.checksum_set_sha256 -ne $script:objectChecksumsSha256) {
            Add-Reason $reasons "checksum-set-digest-mismatch"
        }
        if (-not (Has-Value $surface.signature_target_sha256)) {
            Add-Reason $reasons "missing-signature-target-sha256"
        } elseif ([string]$surface.signature_target_sha256 -ne $script:descriptorSha256) {
            Add-Reason $reasons "signature-target-digest-mismatch"
        }
        if (-not (Has-Value $surface.revocation_snapshot_sha256)) {
            Add-Reason $reasons "missing-revocation-snapshot-sha256"
        } elseif ([string]$surface.revocation_snapshot_sha256 -ne $script:revocationSnapshotSha256) {
            Add-Reason $reasons "revocation-snapshot-digest-mismatch"
        }
        if (-not (Has-Value $surface.freshness_revocation_binding_sha256)) {
            Add-Reason $reasons "missing-freshness-revocation-binding-sha256"
        }
        if (-not (Has-Value $surface.compatibility_sha256)) {
            Add-Reason $reasons "missing-compatibility-sha256"
        } elseif ([string]$surface.compatibility_sha256 -ne $script:compatibilitySha256) {
            Add-Reason $reasons "compatibility-digest-mismatch"
        }
        if (-not (Has-Value $surface.rollback_baseline_sha256)) {
            Add-Reason $reasons "missing-rollback-baseline-sha256"
        } elseif ([string]$surface.rollback_baseline_sha256 -ne $script:rollbackBaselineSha256) {
            Add-Reason $reasons "rollback-baseline-digest-mismatch"
        }
        if (-not (Has-Value $surface.support_recovery_sha256)) {
            Add-Reason $reasons "missing-support-recovery-sha256"
        } elseif ([string]$surface.support_recovery_sha256 -ne $script:supportIndexSha256) {
            Add-Reason $reasons "support-recovery-digest-mismatch"
        }
        if ($surface.rc15_controlled_execution_ready -ne $true -and $surface.rc15_controlled_local_execution_ready -ne $true) {
            Add-Reason $reasons "rc15-source-evidence-missing"
        }
    }

    $signatureTarget = $Package.artifact_classes.signature_target
    if ($null -eq $signatureTarget -or $signatureTarget.public_signature_artifact.present -ne $true -or -not (Has-Value $signatureTarget.public_signature_artifact.sha256)) {
        Add-Reason $reasons "unsigned-package-descriptor"
    }
    if ($signatureTarget.signature_receipt.present -ne $true -or $signatureTarget.signature_receipt.sha256 -ne $script:signatureReceiptSha256) {
        Add-Reason $reasons "signature-receipt-missing-or-mismatched"
    }
    if ($signatureTarget.crypto_verified -ne $true) {
        Add-Reason $reasons "signature-receipt-not-crypto-verified"
    }

    $revocation = $Package.artifact_classes.revocation_and_freshness
    if ($null -eq $revocation) {
        Add-Reason $reasons "missing-revocation-freshness-section"
    } else {
        if ($revocation.revocation_status -ne "not-revoked") {
            Add-Reason $reasons "revoked-package-descriptor"
        }
        if ($revocation.freshness_window_bound -eq $true -and $revocation.freshness_window_current -ne $true) {
            Add-Reason $reasons "stale-freshness-window"
        }
    }

    $mediaPackage = $Media.source_release_package
    if ($null -eq $mediaPackage -or [string]$mediaPackage.artifact_set_sha256 -ne $script:releasePackageArtifactSetSha256) {
        Add-Reason $reasons "media-package-artifact-set-mismatch"
    }
    if ($Media.release_bytes.payload.sha256 -ne $script:payloadSha256) {
        Add-Reason $reasons "media-payload-digest-mismatch"
    }
    if ($Media.release_bytes.payload.size_bytes -ne $script:payloadSize) {
        Add-Reason $reasons "media-payload-size-mismatch"
    }
    if (-not (@($Media.architecture_and_compatibility.target_arch) -contains "x86_64")) {
        Add-Reason $reasons "unsupported-architecture"
    }
    if ($Media.architecture_and_compatibility.kernel_family -ne "linux-lts") {
        Add-Reason $reasons "unsupported-kernel-family"
    }
    if ($Media.verification_references.crypto_verified -ne $true) {
        Add-Reason $reasons "media-signature-not-crypto-verified"
    }
    if ($Media.install_update_gate.package_descriptor_fail_closed_required -ne $true) {
        Add-Reason $reasons "package-descriptor-fail-closed-gate-missing"
    }

    if ($Package.PSObject.Properties.Name -contains "endpoint_reachability_claimed" -and $Package.endpoint_reachability_claimed -eq $true) {
        Add-Reason $reasons "endpoint-reachability-is-not-authority"
    }
    if ($Package.PSObject.Properties.Name -contains "frontend_output_trusted" -and $Package.frontend_output_trusted -eq $true) {
        Add-Reason $reasons "frontend-output-is-not-authority"
    }
    if ($Package.PSObject.Properties.Name -contains "signer_reachability_claimed" -and $Package.signer_reachability_claimed -eq $true) {
        Add-Reason $reasons "signer-reachability-is-not-authority"
    }
    if ($Package.PSObject.Properties.Name -contains "shell_output_trusted" -and $Package.shell_output_trusted -eq $true) {
        Add-Reason $reasons "shell-output-is-not-authority"
    }
    if ($Package.PSObject.Properties.Name -contains "model_replay_claimed" -and $Package.model_replay_claimed -eq $true) {
        Add-Reason $reasons "model-replay-is-not-authority"
    }

    if (Test-AuthorityBroadening @(
        $Package,
        $Package.package_surface,
        $Package.authority,
        $Media,
        $Media.install_update_gate,
        $Media.authority,
        $Media.rollback_support
    )) {
        Add-Reason $reasons "authority-broadening"
    }

    return [ordered]@{
        observed_state = if ($reasons.Count -eq 0) { "package-descriptor-valid-non-authoritative" } else { "package-descriptor-denied" }
        observed_reasons = @($reasons)
        production_ready_claim = $false
        side_effects = [ordered]@{
            payload_upload_performed = $false
            payload_published = $false
            network_fetch_attempted = $false
            remote_payload_bytes_downloaded = $false
            install_performed = $false
            update_performed = $false
            activation_performed = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            cryptographic_signing_performed = $false
            production_ring_mutated = $false
        }
    }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons,
        [scriptblock]$Mutate
    )
    $package = Convert-JsonClone $script:baselinePackage
    $media = Convert-JsonClone $script:baselineMedia
    if ($null -ne $Mutate) {
        & $Mutate $package $media
    }
    $evaluation = Invoke-PackageDescriptorEvaluation -Package $package -Media $media
    $missing = @($ExpectedReasons | Where-Object { $_ -notin $evaluation.observed_reasons })
    $sideEffectsClear = (
        $evaluation.side_effects.payload_upload_performed -eq $false -and
        $evaluation.side_effects.payload_published -eq $false -and
        $evaluation.side_effects.network_fetch_attempted -eq $false -and
        $evaluation.side_effects.remote_payload_bytes_downloaded -eq $false -and
        $evaluation.side_effects.install_performed -eq $false -and
        $evaluation.side_effects.update_performed -eq $false -and
        $evaluation.side_effects.activation_performed -eq $false -and
        $evaluation.side_effects.active_slot_mutated -eq $false -and
        $evaluation.side_effects.boot_metadata_mutated -eq $false -and
        $evaluation.side_effects.rollback_execution_performed -eq $false -and
        $evaluation.side_effects.support_upload_performed -eq $false -and
        $evaluation.side_effects.recovery_execution_performed -eq $false -and
        $evaluation.side_effects.remote_dispatch_enabled -eq $false -and
        $evaluation.side_effects.cryptographic_signing_performed -eq $false -and
        $evaluation.side_effects.production_ring_mutated -eq $false
    )
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0 -and $evaluation.observed_state -eq "package-descriptor-denied" -and $sideEffectsClear -and $evaluation.production_ready_claim -eq $false) { "passed" } else { "failed" }
        expected_reasons = $ExpectedReasons
        missing_expected_reasons = $missing
        observed_state = $evaluation.observed_state
        observed_reasons = $evaluation.observed_reasons
        production_ready_claim = $evaluation.production_ready_claim
        side_effects = $evaluation.side_effects
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
$resolvedReleasePackageResultPath = Resolve-RepoPath $ReleasePackageResultPath
$resolvedReleasePackageArtifactSetPath = Resolve-RepoPath $ReleasePackageArtifactSetPath
$resolvedInstallableMediaResultPath = Resolve-RepoPath $InstallableMediaResultPath
$resolvedInstallableMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedCurrentPayloadPath = Resolve-RepoPath $CurrentPayloadPath
$resolvedInitramfsManifestPath = Resolve-RepoPath $InitramfsManifestPath
$resolvedAlphaRootfsManifestPath = Resolve-RepoPath $AlphaRootfsManifestPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedObjectChecksumsPath = Resolve-RepoPath $ObjectChecksumsPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releasePackageResult = Read-Json $resolvedReleasePackageResultPath
$script:baselinePackage = Read-Json $resolvedReleasePackageArtifactSetPath
$installableMediaResult = Read-Json $resolvedInstallableMediaResultPath
$script:baselineMedia = Read-Json $resolvedInstallableMediaManifestPath
$initramfsManifest = Read-Json $resolvedInitramfsManifestPath
$alphaRootfsManifest = Read-Json $resolvedAlphaRootfsManifestPath
$descriptor = Read-Json $resolvedDescriptorPath
$objectChecksums = Read-Json $resolvedObjectChecksumsPath

$rc16PreviousStatus = Get-TaskStatus $plan "RC16-011"
$rc16TaskStatus = Get-TaskStatus $plan "RC16-012"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-012" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-020" -and $rc16TaskStatus -eq "completed")
    )
)

$script:payloadSha256 = Get-FileSha256 $resolvedCurrentPayloadPath
$script:payloadSize = if (Test-Path -LiteralPath $resolvedCurrentPayloadPath -PathType Leaf) { (Get-Item -LiteralPath $resolvedCurrentPayloadPath).Length } else { $null }
$script:initramfsManifestSha256 = Get-FileSha256 $resolvedInitramfsManifestPath
$script:alphaRootfsManifestSha256 = Get-FileSha256 $resolvedAlphaRootfsManifestPath
$script:descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$script:objectChecksumsSha256 = Get-FileSha256 $resolvedObjectChecksumsPath
$script:releasePackageArtifactSetSha256 = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
$script:installableMediaManifestSha256 = Get-FileSha256 $resolvedInstallableMediaManifestPath
$script:signatureReceiptSha256 = $script:baselinePackage.artifact_classes.signature_target.signature_receipt.sha256
$script:revocationSnapshotSha256 = $script:baselinePackage.package_surface.revocation_snapshot_sha256
$script:compatibilitySha256 = $script:baselinePackage.package_surface.compatibility_sha256
$script:rollbackBaselineSha256 = $script:baselinePackage.package_surface.rollback_baseline_sha256
$script:supportIndexSha256 = $script:baselinePackage.package_surface.support_recovery_sha256

$source = [ordered]@{
    rc16_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc16_contract = New-ArtifactRef $resolvedContractPath
    rc16_release_package_result = New-ArtifactRef $resolvedReleasePackageResultPath $releasePackageResult
    rc16_release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $script:baselinePackage
    rc16_installable_media_result = New-ArtifactRef $resolvedInstallableMediaResultPath $installableMediaResult
    rc16_installable_media_manifest = New-ArtifactRef $resolvedInstallableMediaManifestPath $script:baselineMedia
    current_payload_bytes = New-ArtifactRef $resolvedCurrentPayloadPath
    initramfs_manifest = New-ArtifactRef $resolvedInitramfsManifestPath $initramfsManifest
    alpha_rootfs_manifest = New-ArtifactRef $resolvedAlphaRootfsManifestPath $alphaRootfsManifest
    payload_descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    object_checksums = New-ArtifactRef $resolvedObjectChecksumsPath $objectChecksums
}

Add-Check "plan.current_task.rc16_012" $planAllowsRun "RC16-012 must run after RC16-011 completes and while the plan pointer is at RC16-012, or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_011_status = $rc16PreviousStatus; rc16_012_status = $rc16TaskStatus })
Add-Check "contract.fail_closed_cases.present" ($contractText.Contains("Required Fail-Closed Cases") -and $contractText.Contains("Missing, stale, mismatched, unsigned, revoked, broad, duplicate, or replayed package descriptor metadata")) "RC16-012 must consume the RC16 package descriptor fail-closed contract." $source.rc16_contract
Add-Check "source.rc16_010.result" ($releasePackageResult.status -eq "passed" -and $releasePackageResult.summary.failed_checks -eq 0 -and $releasePackageResult.summary.rc16_010_complete -eq $true) "RC16-010 release package artifact set must pass before descriptor fail-closed fixtures." $releasePackageResult.summary
Add-Check "source.rc16_011.result" ($installableMediaResult.status -eq "passed" -and $installableMediaResult.summary.failed_checks -eq 0 -and $installableMediaResult.summary.rc16_011_complete -eq $true) "RC16-011 installable media manifest must pass before descriptor fail-closed fixtures." $installableMediaResult.summary

$baselineEvaluation = Invoke-PackageDescriptorEvaluation -Package $script:baselinePackage -Media $script:baselineMedia
Add-Check "baseline.descriptor.valid_non_authoritative" ($baselineEvaluation.observed_state -eq "package-descriptor-valid-non-authoritative" -and $script:baselinePackage.package_surface.install_allowed -eq $false -and $script:baselineMedia.install_update_gate.install_allowed -eq $false) "Baseline RC16 package descriptor must be internally valid while still non-authoritative for install/update effects." ([ordered]@{ state = $baselineEvaluation.observed_state; reasons = $baselineEvaluation.observed_reasons; install_allowed = $script:baselinePackage.package_surface.install_allowed; media_install_allowed = $script:baselineMedia.install_update_gate.install_allowed })

$cases = @()
$cases += Invoke-Case "stale.package_descriptor" @("stale-package-descriptor") { param($p,$m) $p.generated_at = "2020-01-01T00:00:00+00:00" }
$cases += Invoke-Case "broad.release_scope" @("descriptor-scope-too-broad") { param($p,$m) Set-JsonProperty $p "package_scope" "*" }
$cases += Invoke-Case "missing.package_id" @("missing-package-id") { param($p,$m) $p.package_id = $null }
$cases += Invoke-Case "mismatched.package_media_id" @("package-media-id-mismatch") { param($p,$m) $m.package_id = "different-package" }
$cases += Invoke-Case "missing.payload_digest" @("missing-current-payload-sha256") { param($p,$m) $p.package_surface.current_payload_sha256 = $null }
$cases += Invoke-Case "mismatched.payload_digest" @("current-payload-digest-mismatch", "object-id-mismatch") { param($p,$m) $p.package_surface.current_payload_sha256 = "0000" }
$cases += Invoke-Case "oversized.payload_size" @("oversized-payload-size") { param($p,$m) $p.package_surface.current_payload_size_bytes = 1099511627776 }
$cases += Invoke-Case "missing.manifest_digest" @("missing-manifest-sha256") { param($p,$m) $p.package_surface.manifest_sha256 = $null }
$cases += Invoke-Case "mismatched.manifest_digest" @("manifest-digest-mismatch") { param($p,$m) $p.package_surface.manifest_sha256 = "0000" }
$cases += Invoke-Case "mismatched.checksum_set" @("checksum-set-digest-mismatch") { param($p,$m) $p.package_surface.checksum_set_sha256 = "0000" }
$cases += Invoke-Case "unsigned.signature_artifact_missing" @("unsigned-package-descriptor") { param($p,$m) $p.artifact_classes.signature_target.public_signature_artifact.present = $false; $p.artifact_classes.signature_target.public_signature_artifact.sha256 = $null }
$cases += Invoke-Case "unsigned.signature_receipt_not_verified" @("signature-receipt-not-crypto-verified") { param($p,$m) $p.artifact_classes.signature_target.crypto_verified = $false }
$cases += Invoke-Case "revoked.package_metadata" @("revoked-package-descriptor") { param($p,$m) $p.artifact_classes.revocation_and_freshness.revocation_status = "revoked" }
$cases += Invoke-Case "stale.freshness_window" @("stale-freshness-window") { param($p,$m) $p.artifact_classes.revocation_and_freshness.freshness_window_bound = $true; $p.artifact_classes.revocation_and_freshness.freshness_window_current = $false }
$cases += Invoke-Case "missing.compatibility" @("missing-compatibility-sha256") { param($p,$m) $p.package_surface.compatibility_sha256 = $null }
$cases += Invoke-Case "missing.rollback_baseline" @("missing-rollback-baseline-sha256") { param($p,$m) $p.package_surface.rollback_baseline_sha256 = $null }
$cases += Invoke-Case "missing.support_recovery" @("missing-support-recovery-sha256") { param($p,$m) $p.package_surface.support_recovery_sha256 = $null }
$cases += Invoke-Case "missing.rc15_source_evidence" @("rc15-source-evidence-missing") { param($p,$m) $p.package_surface.rc15_controlled_execution_ready = $false }
$cases += Invoke-Case "mismatched.media_payload" @("media-payload-digest-mismatch") { param($p,$m) $m.release_bytes.payload.sha256 = "0000" }
$cases += Invoke-Case "unsupported.media_architecture" @("unsupported-architecture") { param($p,$m) $m.architecture_and_compatibility.target_arch = @("arm64") }
$cases += Invoke-Case "authority.install_allowed" @("authority-broadening") { param($p,$m) $p.package_surface.install_allowed = $true }
$cases += Invoke-Case "authority.update_allowed" @("authority-broadening") { param($p,$m) $m.install_update_gate.update_allowed = $true }
$cases += Invoke-Case "authority.activation_allowed" @("authority-broadening") { param($p,$m) $p.package_surface.activation_allowed = $true }
$cases += Invoke-Case "authority.remote_dispatch" @("authority-broadening") { param($p,$m) $m.authority.remote_dispatch_authority = $true }
$cases += Invoke-Case "claim.production_ready" @("production-ready-claim") { param($p,$m) $p.production_ready_claim = $true }
$cases += Invoke-Case "duplicate.descriptor_metadata" @("duplicate-package-descriptor-metadata") { param($p,$m) Set-JsonProperty $p "duplicate_descriptor_entries" $true }
$cases += Invoke-Case "replayed.descriptor_metadata" @("replayed-package-descriptor") { param($p,$m) Set-JsonProperty $p "replay_nonce_seen" $true }
$cases += Invoke-Case "surface.endpoint_reachability" @("endpoint-reachability-is-not-authority") { param($p,$m) Set-JsonProperty $p "endpoint_reachability_claimed" $true }
$cases += Invoke-Case "surface.frontend_output" @("frontend-output-is-not-authority") { param($p,$m) Set-JsonProperty $p "frontend_output_trusted" $true }
$cases += Invoke-Case "surface.signer_reachability" @("signer-reachability-is-not-authority") { param($p,$m) Set-JsonProperty $p "signer_reachability_claimed" $true }
$cases += Invoke-Case "surface.shell_output" @("shell-output-is-not-authority") { param($p,$m) Set-JsonProperty $p "shell_output_trusted" $true }
$cases += Invoke-Case "surface.model_replay" @("model-replay-is-not-authority") { param($p,$m) Set-JsonProperty $p "model_replay_claimed" $true }
$cases += Invoke-Case "surface.object_storage_ui_authority" @("authority-broadening") { param($p,$m) $p.authority.object_storage_ui_authority = $true }

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "fixtures.all_cases_passed" ($failedCases.Count -eq 0) "All RC16 package descriptor negative fixtures must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = $failedCases.Count })
Add-Check "fixtures.no_side_effects" (@($cases | Where-Object {
    $_.side_effects.payload_upload_performed -or
    $_.side_effects.payload_published -or
    $_.side_effects.network_fetch_attempted -or
    $_.side_effects.remote_payload_bytes_downloaded -or
    $_.side_effects.install_performed -or
    $_.side_effects.update_performed -or
    $_.side_effects.activation_performed -or
    $_.side_effects.active_slot_mutated -or
    $_.side_effects.boot_metadata_mutated -or
    $_.side_effects.rollback_execution_performed -or
    $_.side_effects.support_upload_performed -or
    $_.side_effects.recovery_execution_performed -or
    $_.side_effects.remote_dispatch_enabled -or
    $_.side_effects.cryptographic_signing_performed -or
    $_.side_effects.production_ring_mutated
}).Count -eq 0) "Fixtures must not upload, publish, fetch, install, update, activate, mutate boot/slot state, rollback, upload support, recover, dispatch, sign, or mutate production rings." $null

$matrixPath = Join-Path $resolvedArtifactDir "package-descriptor-fail-closed-matrix.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-012-package-descriptor-fail-closed.json"

$matrix = [ordered]@{
    schema = "agentos.rc16-package-descriptor-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC16-012"
    package_id = [string]$script:baselinePackage.package_id
    release_id = [string]$script:baselinePackage.release_id
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    baseline = [ordered]@{
        observed_state = $baselineEvaluation.observed_state
        observed_reasons = $baselineEvaluation.observed_reasons
        install_allowed = $script:baselinePackage.package_surface.install_allowed
        update_allowed = $script:baselinePackage.package_surface.update_allowed
        activation_allowed = $script:baselinePackage.package_surface.activation_allowed
    }
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = @($failedCases).Count
        failed_case_ids = @($failedCases | ForEach-Object { $_.id })
    }
}
Write-Json $matrix $matrixPath

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc16-package-descriptor-fail-closed-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-012"
    status = $resultStatus
    production_ready_claim = $false
    package_id = [string]$script:baselinePackage.package_id
    release_id = [string]$script:baselinePackage.release_id
    descriptor_surface = [ordered]@{
        state = "package-descriptor-fail-closed-fixtures-passed-install-update-still-gated"
        matrix_sha256 = Get-FileSha256 $matrixPath
        release_package_artifact_set_sha256 = $script:releasePackageArtifactSetSha256
        installable_media_manifest_sha256 = $script:installableMediaManifestSha256
        current_payload_sha256 = $script:payloadSha256
        current_payload_size_bytes = $script:payloadSize
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        active_slot_mutation_allowed = $false
        boot_metadata_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
    }
    outputs = [ordered]@{
        package_descriptor_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
        }
    }
    source = $source
    checks = $script:checks
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
        signer_reachability_authority = $false
        shell_output_authority = $false
        model_replay_authority = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        payload_published = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        frontend_authority = $false
        mirror_authority = $false
        object_storage_ui_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    blockers = @(
        "rc16-installer-updater-preflight-not-bound",
        "rc16-install-update-planspec-not-bound",
        "rc16-rollback-support-package-not-bound",
        "rc16-local-release-channel-consumer-smoke-not-run"
    )
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = @($failedCases).Count
        rc16_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-020"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-package-descriptor-fail-closed-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-012"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    descriptor_surface = $result.descriptor_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-020"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)) "RC16-012 outputs must not contain key blocks, private key paths, auth tokens, or public identity strings." $null

if (@($script:failedChecks).Count -gt 0 -and $result.status -eq "passed") {
    $result.status = "failed"
    $result.summary.failed_checks = @($script:failedChecks).Count
    $result.checks = $script:checks
    Write-Json $result $resultPath
}

Write-Host "RC16 package descriptor fail-closed $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Matrix: $(Get-StablePath $matrixPath)"
Write-Host "Cases: $(@($cases).Count), failed cases: $($failedCases.Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
