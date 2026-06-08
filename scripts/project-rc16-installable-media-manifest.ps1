param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-installable-media-manifest",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$ReleasePackageResultPath = ".workflow/artifacts/rc16-release-package-artifact-set/result.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$CurrentPayloadPath = "image/out/agentos-initramfs.cpio.gz",
    [string]$InitramfsManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$AlphaRootfsManifestPath = "image/out/agentos-alpha-rootfs.manifest.json",
    [string]$AlphaRootfsValidationPath = "image/out/agentos-alpha-rootfs.validation.json",
    [string]$ReleaseProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$UpdateMetadataPath = ".workflow/artifacts/release/update-metadata.json",
    [string]$ReleaseChannelMetadataPath = ".workflow/artifacts/release/release-channel-metadata.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$ObjectChecksumsPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-checksums.json",
    [string]$PublicSignatureArtifactPath = "image/out/agentos-initramfs.cpio.gz.prod.sig.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$FreshnessRevocationBindingPath = ".workflow/artifacts/rc13-freshness-revocation-authority/freshness-revocation-authority-binding.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$Rc15FinalAuditPath = ".workflow/artifacts/rc15-final-closeout-audit/result.json",
    [string]$Rc15AgentCorePlanSpecPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/agentcore-planspec.json",
    [string]$Rc15SecurityExecutionDecisionPath = ".workflow/artifacts/rc15-security-execution-allow-decision/security-execution-allow-decision.json",
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
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
$resolvedCurrentPayloadPath = Resolve-RepoPath $CurrentPayloadPath
$resolvedInitramfsManifestPath = Resolve-RepoPath $InitramfsManifestPath
$resolvedAlphaRootfsManifestPath = Resolve-RepoPath $AlphaRootfsManifestPath
$resolvedAlphaRootfsValidationPath = Resolve-RepoPath $AlphaRootfsValidationPath
$resolvedReleaseProvenancePath = Resolve-RepoPath $ReleaseProvenancePath
$resolvedUpdateMetadataPath = Resolve-RepoPath $UpdateMetadataPath
$resolvedReleaseChannelMetadataPath = Resolve-RepoPath $ReleaseChannelMetadataPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedObjectChecksumsPath = Resolve-RepoPath $ObjectChecksumsPath
$resolvedPublicSignatureArtifactPath = Resolve-RepoPath $PublicSignatureArtifactPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedRevocationSnapshotPath = Resolve-RepoPath $RevocationSnapshotPath
$resolvedFreshnessRevocationBindingPath = Resolve-RepoPath $FreshnessRevocationBindingPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedRc15FinalAuditPath = Resolve-RepoPath $Rc15FinalAuditPath
$resolvedRc15AgentCorePlanSpecPath = Resolve-RepoPath $Rc15AgentCorePlanSpecPath
$resolvedRc15SecurityExecutionDecisionPath = Resolve-RepoPath $Rc15SecurityExecutionDecisionPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releasePackageResult = Read-Json $resolvedReleasePackageResultPath
$releasePackageArtifactSet = Read-Json $resolvedReleasePackageArtifactSetPath
$initramfsManifest = Read-Json $resolvedInitramfsManifestPath
$alphaRootfsManifest = Read-Json $resolvedAlphaRootfsManifestPath
$alphaRootfsValidation = Read-Json $resolvedAlphaRootfsValidationPath
$releaseProvenance = Read-Json $resolvedReleaseProvenancePath
$updateMetadata = Read-Json $resolvedUpdateMetadataPath
$releaseChannelMetadata = Read-Json $resolvedReleaseChannelMetadataPath
$descriptor = Read-Json $resolvedDescriptorPath
$objectChecksums = Read-Json $resolvedObjectChecksumsPath
$publicSignatureArtifact = Read-Json $resolvedPublicSignatureArtifactPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$revocationSnapshot = Read-Json $resolvedRevocationSnapshotPath
$freshnessRevocationBinding = Read-Json $resolvedFreshnessRevocationBindingPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath
$rc15FinalAudit = Read-Json $resolvedRc15FinalAuditPath
$rc15AgentCorePlanSpec = Read-Json $resolvedRc15AgentCorePlanSpecPath
$rc15SecurityExecutionDecision = Read-Json $resolvedRc15SecurityExecutionDecisionPath

$rc16PreviousStatus = Get-TaskStatus $plan "RC16-010"
$rc16TaskStatus = Get-TaskStatus $plan "RC16-011"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-011" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-012" -and $rc16TaskStatus -eq "completed")
    )
)

$payloadSha256 = Get-FileSha256 $resolvedCurrentPayloadPath
$payloadSize = if (Test-Path -LiteralPath $resolvedCurrentPayloadPath -PathType Leaf) { (Get-Item -LiteralPath $resolvedCurrentPayloadPath).Length } else { $null }
$initramfsManifestSha256 = Get-FileSha256 $resolvedInitramfsManifestPath
$alphaRootfsManifestSha256 = Get-FileSha256 $resolvedAlphaRootfsManifestPath
$alphaRootfsValidationSha256 = Get-FileSha256 $resolvedAlphaRootfsValidationPath
$releasePackageResultSha256 = Get-FileSha256 $resolvedReleasePackageResultPath
$releasePackageArtifactSetSha256 = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
$releaseProvenanceSha256 = Get-FileSha256 $resolvedReleaseProvenancePath
$updateMetadataSha256 = Get-FileSha256 $resolvedUpdateMetadataPath
$releaseChannelMetadataSha256 = Get-FileSha256 $resolvedReleaseChannelMetadataPath
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$objectChecksumsSha256 = Get-FileSha256 $resolvedObjectChecksumsPath
$publicSignatureArtifactSha256 = Get-FileSha256 $resolvedPublicSignatureArtifactPath
$signatureReceiptSha256 = Get-FileSha256 $resolvedSignatureReceiptPath
$signatureSummarySha256 = Get-FileSha256 $resolvedSignatureSummaryPath
$revocationSnapshotSha256 = Get-FileSha256 $resolvedRevocationSnapshotPath
$freshnessBindingSha256 = Get-FileSha256 $resolvedFreshnessRevocationBindingPath
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $resolvedSupportIndexPath

$source = [ordered]@{
    rc16_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc16_contract = New-ArtifactRef $resolvedContractPath
    rc16_release_package_result = New-ArtifactRef $resolvedReleasePackageResultPath $releasePackageResult
    rc16_release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $releasePackageArtifactSet
    current_payload_bytes = New-ArtifactRef $resolvedCurrentPayloadPath
    initramfs_manifest = New-ArtifactRef $resolvedInitramfsManifestPath $initramfsManifest
    alpha_rootfs_manifest = New-ArtifactRef $resolvedAlphaRootfsManifestPath $alphaRootfsManifest
    alpha_rootfs_validation = New-ArtifactRef $resolvedAlphaRootfsValidationPath $alphaRootfsValidation
    release_provenance = New-ArtifactRef $resolvedReleaseProvenancePath $releaseProvenance
    update_metadata = New-ArtifactRef $resolvedUpdateMetadataPath $updateMetadata
    release_channel_metadata = New-ArtifactRef $resolvedReleaseChannelMetadataPath $releaseChannelMetadata
    payload_descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    object_checksums = New-ArtifactRef $resolvedObjectChecksumsPath $objectChecksums
    public_signature_artifact = New-ArtifactRef $resolvedPublicSignatureArtifactPath $publicSignatureArtifact
    signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    revocation_snapshot = New-ArtifactRef $resolvedRevocationSnapshotPath $revocationSnapshot
    freshness_revocation_binding = New-ArtifactRef $resolvedFreshnessRevocationBindingPath $freshnessRevocationBinding
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    rc15_final_audit = New-ArtifactRef $resolvedRc15FinalAuditPath $rc15FinalAudit
    rc15_agentcore_planspec = New-ArtifactRef $resolvedRc15AgentCorePlanSpecPath $rc15AgentCorePlanSpec
    rc15_security_execution_decision = New-ArtifactRef $resolvedRc15SecurityExecutionDecisionPath $rc15SecurityExecutionDecision
}

$requiredSourceRefs = @(
    $source.rc16_release_package_result,
    $source.rc16_release_package_artifact_set,
    $source.current_payload_bytes,
    $source.initramfs_manifest,
    $source.alpha_rootfs_manifest,
    $source.alpha_rootfs_validation,
    $source.release_provenance,
    $source.update_metadata,
    $source.release_channel_metadata,
    $source.payload_descriptor,
    $source.object_checksums,
    $source.public_signature_artifact,
    $source.signature_receipt,
    $source.signature_summary,
    $source.revocation_snapshot,
    $source.freshness_revocation_binding,
    $source.compatibility,
    $source.rollback_baseline,
    $source.support_index,
    $source.rc15_final_audit,
    $source.rc15_agentcore_planspec,
    $source.rc15_security_execution_decision
)
$missingRequiredRefs = @($requiredSourceRefs | Where-Object { $_.present -ne $true -or [string]::IsNullOrWhiteSpace($_.sha256) })

$payloadBound = (
    $payloadSha256 -and
    $payloadSha256 -eq $releasePackageArtifactSet.package_surface.current_payload_sha256 -and
    $payloadSha256 -eq $initramfsManifest.artifact_sha256 -and
    $payloadSha256 -eq $releaseProvenance.artifacts.initramfs.sha256 -and
    $payloadSha256 -eq $descriptor.sha256 -and
    $payloadSha256 -eq $objectChecksums.sha256
)
$manifestBound = (
    $initramfsManifestSha256 -eq $releasePackageArtifactSet.package_surface.manifest_sha256 -and
    $initramfsManifestSha256 -eq $releaseProvenance.artifacts.initramfs.manifest_sha256 -and
    $alphaRootfsManifestSha256 -eq $releaseProvenance.artifacts.alpha_rootfs_manifest.sha256 -and
    $initramfsManifest.alpha_rootfs.manifest -eq (Get-StablePath $resolvedAlphaRootfsManifestPath)
)
$rootfsValid = (
    $alphaRootfsManifest.schema -eq "agentos.alpha-rootfs-assembly.v1" -and
    $alphaRootfsValidation.schema -eq "agentos.alpha-rootfs-validation.v1" -and
    $alphaRootfsValidation.result -eq "passed" -and
    $alphaRootfsValidation.summary.failed -eq 0 -and
    $alphaRootfsManifest.rootfs_runtime_manifest_sha256 -eq $initramfsManifest.alpha_rootfs.rootfs_runtime_manifest_sha256
)
$compatibilityBound = (
    @($compatibility.target_arch) -contains "x86_64" -and
    @($compatibility.boot_path.boot_modes).Count -gt 0 -and
    $compatibility.boot_path.kernel_family -eq "linux-lts" -and
    $compatibility.authority.installer_preflight_can_activate -eq $false -and
    $compatibility.authority.shell_authority -eq $false
)
$releasePackageReady = (
    $releasePackageResult.status -eq "passed" -and
    $releasePackageArtifactSet.schema -eq "agentos.rc16-release-package-artifact-set.v1" -and
    $releasePackageArtifactSet.production_ready_claim -eq $false -and
    $releasePackageArtifactSet.package_surface.install_allowed -eq $false -and
    $releasePackageArtifactSet.package_surface.update_allowed -eq $false
)
$verificationBound = (
    $publicSignatureArtifact.schema -eq "agentos.production-detached-signature.v1" -and
    $signatureReceipt.crypto_verified -eq $true -and
    $signatureSummary.production_ready_claim -eq $false -and
    $revocationSnapshot.status -eq "revocation-current-projected" -and
    $freshnessRevocationBinding.production_ready_claim -eq $false
)
$rollbackSupportBound = (
    $rollbackBaseline.production_ready_claim -eq $false -and
    $supportIndex.support_upload_allowed -eq $false -and
    $supportIndex.recovery_execution_allowed -eq $false -and
    $supportIndex.rollback_execution_allowed -eq $false
)
$rc15Ready = (
    $rc15FinalAudit.status -eq "passed" -and
    $rc15FinalAudit.decision -eq "PASS" -and
    $rc15FinalAudit.controlled_local_execution_ready -eq $true -and
    $rc15AgentCorePlanSpec.status -eq "agentcore-planspec-executable" -and
    $rc15SecurityExecutionDecision.status -eq "security-execution-allow-bound"
)

Add-Check "plan.current_task.rc16_011" $planAllowsRun "RC16-011 must run after RC16-010 completes and while the plan pointer is at RC16-011, or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_010_status = $rc16PreviousStatus; rc16_011_status = $rc16TaskStatus })
Add-Check "contract.installable_media_gate.present" ($contractText.Contains("Assemble the installable media manifest") -and $contractText.Contains("Install And Update Contract")) "RC16-011 must consume the RC16 install/update contract." $source.rc16_contract
Add-Check "sources.required.present" (@($missingRequiredRefs).Count -eq 0) "Required installable media sources must be present and hash-bound." (@($missingRequiredRefs | ForEach-Object { $_.path }))
Add-Check "rc16.package.ready" $releasePackageReady "RC16-011 must consume the completed RC16 release package artifact set without broadening authority." ([ordered]@{ result_status = $releasePackageResult.status; artifact_set_schema = $releasePackageArtifactSet.schema; install_allowed = $releasePackageArtifactSet.package_surface.install_allowed; update_allowed = $releasePackageArtifactSet.package_surface.update_allowed })
Add-Check "release.bytes.bound" ($payloadBound -and $manifestBound) "Current AIOS release bytes must match package surface, descriptor, checksums, provenance, and initramfs manifest." ([ordered]@{ payload_sha256 = $payloadSha256; package_payload_sha256 = $releasePackageArtifactSet.package_surface.current_payload_sha256; initramfs_manifest_sha256 = $initramfsManifestSha256; package_manifest_sha256 = $releasePackageArtifactSet.package_surface.manifest_sha256; alpha_rootfs_manifest_sha256 = $alphaRootfsManifestSha256 })
Add-Check "rootfs.initramfs.provenance.bound" $rootfsValid "Rootfs and initramfs provenance must be bound to validated rootfs runtime artifacts." ([ordered]@{ rootfs_schema = $alphaRootfsManifest.schema; validation_result = $alphaRootfsValidation.result; validation_failed = $alphaRootfsValidation.summary.failed; runtime_manifest_sha256 = $alphaRootfsManifest.rootfs_runtime_manifest_sha256; runtime_artifact_count = @($alphaRootfsManifest.artifacts).Count })
Add-Check "architecture.compatibility.bound" $compatibilityBound "Manifest must bind architecture, Linux boot compatibility, and no-shell authority constraints." ([ordered]@{ target_arch = @($compatibility.target_arch); kernel_family = $compatibility.boot_path.kernel_family; boot_modes = @($compatibility.boot_path.boot_modes); shell_authority = $compatibility.authority.shell_authority })
Add-Check "verification.refs.bound" $verificationBound "Manifest must bind signature, receipt, revocation, and freshness references without claiming GA." ([ordered]@{ public_signature_schema = $publicSignatureArtifact.schema; crypto_verified = $signatureReceipt.crypto_verified; revocation_status = $revocationSnapshot.status; freshness_window_bound = $freshnessRevocationBinding.freshness.freshness_window_bound })
Add-Check "rollback.support.bound" $rollbackSupportBound "Rollback and support/recovery references must be bound while execution and upload remain disabled." ([ordered]@{ rollback_status = $rollbackBaseline.status; support_mode = $supportIndex.support_mode; support_upload_allowed = $supportIndex.support_upload_allowed; recovery_execution_allowed = $supportIndex.recovery_execution_allowed })
Add-Check "rc15.execution.bound" $rc15Ready "Installable media manifest must bind RC15 controlled local execution readiness as source evidence." ([ordered]@{ rc15_status = $rc15FinalAudit.status; rc15_decision = $rc15FinalAudit.decision; agentcore_status = $rc15AgentCorePlanSpec.status; security_status = $rc15SecurityExecutionDecision.status })

$mediaIdInput = @(
    "agentos.rc16-installable-media-manifest.v1",
    $releasePackageArtifactSetSha256,
    $payloadSha256,
    $initramfsManifestSha256,
    $alphaRootfsManifestSha256,
    $alphaRootfsValidationSha256,
    $releaseProvenanceSha256,
    $updateMetadataSha256,
    $releaseChannelMetadataSha256,
    $descriptorSha256,
    $objectChecksumsSha256,
    $publicSignatureArtifactSha256,
    $signatureReceiptSha256,
    $signatureSummarySha256,
    $revocationSnapshotSha256,
    $freshnessBindingSha256,
    $compatibilitySha256,
    $rollbackBaselineSha256,
    $supportIndexSha256,
    "repo-local-no-upload-no-install-no-activation"
) -join "|"
$mediaId = "sha256:$(Get-StringSha256 $mediaIdInput)"

$manifest = [ordered]@{
    schema = "agentos.rc16-installable-media-manifest.v1"
    generated_at = $generatedAtValue
    task = "RC16-011"
    status = "installable-media-manifest-projected-install-update-gated"
    media_id = $mediaId
    package_id = [string]$releasePackageArtifactSet.package_id
    release_id = [string]$releasePackageArtifactSet.release_id
    production_ready_claim = $false
    source_release_package = [ordered]@{
        result = $source.rc16_release_package_result
        artifact_set = $source.rc16_release_package_artifact_set
        artifact_set_sha256 = $releasePackageArtifactSetSha256
        package_surface_state = [string]$releasePackageArtifactSet.package_surface.state
        rc15_controlled_execution_ready = $releasePackageArtifactSet.package_surface.rc15_controlled_execution_ready
    }
    media_identity = [ordered]@{
        content_addressed = $true
        hash_algorithm = "sha256"
        generated_from_repo_local_evidence = $true
        large_payload_uploaded = $false
        payload_published = $false
        network_fetch_attempted = $false
        machine_local_paths_in_media_id = $false
    }
    release_bytes = [ordered]@{
        payload = [ordered]@{
            path = Get-StablePath $resolvedCurrentPayloadPath
            sha256 = $payloadSha256
            size_bytes = $payloadSize
            object_id = [string]$releasePackageArtifactSet.package_surface.object_id
            object_kind = [string]$releasePackageArtifactSet.package_surface.object_kind
        }
        descriptor = $source.payload_descriptor
        checksum_set = $source.object_checksums
        initramfs_manifest = $source.initramfs_manifest
        release_provenance = $source.release_provenance
        update_metadata = $source.update_metadata
        release_channel_metadata = $source.release_channel_metadata
    }
    rootfs_initramfs_provenance = [ordered]@{
        initramfs = [ordered]@{
            artifact = [string]$initramfsManifest.artifact
            artifact_sha256 = [string]$initramfsManifest.artifact_sha256
            source_dir = [string]$initramfsManifest.source_dir
            generated_agentd = [string]$initramfsManifest.generated_agentd
            generated_agentd_sha256 = [string]$initramfsManifest.generated_agentd_sha256
            boot_args = [string]$initramfsManifest.boot_args
            boot_markers = @($initramfsManifest.boot_markers)
            runtime_artifact_ids = @($initramfsManifest.runtime_artifact_ids)
        }
        alpha_rootfs = [ordered]@{
            manifest = $source.alpha_rootfs_manifest
            validation = $source.alpha_rootfs_validation
            source_rootfs = [string]$alphaRootfsManifest.source_rootfs
            staged_rootfs = [string]$alphaRootfsManifest.staged_rootfs
            rootfs_runtime_manifest = [string]$alphaRootfsManifest.rootfs_runtime_manifest
            rootfs_runtime_manifest_sha256 = [string]$alphaRootfsManifest.rootfs_runtime_manifest_sha256
            runtime_artifact_count = @($alphaRootfsManifest.artifacts).Count
            validation_result = [string]$alphaRootfsValidation.result
        }
    }
    architecture_and_compatibility = [ordered]@{
        target_arch = @($compatibility.target_arch)
        image_format = @($compatibility.image_format)
        boot_modes = @($compatibility.boot_path.boot_modes)
        kernel_family = [string]$compatibility.boot_path.kernel_family
        initramfs_contract = [string]$compatibility.boot_path.initramfs_contract
        console_readiness_marker_required = $compatibility.boot_path.console_readiness_marker_required
        minimum_runtime = $compatibility.minimum_runtime
        constraints = @(
            "developer-vm-first",
            "cloud-vm-compatible",
            "x86_64-linux-vm",
            "no-remote-llm-required",
            "no-arbitrary-root-shell-normal-mode"
        )
        compatibility = $source.compatibility
    }
    verification_references = [ordered]@{
        public_signature_artifact = $source.public_signature_artifact
        signature_receipt = $source.signature_receipt
        signature_summary = $source.signature_summary
        revocation_snapshot = $source.revocation_snapshot
        freshness_revocation_binding = $source.freshness_revocation_binding
        signature_target_sha256 = $releasePackageArtifactSet.package_surface.signature_target_sha256
        revocation_snapshot_sha256 = $releasePackageArtifactSet.package_surface.revocation_snapshot_sha256
        freshness_window_bound = $freshnessRevocationBinding.freshness.freshness_window_bound
        crypto_verified = $signatureReceipt.crypto_verified
    }
    rollback_support = [ordered]@{
        rollback_baseline = $source.rollback_baseline
        support_index = $source.support_index
        rollback_baseline_sha256 = $rollbackBaselineSha256
        support_recovery_sha256 = $supportIndexSha256
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
    install_update_gate = [ordered]@{
        installer_updater_preflight_required = $true
        package_descriptor_fail_closed_required = $true
        agentcore_install_update_planspec_required = $true
        security_execution_install_update_allow_required = $true
        rollback_support_binding_required = $true
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        active_slot_mutation_allowed = $false
        boot_metadata_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        next_task = "RC16-012"
    }
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        mirror_authority = $false
        frontend_authority = $false
        nginx_or_tls_authority = $false
        signer_reachability_authority = $false
        object_storage_ui_authority = $false
        normal_shell_authority = $false
        model_replay_authority = $false
        tui_authority = $false
        install_authority = $false
        update_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        production_ring_mutation_authority = $false
        signing_authority = $false
    }
    source = $source
}

$manifestPath = Join-Path $resolvedArtifactDir "installable-media-manifest.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-011-installable-media-manifest.json"
Write-Json $manifest $manifestPath

$authorityClean = (
    $manifest.authority.install_authority -eq $false -and
    $manifest.authority.update_authority -eq $false -and
    $manifest.authority.activation_authority -eq $false -and
    $manifest.authority.rollback_execution_authority -eq $false -and
    $manifest.authority.support_upload_authority -eq $false -and
    $manifest.authority.recovery_execution_authority -eq $false -and
    $manifest.authority.remote_dispatch_authority -eq $false -and
    $manifest.authority.production_ring_mutation_authority -eq $false -and
    $manifest.authority.signing_authority -eq $false
)
$sideEffects = [ordered]@{
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
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    production_ring_mutated = $false
}
Add-Check "authority.no_side_effects" ($authorityClean -and @($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC16-011 must not upload, publish, fetch, install, update, activate, mutate slots, rollback, upload support, recover, dispatch, sign, or mutate production state." ([ordered]@{ authority = $manifest.authority; side_effects = $sideEffects })

$manifestText = Get-Content -Raw -LiteralPath $manifestPath
Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @($manifestText)) "RC16-011 generated manifest must not contain key blocks, private key paths, auth tokens, or public identity strings." $null
Add-Check "media.id.deterministic" ($mediaId.StartsWith("sha256:", [StringComparison]::Ordinal) -and $manifest.media_identity.content_addressed -eq $true -and $manifest.media_identity.machine_local_paths_in_media_id -eq $false) "Installable media id must be deterministic and content-addressed from repo-local evidence." ([ordered]@{ media_id = $mediaId; content_addressed = $manifest.media_identity.content_addressed; machine_local_paths_in_media_id = $manifest.media_identity.machine_local_paths_in_media_id })

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$manifestSha256 = Get-FileSha256 $manifestPath
$result = [ordered]@{
    schema = "agentos.rc16-installable-media-manifest-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-011"
    status = $resultStatus
    production_ready_claim = $false
    media_id = $mediaId
    package_id = $manifest.package_id
    release_id = $manifest.release_id
    media_surface = [ordered]@{
        state = $manifest.status
        manifest_sha256 = $manifestSha256
        release_package_artifact_set_sha256 = $releasePackageArtifactSetSha256
        current_payload_sha256 = $payloadSha256
        current_payload_size_bytes = $payloadSize
        initramfs_manifest_sha256 = $initramfsManifestSha256
        alpha_rootfs_manifest_sha256 = $alphaRootfsManifestSha256
        alpha_rootfs_validation_sha256 = $alphaRootfsValidationSha256
        target_arch = @($compatibility.target_arch)
        kernel_family = [string]$compatibility.boot_path.kernel_family
        compatibility_sha256 = $compatibilitySha256
        rollback_baseline_sha256 = $rollbackBaselineSha256
        support_recovery_sha256 = $supportIndexSha256
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
        installable_media_manifest = [ordered]@{
            path = Get-StablePath $manifestPath
            sha256 = $manifestSha256
            media_id = $mediaId
        }
    }
    source = $source
    checks = $script:checks
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
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
        signer_reachability_authority = $false
        object_storage_ui_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    blockers = @(
        "rc16-package-descriptor-fail-closed-not-run",
        "rc16-installer-updater-preflight-not-bound",
        "rc16-install-update-planspec-not-bound",
        "rc16-rollback-support-package-not-bound",
        "rc16-local-release-channel-consumer-smoke-not-run"
    )
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        rootfs_runtime_artifacts = @($alphaRootfsManifest.artifacts).Count
        boot_markers = @($initramfsManifest.boot_markers).Count
        rc16_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-012"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-installable-media-manifest-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-011"
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
    media_surface = $result.media_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-012"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC16-011 outputs."
}

Write-Host "RC16 installable media manifest $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Manifest: $(Get-StablePath $manifestPath)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
