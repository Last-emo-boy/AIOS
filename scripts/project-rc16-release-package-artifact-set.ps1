param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-release-package-artifact-set",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$ReleaseArtifactsDocPath = "docs/release-artifacts.md",
    [string]$BuildReleaseScriptPath = "scripts/build-release.ps1",
    [string]$CurrentPayloadPath = "image/out/agentos-initramfs.cpio.gz",
    [string]$InitramfsManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$AlphaRootfsManifestPath = "image/out/agentos-alpha-rootfs.manifest.json",
    [string]$AlphaRootfsValidationPath = "image/out/agentos-alpha-rootfs.validation.json",
    [string]$ReleaseProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$UpdateMetadataPath = ".workflow/artifacts/release/update-metadata.json",
    [string]$ReleaseChannelMetadataPath = ".workflow/artifacts/release/release-channel-metadata.json",
    [string]$SbomPath = ".workflow/artifacts/release/sbom.json",
    [string]$DependencyInventoryPath = ".workflow/artifacts/release/dependency-inventory.json",
    [string]$FleetRolloutAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
    [string]$Rc1InstallableMediaManifestPath = ".workflow/artifacts/rc1-installable-media/installable-media-manifest.json",
    [string]$Rc1InstalledSystemGatePath = ".workflow/artifacts/release/rc1-installed-system-gate.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$ObjectChecksumsPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-checksums.json",
    [string]$PublicSignatureArtifactPath = "image/out/agentos-initramfs.cpio.gz.prod.sig.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$SignedMetadataPath = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json",
    [string]$RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$FreshnessRevocationBindingPath = ".workflow/artifacts/rc13-freshness-revocation-authority/freshness-revocation-authority-binding.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$ObjectTrustResultPath = ".workflow/artifacts/rc14-local-object-trust-verification/result.json",
    [string]$QuarantineResultPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/result.json",
    [string]$QuarantineManifestPath = ".workflow/artifacts/rc14-verified-quarantine-preflight/verified-quarantine-manifest.json",
    [string]$Rc15FinalAuditPath = ".workflow/artifacts/rc15-final-closeout-audit/result.json",
    [string]$Rc15ExactApprovalResultPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json",
    [string]$Rc15AgentCorePlanSpecPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/agentcore-planspec.json",
    [string]$Rc15SecurityExecutionDecisionPath = ".workflow/artifacts/rc15-security-execution-allow-decision/security-execution-allow-decision.json",
    [string]$Rc15ActivationReportPath = ".workflow/artifacts/rc15-controlled-local-activation/activation-gate-report.json",
    [string]$Rc15RollbackResultPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/result.json",
    [string]$Rc15SupportRecoveryEvidenceChainPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/support-recovery-evidence-chain.json",
    [string]$Rc15RecoveryReferenceIndexPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/recovery-reference-index.json",
    [string]$TuiReplayResultPath = ".workflow/artifacts/tui-replay/result.json",
    [string]$TuiSessionHardeningReplayPath = ".workflow/artifacts/release/tui-session-hardening-replay.json",
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
$resolvedReleaseArtifactsDocPath = Resolve-RepoPath $ReleaseArtifactsDocPath
$resolvedBuildReleaseScriptPath = Resolve-RepoPath $BuildReleaseScriptPath
$resolvedCurrentPayloadPath = Resolve-RepoPath $CurrentPayloadPath
$resolvedInitramfsManifestPath = Resolve-RepoPath $InitramfsManifestPath
$resolvedAlphaRootfsManifestPath = Resolve-RepoPath $AlphaRootfsManifestPath
$resolvedAlphaRootfsValidationPath = Resolve-RepoPath $AlphaRootfsValidationPath
$resolvedReleaseProvenancePath = Resolve-RepoPath $ReleaseProvenancePath
$resolvedUpdateMetadataPath = Resolve-RepoPath $UpdateMetadataPath
$resolvedReleaseChannelMetadataPath = Resolve-RepoPath $ReleaseChannelMetadataPath
$resolvedSbomPath = Resolve-RepoPath $SbomPath
$resolvedDependencyInventoryPath = Resolve-RepoPath $DependencyInventoryPath
$resolvedFleetRolloutAuthorityPath = Resolve-RepoPath $FleetRolloutAuthorityPath
$resolvedRc1InstallableMediaManifestPath = Resolve-RepoPath $Rc1InstallableMediaManifestPath
$resolvedRc1InstalledSystemGatePath = Resolve-RepoPath $Rc1InstalledSystemGatePath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedObjectChecksumsPath = Resolve-RepoPath $ObjectChecksumsPath
$resolvedPublicSignatureArtifactPath = Resolve-RepoPath $PublicSignatureArtifactPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedSignedMetadataPath = Resolve-RepoPath $SignedMetadataPath
$resolvedRevocationSnapshotPath = Resolve-RepoPath $RevocationSnapshotPath
$resolvedFreshnessRevocationBindingPath = Resolve-RepoPath $FreshnessRevocationBindingPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedObjectTrustResultPath = Resolve-RepoPath $ObjectTrustResultPath
$resolvedQuarantineResultPath = Resolve-RepoPath $QuarantineResultPath
$resolvedQuarantineManifestPath = Resolve-RepoPath $QuarantineManifestPath
$resolvedRc15FinalAuditPath = Resolve-RepoPath $Rc15FinalAuditPath
$resolvedRc15ExactApprovalResultPath = Resolve-RepoPath $Rc15ExactApprovalResultPath
$resolvedRc15AgentCorePlanSpecPath = Resolve-RepoPath $Rc15AgentCorePlanSpecPath
$resolvedRc15SecurityExecutionDecisionPath = Resolve-RepoPath $Rc15SecurityExecutionDecisionPath
$resolvedRc15ActivationReportPath = Resolve-RepoPath $Rc15ActivationReportPath
$resolvedRc15RollbackResultPath = Resolve-RepoPath $Rc15RollbackResultPath
$resolvedRc15SupportRecoveryEvidenceChainPath = Resolve-RepoPath $Rc15SupportRecoveryEvidenceChainPath
$resolvedRc15RecoveryReferenceIndexPath = Resolve-RepoPath $Rc15RecoveryReferenceIndexPath
$resolvedTuiReplayResultPath = Resolve-RepoPath $TuiReplayResultPath
$resolvedTuiSessionHardeningReplayPath = Resolve-RepoPath $TuiSessionHardeningReplayPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseArtifactsDocText = Get-Content -Raw -LiteralPath $resolvedReleaseArtifactsDocPath
$descriptor = Read-Json $resolvedDescriptorPath
$objectChecksums = Read-Json $resolvedObjectChecksumsPath
$initramfsManifest = Read-Json $resolvedInitramfsManifestPath
$alphaRootfsManifest = Read-Json $resolvedAlphaRootfsManifestPath
$alphaRootfsValidation = Read-Json $resolvedAlphaRootfsValidationPath
$releaseProvenance = Read-Json $resolvedReleaseProvenancePath
$updateMetadata = Read-Json $resolvedUpdateMetadataPath
$releaseChannelMetadata = Read-Json $resolvedReleaseChannelMetadataPath
$sbom = Read-Json $resolvedSbomPath
$dependencyInventory = Read-Json $resolvedDependencyInventoryPath
$fleetRolloutAuthority = Read-Json $resolvedFleetRolloutAuthorityPath
$rc1InstallableMediaManifest = Read-Json $resolvedRc1InstallableMediaManifestPath
$rc1InstalledSystemGate = Read-Json $resolvedRc1InstalledSystemGatePath
$publicSignatureArtifact = Read-Json $resolvedPublicSignatureArtifactPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$signedMetadata = Read-Json $resolvedSignedMetadataPath
$revocationSnapshot = Read-Json $resolvedRevocationSnapshotPath
$freshnessRevocationBinding = Read-Json $resolvedFreshnessRevocationBindingPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath
$objectTrustResult = Read-Json $resolvedObjectTrustResultPath
$quarantineResult = Read-Json $resolvedQuarantineResultPath
$quarantineManifest = Read-Json $resolvedQuarantineManifestPath
$rc15FinalAudit = Read-Json $resolvedRc15FinalAuditPath
$rc15ExactApprovalResult = Read-Json $resolvedRc15ExactApprovalResultPath
$rc15AgentCorePlanSpec = Read-Json $resolvedRc15AgentCorePlanSpecPath
$rc15SecurityExecutionDecision = Read-Json $resolvedRc15SecurityExecutionDecisionPath
$rc15ActivationReport = Read-Json $resolvedRc15ActivationReportPath
$rc15RollbackResult = Read-Json $resolvedRc15RollbackResultPath
$rc15SupportRecoveryEvidenceChain = Read-Json $resolvedRc15SupportRecoveryEvidenceChainPath
$rc15RecoveryReferenceIndex = Read-Json $resolvedRc15RecoveryReferenceIndexPath
$tuiReplayResult = Read-Json $resolvedTuiReplayResultPath
$tuiSessionHardeningReplay = Read-Json $resolvedTuiSessionHardeningReplayPath

$rc16TaskStatus = Get-TaskStatus $plan "RC16-010"
$rc16PreviousStatus = Get-TaskStatus $plan "RC16-001"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-010" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-011" -and $rc16TaskStatus -eq "completed")
    )
)

$payloadSha256 = Get-FileSha256 $resolvedCurrentPayloadPath
$payloadSize = if (Test-Path -LiteralPath $resolvedCurrentPayloadPath -PathType Leaf) { (Get-Item -LiteralPath $resolvedCurrentPayloadPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$initramfsManifestSha256 = Get-FileSha256 $resolvedInitramfsManifestPath
$objectChecksumsSha256 = Get-FileSha256 $resolvedObjectChecksumsPath
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
    release_artifacts_doc = New-ArtifactRef $resolvedReleaseArtifactsDocPath
    build_release_script = New-ArtifactRef $resolvedBuildReleaseScriptPath
    current_payload_bytes = New-ArtifactRef $resolvedCurrentPayloadPath
    initramfs_manifest = New-ArtifactRef $resolvedInitramfsManifestPath $initramfsManifest
    alpha_rootfs_manifest = New-ArtifactRef $resolvedAlphaRootfsManifestPath $alphaRootfsManifest
    alpha_rootfs_validation = New-ArtifactRef $resolvedAlphaRootfsValidationPath $alphaRootfsValidation
    release_provenance = New-ArtifactRef $resolvedReleaseProvenancePath $releaseProvenance
    update_metadata = New-ArtifactRef $resolvedUpdateMetadataPath $updateMetadata
    release_channel_metadata = New-ArtifactRef $resolvedReleaseChannelMetadataPath $releaseChannelMetadata
    sbom = New-ArtifactRef $resolvedSbomPath $sbom
    dependency_inventory = New-ArtifactRef $resolvedDependencyInventoryPath $dependencyInventory
    fleet_rollout_authority = New-ArtifactRef $resolvedFleetRolloutAuthorityPath $fleetRolloutAuthority
    rc1_installable_media_manifest = New-ArtifactRef $resolvedRc1InstallableMediaManifestPath $rc1InstallableMediaManifest
    rc1_installed_system_gate = New-ArtifactRef $resolvedRc1InstalledSystemGatePath $rc1InstalledSystemGate
    payload_descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    object_checksums = New-ArtifactRef $resolvedObjectChecksumsPath $objectChecksums
    public_signature_artifact = New-ArtifactRef $resolvedPublicSignatureArtifactPath $publicSignatureArtifact
    signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    signed_metadata = New-ArtifactRef $resolvedSignedMetadataPath $signedMetadata
    revocation_snapshot = New-ArtifactRef $resolvedRevocationSnapshotPath $revocationSnapshot
    freshness_revocation_binding = New-ArtifactRef $resolvedFreshnessRevocationBindingPath $freshnessRevocationBinding
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    object_trust_result = New-ArtifactRef $resolvedObjectTrustResultPath $objectTrustResult
    quarantine_result = New-ArtifactRef $resolvedQuarantineResultPath $quarantineResult
    quarantine_manifest = New-ArtifactRef $resolvedQuarantineManifestPath $quarantineManifest
    rc15_final_audit = New-ArtifactRef $resolvedRc15FinalAuditPath $rc15FinalAudit
    rc15_exact_approval = New-ArtifactRef $resolvedRc15ExactApprovalResultPath $rc15ExactApprovalResult
    rc15_agentcore_planspec = New-ArtifactRef $resolvedRc15AgentCorePlanSpecPath $rc15AgentCorePlanSpec
    rc15_security_execution_decision = New-ArtifactRef $resolvedRc15SecurityExecutionDecisionPath $rc15SecurityExecutionDecision
    rc15_activation_report = New-ArtifactRef $resolvedRc15ActivationReportPath $rc15ActivationReport
    rc15_rollback_result = New-ArtifactRef $resolvedRc15RollbackResultPath $rc15RollbackResult
    rc15_support_recovery_evidence_chain = New-ArtifactRef $resolvedRc15SupportRecoveryEvidenceChainPath $rc15SupportRecoveryEvidenceChain
    rc15_recovery_reference_index = New-ArtifactRef $resolvedRc15RecoveryReferenceIndexPath $rc15RecoveryReferenceIndex
    tui_replay = New-ArtifactRef $resolvedTuiReplayResultPath $tuiReplayResult
    tui_session_hardening_replay = New-ArtifactRef $resolvedTuiSessionHardeningReplayPath $tuiSessionHardeningReplay
}

$requiredSourceRefs = @(
    $source.current_payload_bytes,
    $source.initramfs_manifest,
    $source.alpha_rootfs_manifest,
    $source.release_provenance,
    $source.update_metadata,
    $source.release_channel_metadata,
    $source.payload_descriptor,
    $source.object_checksums,
    $source.signature_receipt,
    $source.revocation_snapshot,
    $source.compatibility,
    $source.rollback_baseline,
    $source.support_index,
    $source.rc15_final_audit
)
$missingRequiredRefs = @($requiredSourceRefs | Where-Object { $_.present -ne $true })
$payloadMatchesDescriptor = (
    $payloadSha256 -eq [string]$descriptor.sha256 -and
    $payloadSha256 -eq [string]$descriptor.source_build_artifact_sha256 -and
    [int64]$payloadSize -eq [int64]$descriptor.size_bytes
)
$payloadMatchesManifestAndChecksums = (
    $payloadSha256 -eq [string]$initramfsManifest.artifact_sha256 -and
    $payloadSha256 -eq [string]$objectChecksums.sha256 -and
    $payloadSha256 -eq [string]$objectChecksums.manifest_declared_sha256 -and
    [int64]$payloadSize -eq [int64]$objectChecksums.size_bytes
)
$metadataPresent = (
    $releaseProvenance.schema -eq "agentos.production-candidate.provenance.v1" -and
    $updateMetadata.schema -eq "agentos.candidate-update-metadata.v1" -and
    $releaseChannelMetadata.schema -eq "agentos.release-channel-metadata.v1" -and
    $sbom.schema -eq "agentos.candidate-sbom.v1" -and
    $dependencyInventory.schema -eq "aios.dependency-inventory.v1" -and
    $fleetRolloutAuthority.schema -eq "agentos.fleet-rollout-authority.v1"
)
$signatureRevocationPresent = (
    $publicSignatureArtifact.schema -eq "agentos.production-detached-signature.v1" -and
    $signatureReceipt.crypto_verified -eq $true -and
    $signatureReceiptSha256 -and
    $signatureSummarySha256 -and
    $signedMetadata.schema -and
    $revocationSnapshotSha256 -and
    $freshnessBindingSha256
)
$rollbackSupportPresent = (
    $rollbackBaselineSha256 -and
    $supportIndexSha256 -and
    $rc15RollbackResult.status -eq "passed" -and
    $source.rc15_support_recovery_evidence_chain.present -eq $true -and
    $source.rc15_recovery_reference_index.present -eq $true
)
$installUpdateRefsPresent = (
    $rc1InstallableMediaManifest.schema -and
    $rc1InstalledSystemGate.status -eq "passed" -and
    $objectTrustResult.status -eq "passed" -and
    $quarantineResult.status -eq "passed" -and
    $rc15AgentCorePlanSpec.status -eq "agentcore-planspec-executable" -and
    $rc15SecurityExecutionDecision.status -eq "security-execution-allow-bound"
)
$rc15Bound = (
    $rc15FinalAudit.status -eq "passed" -and
    $rc15FinalAudit.decision -eq "PASS" -and
    $rc15FinalAudit.controlled_local_execution_ready -eq $true -and
    $rc15FinalAudit.production_ready_claim -eq $false
)
$operatorExplainabilityPresent = (
    $contractText.Contains("Operator Explainability Contract") -and
    $releaseArtifactsDocText.Contains("Release Artifacts") -and
    $tuiReplayResult.status -eq "passed" -and
    $tuiSessionHardeningReplay.status -eq "passed"
)

Add-Check "plan.current_task.rc16_010" $planAllowsRun "RC16-010 must run after RC16-001 completes and while the plan pointer is at RC16-010, or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_001_status = $rc16PreviousStatus; rc16_010_status = $rc16TaskStatus })
Add-Check "contract.package_gate.present" ($contractText.Contains("Project the repo-local distributable release package artifact set") -and $contractText.Contains("Package Contract")) "RC16-010 must consume the RC16 package and release-operation contract." $source.rc16_contract
Add-Check "sources.required.present" (@($missingRequiredRefs).Count -eq 0) "Required package inputs must be present before package artifact set projection." (@($missingRequiredRefs | ForEach-Object { $_.path }))
Add-Check "payload.bytes.bound" ($payloadMatchesDescriptor -and $payloadMatchesManifestAndChecksums) "Current payload bytes must be bound to descriptor, initramfs manifest, and checksum set." ([ordered]@{ payload_sha256 = $payloadSha256; descriptor_sha256 = $descriptor.sha256; manifest_payload_sha256 = $initramfsManifest.artifact_sha256; checksum_sha256 = $objectChecksums.sha256; payload_size_bytes = $payloadSize; descriptor_size_bytes = $descriptor.size_bytes })
Add-Check "release.metadata.bound" $metadataPresent "Release provenance, update metadata, release channel metadata, SBOM, dependency inventory, and fleet rollout authority must be hash-bound." ([ordered]@{ provenance_schema = $releaseProvenance.schema; update_metadata_schema = $updateMetadata.schema; release_channel_schema = $releaseChannelMetadata.schema; sbom_schema = $sbom.schema; dependency_inventory_schema = $dependencyInventory.schema; fleet_rollout_schema = $fleetRolloutAuthority.schema })
Add-Check "signature.revocation.bound" $signatureRevocationPresent "Package artifact set must bind detached public verification, signed metadata, revocation, and freshness/revocation references." ([ordered]@{ public_signature_schema = $publicSignatureArtifact.schema; signature_receipt_crypto_verified = $signatureReceipt.crypto_verified; revocation_snapshot_sha256 = $revocationSnapshotSha256; freshness_binding_sha256 = $freshnessBindingSha256; freshness_window_bound = $freshnessRevocationBinding.freshness.freshness_window_bound })
Add-Check "rollback.support.bound" $rollbackSupportPresent "Rollback baseline and support/recovery references must be bound." ([ordered]@{ rollback_baseline_sha256 = $rollbackBaselineSha256; support_index_sha256 = $supportIndexSha256; rc15_rollback_status = $rc15RollbackResult.status; support_chain_present = $source.rc15_support_recovery_evidence_chain.present; recovery_index_present = $source.rc15_recovery_reference_index.present })
Add-Check "install_update.refs.bound" $installUpdateRefsPresent "Install/update package references must bind installable media, installed-system gate, object trust, quarantine, AgentCore, and SecurityExecution evidence." ([ordered]@{ installable_media_schema = $rc1InstallableMediaManifest.schema; installed_system_gate_status = $rc1InstalledSystemGate.status; object_trust_status = $objectTrustResult.status; quarantine_status = $quarantineResult.status; agentcore_status = $rc15AgentCorePlanSpec.status; security_status = $rc15SecurityExecutionDecision.status })
Add-Check "rc15.execution.bound" $rc15Bound "RC16 package set must bind RC15 controlled local execution readiness without claiming GA." ([ordered]@{ rc15_status = $rc15FinalAudit.status; decision = $rc15FinalAudit.decision; controlled_local_execution_ready = $rc15FinalAudit.controlled_local_execution_ready; production_ready_claim = $rc15FinalAudit.production_ready_claim })
Add-Check "operator.explainability.refs.bound" $operatorExplainabilityPresent "Package set must record operator explainability references without TUI authority." ([ordered]@{ contract_has_operator_section = $contractText.Contains("Operator Explainability Contract"); release_doc_present = $source.release_artifacts_doc.present; tui_replay_status = $tuiReplayResult.status; tui_session_hardening_status = $tuiSessionHardeningReplay.status })

$artifactSet = [ordered]@{
    schema = "agentos.rc16-release-package-artifact-set.v1"
    generated_at = $generatedAtValue
    task = "RC16-010"
    status = "repo-local-distributable-release-package-artifact-set-projected"
    package_id = "production-distro-rc16-repo-local-distributable-package"
    release_id = [string]$descriptor.release_id
    production_ready_claim = $false
    package_surface = [ordered]@{
        state = "repo-local-package-artifact-set-projected-install-update-gated"
        current_payload_path = Get-StablePath $resolvedCurrentPayloadPath
        current_payload_size_bytes = $payloadSize
        current_payload_sha256 = $payloadSha256
        object_id = [string]$descriptor.object_id
        object_kind = [string]$descriptor.kind
        descriptor_sha256 = $descriptorSha256
        manifest_sha256 = $initramfsManifestSha256
        checksum_set_sha256 = $objectChecksumsSha256
        signature_target_sha256 = $descriptorSha256
        revocation_snapshot_sha256 = $revocationSnapshotSha256
        freshness_revocation_binding_sha256 = $freshnessBindingSha256
        compatibility_sha256 = $compatibilitySha256
        rollback_baseline_sha256 = $rollbackBaselineSha256
        support_recovery_sha256 = $supportIndexSha256
        rc15_controlled_execution_ready = $rc15FinalAudit.controlled_local_execution_ready
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    artifact_classes = [ordered]@{
        release_bytes = [ordered]@{
            current_payload = $source.current_payload_bytes
            payload_descriptor = $source.payload_descriptor
        }
        manifests = [ordered]@{
            initramfs_manifest = $source.initramfs_manifest
            alpha_rootfs_manifest = $source.alpha_rootfs_manifest
            alpha_rootfs_validation = $source.alpha_rootfs_validation
            rc1_installable_media_manifest = $source.rc1_installable_media_manifest
        }
        checksums = [ordered]@{
            object_checksums = $source.object_checksums
            checksum_set_sha256 = $objectChecksumsSha256
            manifest_declared_payload_sha256 = [string]$objectChecksums.manifest_declared_sha256
        }
        release_metadata = [ordered]@{
            release_provenance = $source.release_provenance
            update_metadata = $source.update_metadata
            release_channel_metadata = $source.release_channel_metadata
            sbom = $source.sbom
            dependency_inventory = $source.dependency_inventory
            fleet_rollout_authority = $source.fleet_rollout_authority
        }
        signature_target = [ordered]@{
            public_signature_artifact = $source.public_signature_artifact
            signature_receipt = $source.signature_receipt
            signature_summary = $source.signature_summary
            signed_metadata = $source.signed_metadata
            signature_target_descriptor_sha256 = $descriptorSha256
            crypto_verified = $signatureReceipt.crypto_verified
            raw_signature_value_redacted = $true
        }
        revocation_and_freshness = [ordered]@{
            revocation_snapshot = $source.revocation_snapshot
            freshness_revocation_binding = $source.freshness_revocation_binding
            freshness_window_bound = $freshnessRevocationBinding.freshness.freshness_window_bound
            freshness_window_current = $freshnessRevocationBinding.freshness.freshness_window_current
            revocation_status = $freshnessRevocationBinding.revocation.status
        }
        install_update = [ordered]@{
            rc1_installed_system_gate = $source.rc1_installed_system_gate
            object_trust_result = $source.object_trust_result
            quarantine_result = $source.quarantine_result
            quarantine_manifest = $source.quarantine_manifest
            rc15_agentcore_planspec = $source.rc15_agentcore_planspec
            rc15_security_execution_decision = $source.rc15_security_execution_decision
            installer_updater_preflight_required = $true
            agentcore_install_update_planspec_required = $true
            security_execution_install_update_allow_required = $true
        }
        rollback_support = [ordered]@{
            rollback_baseline = $source.rollback_baseline
            support_index = $source.support_index
            rc15_rollback_result = $source.rc15_rollback_result
            rc15_support_recovery_evidence_chain = $source.rc15_support_recovery_evidence_chain
            rc15_recovery_reference_index = $source.rc15_recovery_reference_index
            support_upload_allowed = $false
            recovery_execution_allowed = $false
        }
        rc15_execution_evidence = [ordered]@{
            rc15_final_audit = $source.rc15_final_audit
            rc15_exact_approval = $source.rc15_exact_approval
            rc15_activation_report = $source.rc15_activation_report
            controlled_local_execution_ready = $rc15FinalAudit.controlled_local_execution_ready
        }
        operator_explainability = [ordered]@{
            rc16_contract = $source.rc16_contract
            release_artifacts_doc = $source.release_artifacts_doc
            tui_replay = $source.tui_replay
            tui_session_hardening_replay = $source.tui_session_hardening_replay
            tui_authority = $false
            explanation_only = $true
        }
    }
    next_required_gates = [ordered]@{
        rc16_011_installable_media_manifest = "required-before-installable-media-claim"
        rc16_012_package_descriptor_fail_closed = "required-before-package-trust"
        rc16_020_installer_updater_preflight = "required-before-install-update-authority"
        rc16_021_agentcore_security_install_update_binding = "required-before-effects"
        rc16_022_rollback_support_package = "required-before-effects"
        rc16_030_tui_projection = "explanation-only"
        rc16_031_local_consumer_smoke = "must-execute-or-deny-with-audit"
    }
    authority = [ordered]@{
        aios_body_only = $true
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

$artifactSetPath = Join-Path $resolvedArtifactDir "release-package-artifact-set.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-010-release-package-artifact-set.json"
Write-Json $artifactSet $artifactSetPath

$authorityClean = (
    $artifactSet.authority.install_authority -eq $false -and
    $artifactSet.authority.update_authority -eq $false -and
    $artifactSet.authority.activation_authority -eq $false -and
    $artifactSet.authority.rollback_execution_authority -eq $false -and
    $artifactSet.authority.support_upload_authority -eq $false -and
    $artifactSet.authority.recovery_execution_authority -eq $false -and
    $artifactSet.authority.remote_dispatch_authority -eq $false -and
    $artifactSet.authority.production_ring_mutation_authority -eq $false -and
    $artifactSet.authority.signing_authority -eq $false -and
    $artifactSet.authority.tui_authority -eq $false
)
$sideEffects = [ordered]@{
    payload_upload_performed = $false
    payload_published = $false
    network_fetch_attempted = $false
    remote_payload_bytes_downloaded = $false
    install_performed = $false
    update_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}
Add-Check "authority.no_side_effects" ($authorityClean -and @($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC16-010 must not upload, publish, fetch, install, update, activate, rollback, upload support, recover, dispatch, sign, or mutate production state." ([ordered]@{ authority = $artifactSet.authority; side_effects = $sideEffects })

$artifactSetText = Get-Content -Raw -LiteralPath $artifactSetPath
Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @($artifactSetText)) "RC16-010 generated artifact set must not contain key blocks, private key paths, auth tokens, or public identity strings." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc16-release-package-artifact-set-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-010"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $artifactSet.package_id
    release_id = $artifactSet.release_id
    package_surface = [ordered]@{
        state = $artifactSet.package_surface.state
        artifact_set_sha256 = Get-FileSha256 $artifactSetPath
        current_payload_sha256 = $payloadSha256
        current_payload_size_bytes = $payloadSize
        manifest_sha256 = $initramfsManifestSha256
        checksum_set_sha256 = $objectChecksumsSha256
        signature_target_sha256 = $descriptorSha256
        revocation_snapshot_sha256 = $revocationSnapshotSha256
        rollback_baseline_sha256 = $rollbackBaselineSha256
        support_recovery_sha256 = $supportIndexSha256
        rc15_controlled_local_execution_ready = $rc15FinalAudit.controlled_local_execution_ready
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    outputs = [ordered]@{
        release_package_artifact_set = [ordered]@{
            path = Get-StablePath $artifactSetPath
            sha256 = Get-FileSha256 $artifactSetPath
        }
    }
    source = $source
    checks = $script:checks
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
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
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
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
        "rc16-installable-media-manifest-not-assembled",
        "rc16-package-descriptor-fail-closed-not-run",
        "rc16-installer-updater-preflight-not-bound",
        "rc16-install-update-planspec-not-bound",
        "rc16-rollback-support-package-not-bound",
        "rc16-local-release-channel-consumer-smoke-not-run"
    )
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        artifact_classes = @($artifactSet.artifact_classes.PSObject.Properties).Count
        rc16_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-011"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-release-package-artifact-set-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-010"
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
    package_surface = $result.package_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-011"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC16-010 outputs."
}

Write-Host "RC16 release package artifact set $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Artifact set: $(Get-StablePath $artifactSetPath)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
