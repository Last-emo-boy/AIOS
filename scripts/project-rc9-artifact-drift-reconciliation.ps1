param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-artifact-drift-reconciliation",
    [string]$GeneratedAt = "",
    [string]$PublicationResultPath = ".workflow/artifacts/rc9-external-object-publication/result.json",
    [string]$PublicationCandidatePath = ".workflow/artifacts/rc9-external-object-publication/external-object-publication-candidate.json",
    [string]$PublicationHandoffPath = ".workflow/artifacts/rc9-external-object-publication/installer-handoff.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$PayloadManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$Rc6PayloadManifestPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-manifest.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$Rc7SignedMetadataPath = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json",
    [string]$Rc7RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$Rc7CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$Rc7RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$HostedPayloadIndexPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-payload-index.json",
    [string]$InstallBootstrapPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/install-bootstrap.json",
    [string]$HostedChannelIndexPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-channel-index.json",
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
    $script:checks += [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
}

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Expected,
        [AllowNull()][string]$Actual,
        [string]$ExpectedSource = "",
        [string]$ActualSource = "",
        [string]$DriftReason = "value-mismatch"
    )
    $status = if ($null -eq $Actual -or $Actual -eq "") {
        "missing"
    } elseif ($Expected -eq $Actual) {
        "matched"
    } else {
        "drift"
    }
    $entry = [ordered]@{
        id = $Id
        status = $status
        expected = $Expected
        actual = $Actual
        expected_source = $ExpectedSource
        actual_source = $ActualSource
        denial_reason = if ($status -eq "matched") { $null } else { $DriftReason }
    }
    $script:comparisons += $entry
    if ($status -ne "matched") {
        $script:drifts += $entry
    }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function Test-FreshUntil {
    param([string]$Value, [string]$Now)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    try {
        $until = [DateTimeOffset]::Parse($Value)
        $nowValue = [DateTimeOffset]::Parse($Now)
        return $until -gt $nowValue
    } catch {
        return $false
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key.pem"),
        ("/etc/" + "aios-signer")
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
$script:comparisons = @()
$script:drifts = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedPublicationCandidatePath = Resolve-RepoPath $PublicationCandidatePath
$resolvedPublicationHandoffPath = Resolve-RepoPath $PublicationHandoffPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedPayloadManifestPath = Resolve-RepoPath $PayloadManifestPath
$resolvedRc6PayloadManifestPath = Resolve-RepoPath $Rc6PayloadManifestPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedRc7SignedMetadataPath = Resolve-RepoPath $Rc7SignedMetadataPath
$resolvedRc7RevocationSnapshotPath = Resolve-RepoPath $Rc7RevocationSnapshotPath
$resolvedRc7CompatibilityPath = Resolve-RepoPath $Rc7CompatibilityPath
$resolvedRc7RollbackBaselinePath = Resolve-RepoPath $Rc7RollbackBaselinePath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath
$resolvedHostedPayloadIndexPath = Resolve-RepoPath $HostedPayloadIndexPath
$resolvedInstallBootstrapPath = Resolve-RepoPath $InstallBootstrapPath
$resolvedHostedChannelIndexPath = Resolve-RepoPath $HostedChannelIndexPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$publicationCandidate = Read-Json $resolvedPublicationCandidatePath
$publicationHandoff = Read-Json $resolvedPublicationHandoffPath
$descriptor = Read-Json $resolvedDescriptorPath
$payloadManifest = Read-Json $resolvedPayloadManifestPath
$rc6PayloadManifest = Read-Json $resolvedRc6PayloadManifestPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$rc7SignedMetadata = Read-Json $resolvedRc7SignedMetadataPath
$rc7RevocationSnapshot = Read-Json $resolvedRc7RevocationSnapshotPath
$rc7Compatibility = Read-Json $resolvedRc7CompatibilityPath
$rc7RollbackBaseline = Read-Json $resolvedRc7RollbackBaselinePath
$supportRecovery = Read-Json $resolvedSupportRecoveryPath
$hostedPayloadIndex = Read-Json $resolvedHostedPayloadIndexPath
$installBootstrap = Read-Json $resolvedInstallBootstrapPath
$hostedChannelIndex = Read-Json $resolvedHostedChannelIndexPath

$releaseId = [string]$descriptor.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$descriptor.source_build_artifact)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$payloadManifestSha256 = Get-FileSha256 $resolvedPayloadManifestPath
$rc6PayloadManifestSha256 = Get-FileSha256 $resolvedRc6PayloadManifestPath
$signatureReceiptSha256 = Get-FileSha256 $resolvedSignatureReceiptPath
$signatureSummarySha256 = Get-FileSha256 $resolvedSignatureSummaryPath
$rc7SignedMetadataSha256 = Get-FileSha256 $resolvedRc7SignedMetadataPath
$rc7RevocationSnapshotSha256 = Get-FileSha256 $resolvedRc7RevocationSnapshotPath
$rc7CompatibilitySha256 = Get-FileSha256 $resolvedRc7CompatibilityPath
$rc7RollbackBaselineSha256 = Get-FileSha256 $resolvedRc7RollbackBaselinePath
$supportRecoverySha256 = Get-FileSha256 $resolvedSupportRecoveryPath
$hostedPayloadIndexSha256 = Get-FileSha256 $resolvedHostedPayloadIndexPath
$installBootstrapSha256 = Get-FileSha256 $resolvedInstallBootstrapPath
$hostedChannelIndexSha256 = Get-FileSha256 $resolvedHostedChannelIndexPath

Add-Comparison "release.descriptor_vs_publication_result" $releaseId ([string]$publicationResult.release_id) "descriptor.release_id" "rc9-publication-result.release_id" "publication-release-id-mismatch"
Add-Comparison "source_artifact.sha256" ([string]$descriptor.sha256) $sourceArtifactSha256 "descriptor.sha256" "current source artifact" "source-artifact-digest-mismatch"
Add-Comparison "source_artifact.size_bytes" ([string]$descriptor.size_bytes) ([string]$sourceArtifactSize) "descriptor.size_bytes" "current source artifact" "source-artifact-size-mismatch"
Add-Comparison "payload_manifest.digest" ([string]$descriptor.manifest_sha256) $payloadManifestSha256 "descriptor.manifest_sha256" "current payload manifest file" "manifest-digest-mismatch"
Add-Comparison "checksum_set.digest" ([string]$descriptor.checksums_sha256) $rc6PayloadManifestSha256 "descriptor.checksums_sha256" "rc6 payload manifest file" "checksum-set-digest-mismatch"
Add-Comparison "signature_receipt.descriptor_sha256" $descriptorSha256 ([string]$signatureReceipt.descriptor_sha256) "descriptor file" "signature receipt" "signature-receipt-descriptor-mismatch"
Add-Comparison "signature_receipt.object_sha256" ([string]$descriptor.sha256) ([string]$signatureReceipt.signed_object_sha256) "descriptor.sha256" "signature receipt" "signature-receipt-object-mismatch"
Add-Comparison "signature_summary.descriptor_sha256" $descriptorSha256 ([string]$signatureSummary.descriptor_sha256) "descriptor file" "signature summary" "signature-summary-descriptor-mismatch"
Add-Comparison "signature_summary.object_sha256" ([string]$descriptor.sha256) ([string]$signatureSummary.signed_object_sha256) "descriptor.sha256" "signature summary" "signature-summary-object-mismatch"
Add-Comparison "revocation_snapshot.digest" ([string]$descriptor.revocation_snapshot_sha256) $rc7RevocationSnapshotSha256 "descriptor.revocation_snapshot_sha256" "revocation snapshot file" "revocation-snapshot-digest-mismatch"
Add-Comparison "installer_compatibility.digest" ([string]$descriptor.installer_compatibility_sha256) $rc7CompatibilitySha256 "descriptor.installer_compatibility_sha256" "compatibility file" "compatibility-digest-mismatch"
Add-Comparison "rollback_baseline.digest" ([string]$descriptor.rollback_baseline_sha256) $rc7RollbackBaselineSha256 "descriptor.rollback_baseline_sha256" "rollback baseline file" "rollback-baseline-digest-mismatch"
Add-Comparison "support_recovery.digest" ([string]$descriptor.support_recovery_sha256) $supportRecoverySha256 "descriptor.support_recovery_sha256" "support recovery file" "support-recovery-digest-mismatch"
Add-Comparison "mirror.payload_index.object_descriptor_sha256" $descriptorSha256 ([string]$hostedPayloadIndex.entries[0].object_descriptor_sha256) "descriptor file" "hosted payload index" "mirror-payload-index-descriptor-mismatch"
Add-Comparison "mirror.payload_index.object_sha256" ([string]$descriptor.sha256) ([string]$hostedPayloadIndex.entries[0].object_sha256) "descriptor.sha256" "hosted payload index" "mirror-payload-index-object-mismatch"
Add-Comparison "mirror.install_bootstrap.object_descriptor_sha256" $descriptorSha256 ([string]$installBootstrap.projection.object_descriptor_sha256) "descriptor file" "install bootstrap" "install-bootstrap-descriptor-mismatch"
Add-Comparison "mirror.channel.object_descriptor_sha256" $descriptorSha256 ([string]$hostedChannelIndex.payload_channel.object_descriptor_sha256) "descriptor file" "channel index" "channel-descriptor-mismatch"

Add-Comparison "declared.rc6_payload_manifest.release_id" $releaseId ([string]$rc6PayloadManifest.release_id) "current descriptor release_id" "rc6 payload manifest release_id" "declared-release-id-superseded"
Add-Comparison "declared.rc7_signed_metadata.release_id" $releaseId ([string]$rc7SignedMetadata.release_id) "current descriptor release_id" "rc7 signed metadata release_id" "declared-release-id-superseded"
Add-Comparison "declared.rc7_signature_claims.release_id" $releaseId ([string]$rc7SignedMetadata.signature_claims.release_id) "current descriptor release_id" "rc7 signature claims release_id" "declared-release-id-superseded"
Add-Comparison "declared.rc7_revocation.release_id" $releaseId ([string]$rc7RevocationSnapshot.release_id) "current descriptor release_id" "rc7 revocation release_id" "declared-release-id-superseded"
Add-Comparison "declared.rc7_compatibility.release_id" $releaseId ([string]$rc7Compatibility.release_id) "current descriptor release_id" "rc7 compatibility release_id" "declared-release-id-superseded"
Add-Comparison "declared.rc7_rollback.release_id" $releaseId ([string]$rc7RollbackBaseline.release_id) "current descriptor release_id" "rc7 rollback release_id" "declared-release-id-superseded"
Add-Comparison "declared.rc7_compatibility.payload_manifest_sha256" ([string]$descriptor.manifest_sha256) ([string]$rc7Compatibility.required_metadata.payload_manifest_sha256) "descriptor.manifest_sha256" "rc7 compatibility required metadata" "declared-manifest-digest-superseded"
Add-Comparison "declared.rc7_compatibility.payload_checksums_sha256" ([string]$descriptor.checksums_sha256) ([string]$rc7Compatibility.required_metadata.payload_checksums_sha256) "descriptor.checksums_sha256" "rc7 compatibility required metadata" "declared-checksum-digest-superseded"
Add-Comparison "declared.rc7_signed_metadata.payload_manifest_sha256" ([string]$descriptor.manifest_sha256) ([string]$rc7SignedMetadata.signature_claims.payload_manifest_content_sha256) "descriptor.manifest_sha256" "rc7 signature claims" "signed-metadata-manifest-digest-superseded"
Add-Comparison "declared.rc7_signed_metadata.revocation_snapshot_sha256" ([string]$descriptor.revocation_snapshot_sha256) ([string]$rc7SignedMetadata.signature_claims.revocation_snapshot_sha256) "descriptor.revocation_snapshot_sha256" "rc7 signature claims" "signed-metadata-revocation-digest-superseded"

foreach ($component in @($rc6PayloadManifest.payload_components)) {
    if ($component.hash_matches_declared -eq $false) {
        Add-Comparison "declared.rc6_payload_component.$($component.id)" ([string]$component.declared_sha256) ([string]$component.observed_sha256) "rc6 payload manifest declared_sha256" "current observed component sha256" "declared-component-hash-drift"
    }
}

$freshness = [ordered]@{
    signed_metadata_fresh = Test-FreshUntil ([string]$rc7SignedMetadata.signature_claims.expires_at) $generatedAt
    revocation_snapshot_fresh = Test-FreshUntil ([string]$rc7RevocationSnapshot.valid_until) $generatedAt
    compatibility_fresh = Test-FreshUntil ([string]$rc7Compatibility.valid_until) $generatedAt
    rollback_baseline_fresh = Test-FreshUntil ([string]$rc7RollbackBaseline.valid_until) $generatedAt
}

$externalObjectMissing = $publicationResult.publication_surface.external_object_url_published -ne $true
$declaredDriftCount = @($script:drifts).Count
$reconciliationState = if ($declaredDriftCount -gt 0) {
    "drift-denied"
} elseif ($externalObjectMissing) {
    "evidence-missing-denied"
} else {
    "reconciled-current-artifact"
}

$blockers = @()
if ($declaredDriftCount -gt 0) {
    $blockers += "declared-current-artifact-drift-denied"
}
if ($externalObjectMissing) {
    $blockers += "external-https-object-uri-not-published"
}
foreach ($blocker in @("installer-quarantine-fetch-not-run", "exact-operator-approval-pending", "controlled-execution-not-authorized")) {
    if ($blockers -notcontains $blocker) {
        $blockers += $blocker
    }
}

Add-Check "source.rc9_010.publication_result" ($publicationResult.status -eq "passed" -and $publicationResult.summary.rc9_010_complete -eq $true) "RC9-010 publication result must pass before drift reconciliation." ([ordered]@{ status = $publicationResult.status; state = $publicationResult.publication_surface.state })
Add-Check "current.payload.bindings" ($sourceArtifactSha256 -eq [string]$descriptor.sha256 -and $sourceArtifactSize -eq [int64]$descriptor.size_bytes -and $payloadManifestSha256 -eq [string]$descriptor.manifest_sha256) "Current payload bytes and manifest must bind to the descriptor before comparing declared metadata." ([ordered]@{ source_sha256 = $sourceArtifactSha256; descriptor_sha256 = $descriptor.sha256; source_size_bytes = $sourceArtifactSize; manifest_sha256 = $payloadManifestSha256 })
Add-Check "mirror.bindings.match_current_descriptor" (@($script:comparisons | Where-Object { $_.id -like "mirror.*" -and $_.status -ne "matched" }).Count -eq 0) "Mirror metadata must still bind to the current descriptor while reconciliation runs." (@($script:comparisons | Where-Object { $_.id -like "mirror.*" }))
Add-Check "declared.drift_detected_and_denied" ($reconciliationState -eq "drift-denied" -and $declaredDriftCount -gt 0) "Declared/current drift must be surfaced as denial evidence, not silently repaired." ([ordered]@{ state = $reconciliationState; drift_count = $declaredDriftCount })
Add-Check "freshness.current" ($freshness.signed_metadata_fresh -and $freshness.revocation_snapshot_fresh -and $freshness.compatibility_fresh -and $freshness.rollback_baseline_fresh) "Freshness windows must be valid even when declared/current drift blocks trust." $freshness

$source = [ordered]@{
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    publication_candidate = New-ArtifactRef $resolvedPublicationCandidatePath $publicationCandidate
    publication_handoff = New-ArtifactRef $resolvedPublicationHandoffPath $publicationHandoff
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    payload_manifest = New-ArtifactRef $resolvedPayloadManifestPath $payloadManifest
    rc6_payload_manifest = New-ArtifactRef $resolvedRc6PayloadManifestPath $rc6PayloadManifest
    signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    rc7_signed_metadata = New-ArtifactRef $resolvedRc7SignedMetadataPath $rc7SignedMetadata
    rc7_revocation_snapshot = New-ArtifactRef $resolvedRc7RevocationSnapshotPath $rc7RevocationSnapshot
    rc7_compatibility = New-ArtifactRef $resolvedRc7CompatibilityPath $rc7Compatibility
    rc7_rollback_baseline = New-ArtifactRef $resolvedRc7RollbackBaselinePath $rc7RollbackBaseline
    support_recovery = New-ArtifactRef $resolvedSupportRecoveryPath $supportRecovery
    hosted_payload_index = New-ArtifactRef $resolvedHostedPayloadIndexPath $hostedPayloadIndex
    install_bootstrap = New-ArtifactRef $resolvedInstallBootstrapPath $installBootstrap
    hosted_channel_index = New-ArtifactRef $resolvedHostedChannelIndexPath $hostedChannelIndex
    source_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

$reconciliation = [ordered]@{
    schema = "agentos.rc9-artifact-drift-reconciliation.v1"
    generated_at = $generatedAt
    task = "RC9-011"
    release_id = $releaseId
    status = $reconciliationState
    production_ready_claim = $false
    source = $source
    freshness = $freshness
    comparison_summary = [ordered]@{
        comparisons = @($script:comparisons).Count
        matched = @($script:comparisons | Where-Object { $_.status -eq "matched" }).Count
        drift = @($script:comparisons | Where-Object { $_.status -eq "drift" }).Count
        missing = @($script:comparisons | Where-Object { $_.status -eq "missing" }).Count
    }
    comparisons = $script:comparisons
    drifts = $script:drifts
    blockers = $blockers
    trust_decision = [ordered]@{
        external_object_trust_allowed = $false
        installer_quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        drift_repair_performed = $false
        superseded_metadata_auto_rewritten = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc9-artifact-drift-denial.v1"
    generated_at = $generatedAt
    task = "RC9-011"
    release_id = $releaseId
    status = "drift-denied"
    production_ready_claim = $false
    denied = $true
    denial_reasons = $blockers
    drift_count = $declaredDriftCount
    drift_ids = @($script:drifts | ForEach-Object { $_.id })
    drifted_rc6_components = @($rc6PayloadManifest.drift_policy.drifted_components)
    preserved_boundaries = [ordered]@{
        mirror_metadata_only = $true
        mirror_not_rewritten = $true
        declared_metadata_not_silently_repaired = $true
        external_object_trust_allowed = $false
        installer_quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_allowed = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc9-post-drift-installer-handoff.v1"
    generated_at = $generatedAt
    task = "RC9-011"
    release_id = $releaseId
    status = "blocked-by-drift"
    production_ready_claim = $false
    publication_result = [ordered]@{
        path = Get-StablePath $resolvedPublicationResultPath
        sha256 = Get-FileSha256 $resolvedPublicationResultPath
        state = [string]$publicationResult.publication_surface.state
    }
    reconciliation = [ordered]@{
        state = $reconciliationState
        artifact_path = ".workflow/artifacts/rc9-artifact-drift-reconciliation/artifact-drift-reconciliation.json"
        drift_denial_path = ".workflow/artifacts/rc9-artifact-drift-reconciliation/drift-denial.json"
    }
    expected_object = [ordered]@{
        object_id = [string]$descriptor.object_id
        size_bytes = [int64]$descriptor.size_bytes
        sha256 = [string]$descriptor.sha256
        descriptor_sha256 = $descriptorSha256
        public_signature_receipt_sha256 = $signatureReceiptSha256
        revocation_snapshot_sha256 = [string]$descriptor.revocation_snapshot_sha256
        installer_compatibility_sha256 = [string]$descriptor.installer_compatibility_sha256
        rollback_baseline_sha256 = [string]$descriptor.rollback_baseline_sha256
    }
    quarantine_policy = [ordered]@{
        quarantine_fetch_allowed = $false
        reason = "blocked-by-publication-or-drift-denial"
        interpret_before_size_digest_signature_verification = $false
    }
    blockers = $blockers
    next_task = "RC9-012"
}

$reconciliationPath = Join-Path $resolvedArtifactDir "artifact-drift-reconciliation.json"
$denialPath = Join-Path $resolvedArtifactDir "drift-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "installer-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $reconciliation $reconciliationPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $reconciliationPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-011 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null
Add-Check "outputs.side_effects_blocked" ($reconciliation.trust_decision.install_allowed -eq $false -and $reconciliation.trust_decision.activation_allowed -eq $false -and $reconciliation.trust_decision.rollback_execution_allowed -eq $false -and $denial.preserved_boundaries.remote_dispatch_allowed -eq $false) "Drift reconciliation must not authorize install, activation, rollback, support upload, or remote dispatch." ([ordered]@{ install_allowed = $reconciliation.trust_decision.install_allowed; activation_allowed = $reconciliation.trust_decision.activation_allowed; rollback_execution_allowed = $reconciliation.trust_decision.rollback_execution_allowed })

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc9-artifact-drift-reconciliation-result.v1"
    generated_at = $generatedAt
    task = "RC9-011"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    reconciliation_surface = [ordered]@{
        state = $reconciliationState
        drift_count = $declaredDriftCount
        external_object_url_published = ($publicationResult.publication_surface.external_object_url_published -eq $true)
        external_object_trust_allowed = $false
        installer_quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $blockers
    }
    outputs = [ordered]@{
        reconciliation = [ordered]@{
            path = Get-StablePath $reconciliationPath
            sha256 = Get-FileSha256 $reconciliationPath
        }
        denial = [ordered]@{
            path = Get-StablePath $denialPath
            sha256 = Get-FileSha256 $denialPath
        }
        installer_handoff = [ordered]@{
            path = Get-StablePath $handoffPath
            sha256 = Get-FileSha256 $handoffPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = $blockers
    invariants = [ordered]@{
        mirror_metadata_only = $true
        mirror_metadata_mutated = $false
        declared_metadata_rewritten = $false
        payload_bytes_uploaded = $false
        payload_bytes_downloaded = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        comparisons = @($script:comparisons).Count
        drift_count = $declaredDriftCount
        rc9_011_complete = ($failedChecks.Count -eq 0)
        next_task = "RC9-012"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-011 result."
}

Write-Host "RC9 artifact drift reconciliation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Reconciliation state: $reconciliationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), drifts: $declaredDriftCount"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
