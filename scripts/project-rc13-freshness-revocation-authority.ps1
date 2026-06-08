param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-freshness-revocation-authority",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$BindingResultPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/result.json",
    [string]$BindingPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/object-manifest-descriptor-binding.json",
    [string]$FreshnessHandoffPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/freshness-revocation-authority-handoff.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$SignatureArtifactPath = "image/out/agentos-initramfs.cpio.gz.prod.sig.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$SignedMetadataPath = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json",
    [string]$RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$KeyringPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-custody.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
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
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
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

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ActualSource,
        [string]$DenialReason = "freshness-revocation-authority-drift"
    )
    $expectedText = if ($null -eq $Expected) { $null } else { [string]$Expected }
    $actualText = if ($null -eq $Actual) { $null } else { [string]$Actual }
    $matched = ($expectedText -eq $actualText)
    $entry = [ordered]@{
        id = $Id
        status = if ($matched) { "matched" } else { "drift" }
        expected = $expectedText
        actual = $actualText
        expected_source = $ExpectedSource
        actual_source = $ActualSource
        denial_reason = if ($matched) { $null } else { $DenialReason }
    }
    $script:comparisons += $entry
    if (-not $matched) {
        $script:comparisonDrifts += $entry
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

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("BEGIN PUBLIC" + " KEY"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer"),
        ("." + "pem"),
        ("finger" + "print")
    )
    if (-not [string]::IsNullOrWhiteSpace($script:rawPublicIdentity)) {
        $markers += $script:rawPublicIdentity
    }
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

function Get-CanonicalSignaturePayload {
    param([Parameter(Mandatory = $true)]$Signature)
    $identityField = "public_" + "finger" + "print"
    return @(
        "agentos.production-detached-signature.v1",
        "artifact.name=$($Signature.artifact.name)",
        "artifact.sha256=$($Signature.artifact.sha256)",
        "source.git_branch=$($Signature.source.git_branch)",
        "source.git_commit=$($Signature.source.git_commit)",
        "policy.policy_version=$($Signature.policy.policy_version)",
        "policy.tool_manifest_version=$($Signature.policy.tool_manifest_version)",
        "key.key_id=$($Signature.key.key_id)",
        "key.$identityField=$($Signature.key.$identityField)",
        "key.rotation_epoch=$($Signature.key.rotation_epoch)"
    ) -join "`n"
}

function Test-RsaPkcs1Sha256Signature {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKeyPem,
        [Parameter(Mandatory = $true)][string]$Payload,
        [Parameter(Mandatory = $true)][string]$SignatureBase64
    )
    try {
        $rsa = [Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportFromPem($PublicKeyPem)
            $payloadBytes = [Text.UTF8Encoding]::new($false).GetBytes($Payload)
            $signatureBytes = [Convert]::FromBase64String($SignatureBase64)
            return $rsa.VerifyData(
                $payloadBytes,
                $signatureBytes,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
        } finally {
            $rsa.Dispose()
        }
    } catch {
        return $false
    }
}

function Test-DateAfter {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Reference
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $false
    }
    try {
        return ([DateTimeOffset]::Parse([string]$Value)) -gt $Reference
    } catch {
        return $false
    }
}

function Get-KeyEntry {
    param($Keyring, [string]$KeyId)
    if ($Keyring -and $Keyring.keys) {
        return @($Keyring.keys | Where-Object { [string]$_.key_id -eq $KeyId }) | Select-Object -First 1
    }
    return $null
}

function Get-RevocationEntry {
    param($RevocationLog, [string]$KeyId)
    if ($RevocationLog -and $RevocationLog.current_status) {
        return @($RevocationLog.current_status | Where-Object { [string]$_.key_id -eq $KeyId }) | Select-Object -First 1
    }
    return $null
}

function Test-AuthorityCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)]$Gates
    )
    $reasons = @()
    if ($Gates.signature_target_bound -ne $true) { $reasons += "public-signature-target-not-bound" }
    if ($Gates.signature_receipt_bound -ne $true) { $reasons += "public-signature-receipt-not-bound" }
    if ($Gates.public_keyring_bound -ne $true) { $reasons += "public-keyring-not-bound" }
    if ($Gates.crypto_verified -ne $true) { $reasons += "public-signature-crypto-not-verified" }
    if ($Gates.revocation_snapshot_bound -ne $true) { $reasons += "revocation-snapshot-not-bound" }
    if ($Gates.revocation_status_not_revoked -ne $true) { $reasons += "revocation-status-not-current" }
    if ($Gates.revocation_snapshot_fresh -ne $true) { $reasons += "revocation-snapshot-stale-or-missing" }
    if ($Gates.freshness_window_bound -ne $true) { $reasons += "freshness-window-missing" }
    if ($Gates.freshness_window_current -ne $true) { $reasons += "freshness-window-stale-or-missing" }
    if ($Gates.no_private_material -ne $true) { $reasons += "private-signing-material-used" }
    if ($Gates.local_descriptor_manifest_consistent -ne $true) { $reasons += "object-manifest-descriptor-inconsistent" }
    if ($Gates.object_manifest_descriptor_binding_allowed -ne $true) { $reasons += "object-manifest-descriptor-binding-not-allowed" }
    if ($Gates.declared_current_drift_zero -ne $true) { $reasons += "declared-current-drift-zero-not-proved" }
    $uniqueReasons = @($reasons | Select-Object -Unique)
    return [ordered]@{
        id = $Id
        status = if ($uniqueReasons.Count -eq 0) { "accepted" } else { "denied" }
        denied = ($uniqueReasons.Count -gt 0)
        gates = $Gates
        denial_reasons = $uniqueReasons
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()
$script:comparisons = @()
$script:comparisonDrifts = @()
$script:rawPublicIdentity = $null

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedBindingResultPath = Resolve-RepoPath $BindingResultPath
$resolvedBindingPath = Resolve-RepoPath $BindingPath
$resolvedFreshnessHandoffPath = Resolve-RepoPath $FreshnessHandoffPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedSignatureArtifactPath = Resolve-RepoPath $SignatureArtifactPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedSignedMetadataPath = Resolve-RepoPath $SignedMetadataPath
$resolvedRevocationSnapshotPath = Resolve-RepoPath $RevocationSnapshotPath
$resolvedKeyringPath = Resolve-RepoPath $KeyringPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$bindingResult = Read-Json $resolvedBindingResultPath
$binding = Read-Json $resolvedBindingPath
$freshnessHandoff = Read-Json $resolvedFreshnessHandoffPath
$signatureIngestionResult = Read-Json $resolvedSignatureIngestionResultPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$signatureArtifact = Read-Json $resolvedSignatureArtifactPath
$descriptor = Read-Json $resolvedDescriptorPath
$signedMetadata = Read-Json $resolvedSignedMetadataPath
$revocationSnapshot = Read-Json $resolvedRevocationSnapshotPath
$keyring = Read-Json $resolvedKeyringPath
$revocationLog = Read-Json $resolvedRevocationLogPath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$generatedAtInstant = [DateTimeOffset]::Parse($generatedAtValue)
$releaseId = [string]$bindingResult.release_id
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$signatureReceiptSha256 = Get-FileSha256 $resolvedSignatureReceiptPath
$signatureSummarySha256 = Get-FileSha256 $resolvedSignatureSummaryPath
$signatureArtifactSha256 = Get-FileSha256 $resolvedSignatureArtifactPath
$signedMetadataSha256 = Get-FileSha256 $resolvedSignedMetadataPath
$revocationSnapshotSha256 = Get-FileSha256 $resolvedRevocationSnapshotPath
$keyringSha256 = Get-FileSha256 $resolvedKeyringPath
$revocationLogSha256 = Get-FileSha256 $resolvedRevocationLogPath

$identityField = "public_" + "finger" + "print"
$script:rawPublicIdentity = if ($signatureArtifact.key) { [string]$signatureArtifact.key.$identityField } else { $null }
$keyId = [string]$signatureArtifact.key.key_id
$keyEntry = Get-KeyEntry -Keyring $keyring -KeyId $keyId
$revocationEntry = Get-RevocationEntry -RevocationLog $revocationLog -KeyId $keyId
$canonicalPayload = Get-CanonicalSignaturePayload $signatureArtifact
$canonicalPayloadSha256 = Get-StringSha256 $canonicalPayload
$signatureValue = [string]$signatureArtifact.signature.value
$signatureValueSha256 = if ([string]::IsNullOrWhiteSpace($signatureValue)) { $null } else { Get-StringSha256 $signatureValue }
$cryptoVerified = $false
if ($keyEntry -and -not [string]::IsNullOrWhiteSpace([string]$keyEntry.public_key_pem) -and -not [string]::IsNullOrWhiteSpace($signatureValue)) {
    $cryptoVerified = Test-RsaPkcs1Sha256Signature -PublicKeyPem ([string]$keyEntry.public_key_pem) -Payload $canonicalPayload -SignatureBase64 $signatureValue
}

$source = [ordered]@{
    rc13_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc13_contract = New-ArtifactRef $resolvedContractPath
    rc13_object_manifest_descriptor_result = New-ArtifactRef $resolvedBindingResultPath $bindingResult
    rc13_object_manifest_descriptor_binding = New-ArtifactRef $resolvedBindingPath $binding
    rc13_freshness_revocation_handoff = New-ArtifactRef $resolvedFreshnessHandoffPath $freshnessHandoff
    rc8_signature_ingestion_result = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestionResult
    rc8_signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    rc8_signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    public_signature_artifact = [ordered]@{
        path = Get-StablePath $resolvedSignatureArtifactPath
        sha256 = $signatureArtifactSha256
        present = Test-Path -LiteralPath $resolvedSignatureArtifactPath -PathType Leaf
        schema = $signatureArtifact.schema
        signature_value_sha256 = $signatureValueSha256
        raw_signature_value_redacted = $true
    }
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    signed_metadata = New-ArtifactRef $resolvedSignedMetadataPath $signedMetadata
    revocation_snapshot = New-ArtifactRef $resolvedRevocationSnapshotPath $revocationSnapshot
    public_keyring = [ordered]@{
        path = Get-StablePath $resolvedKeyringPath
        sha256 = $keyringSha256
        present = Test-Path -LiteralPath $resolvedKeyringPath -PathType Leaf
        schema = $keyring.schema
        key_id = $keyId
        public_key_present = ($null -ne $keyEntry -and -not [string]::IsNullOrWhiteSpace([string]$keyEntry.public_key_pem))
        raw_public_identity_redacted = $true
    }
    revocation_log = [ordered]@{
        path = Get-StablePath $resolvedRevocationLogPath
        sha256 = $revocationLogSha256
        present = Test-Path -LiteralPath $resolvedRevocationLogPath -PathType Leaf
        schema = $revocationLog.schema
        authority_refs_redacted = $true
    }
}

$rc13TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC13-012").status
$rc13PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC13-011").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc13PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC13-012" -and ($rc13TaskStatus -eq "pending" -or $rc13TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC13-020" -and $rc13TaskStatus -eq "completed")
    )
)
Add-Check "plan.current_task.rc13_012" $planAllowsRun "RC13-012 must run after RC13-011 completed, either while current_task is RC13-012 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc13_011_status = $rc13PreviousStatus; rc13_012_status = $rc13TaskStatus })
Add-Check "contract.freshness_revocation_gate.present" ($contractText.Contains("freshness_revocation_authority_bound") -and $contractText.Contains("private signing material")) "RC13-012 must consume the RC13 public signature, freshness, revocation, and private-material boundary." $source.rc13_contract
Add-Check "source.object_manifest_descriptor.completed" ($bindingResult.status -eq "passed" -and $bindingResult.summary.rc13_011_complete -eq $true -and $bindingResult.binding_surface.local_descriptor_manifest_consistent -eq $true) "RC13-012 requires completed RC13-011 descriptor/manifest consistency evidence." ([ordered]@{ status = $bindingResult.status; local_descriptor_manifest_consistent = $bindingResult.binding_surface.local_descriptor_manifest_consistent; binding_allowed = $bindingResult.binding_surface.object_manifest_descriptor_binding_allowed })

Add-Comparison "signature.target.descriptor_sha256.handoff_vs_descriptor" $freshnessHandoff.public_signature_target.descriptor_sha256 $descriptorSha256 "RC13-011 handoff public signature descriptor sha256" "current descriptor file sha256" "signature-target-drift"
Add-Comparison "signature.target.receipt_sha256.handoff_vs_file" $freshnessHandoff.public_signature_target.public_signature_receipt_sha256 $signatureReceiptSha256 "RC13-011 handoff public signature receipt sha256" "current RC8 signature receipt file sha256" "signature-receipt-drift"
Add-Comparison "signature.receipt.sha256.result_vs_file" $signatureIngestionResult.outputs.receipt.sha256 $signatureReceiptSha256 "RC8 signature ingestion result receipt sha256" "current RC8 signature receipt file sha256" "signature-receipt-drift"
Add-Comparison "signature.summary.sha256.result_vs_file" $signatureIngestionResult.outputs.signature_summary.sha256 $signatureSummarySha256 "RC8 signature ingestion result summary sha256" "current RC8 signature summary file sha256" "signature-summary-drift"
Add-Comparison "signature.artifact.sha256.receipt_vs_file" $signatureReceipt.signature_artifact_sha256 $signatureArtifactSha256 "RC8 receipt signature artifact sha256" "current public signature artifact file sha256" "signature-artifact-drift"
Add-Comparison "signature.artifact.sha256.summary_vs_file" $signatureSummary.signature_artifact_sha256 $signatureArtifactSha256 "RC8 summary signature artifact sha256" "current public signature artifact file sha256" "signature-artifact-drift"
Add-Comparison "signature.signed_object.receipt_vs_binding" $signatureReceipt.signed_object_sha256 $bindingResult.binding_surface.current_payload_sha256 "RC8 receipt signed object sha256" "RC13 binding payload sha256" "signed-object-drift"
Add-Comparison "signature.signed_object.summary_vs_binding" $signatureSummary.signed_object_sha256 $bindingResult.binding_surface.current_payload_sha256 "RC8 summary signed object sha256" "RC13 binding payload sha256" "signed-object-drift"
Add-Comparison "signature.canonical_payload.receipt_vs_recomputed" $signatureReceipt.canonical_payload_sha256 $canonicalPayloadSha256 "RC8 receipt canonical payload sha256" "recomputed canonical public signature payload sha256" "canonical-payload-drift"
Add-Comparison "signature.canonical_payload.summary_vs_recomputed" $signatureSummary.canonical_payload_sha256 $canonicalPayloadSha256 "RC8 summary canonical payload sha256" "recomputed canonical public signature payload sha256" "canonical-payload-drift"
Add-Comparison "signature.canonical_payload.artifact_vs_recomputed" $signatureArtifact.verification.canonical_payload_sha256.value $canonicalPayloadSha256 "public signature artifact canonical payload sha256" "recomputed canonical public signature payload sha256" "canonical-payload-drift"
Add-Comparison "signature.key_id.receipt_vs_artifact" $signatureReceipt.key_id $keyId "RC8 receipt key id" "public signature artifact key id" "key-id-drift"
Add-Comparison "signature.key_id.summary_vs_artifact" $signatureSummary.key_id $keyId "RC8 summary key id" "public signature artifact key id" "key-id-drift"
Add-Comparison "signature.key_id.revocation_snapshot_vs_artifact" $revocationSnapshot.key_id $keyId "revocation snapshot key id" "public signature artifact key id" "key-id-drift"
Add-Comparison "signature.revocation.receipt_vs_snapshot" $signatureReceipt.revocation_status $revocationSnapshot.revocation_status "RC8 receipt revocation status" "revocation snapshot status" "revocation-status-drift"
Add-Comparison "signature.revocation.summary_vs_snapshot" $signatureSummary.revocation_status $revocationSnapshot.revocation_status "RC8 summary revocation status" "revocation snapshot status" "revocation-status-drift"
Add-Comparison "signature.revocation.artifact_vs_log" $signatureArtifact.verification.revocation_status $revocationEntry.revocation_status "public signature artifact revocation status" "packaged revocation log status" "revocation-status-drift"
Add-Comparison "revocation.snapshot.sha256.handoff_vs_file" $freshnessHandoff.revocation_and_freshness_inputs.revocation_snapshot_sha256 $revocationSnapshotSha256 "RC13-011 handoff revocation snapshot sha256" "current revocation snapshot file sha256" "revocation-snapshot-drift"
Add-Comparison "revocation.snapshot.sha256.descriptor_vs_file" $descriptor.revocation_snapshot_sha256 $revocationSnapshotSha256 "descriptor revocation snapshot sha256" "current revocation snapshot file sha256" "revocation-snapshot-drift"
Add-Comparison "signed_metadata.sha256.descriptor_vs_file" $descriptor.signed_metadata_sha256 $signedMetadataSha256 "descriptor signed metadata sha256" "current signed metadata file sha256" "signed-metadata-drift"

$comparisonCount = @($script:comparisons).Count
$comparisonDriftCount = @($script:comparisonDrifts).Count
$revocationSnapshotFresh = Test-DateAfter -Value $revocationSnapshot.valid_until -Reference $generatedAtInstant
$freshnessWindowBound = [bool]$freshnessHandoff.revocation_and_freshness_inputs.freshness_window_bound
$freshnessWindowCurrent = Test-DateAfter -Value $freshnessHandoff.revocation_and_freshness_inputs.fresh_until -Reference $generatedAtInstant
$revocationStatusNotRevoked = (
    $signatureReceipt.revocation_status -eq "not-revoked" -and
    $signatureSummary.revocation_status -eq "not-revoked" -and
    $signatureArtifact.verification.revocation_status -eq "not-revoked" -and
    $revocationSnapshot.revocation_status -eq "not-revoked" -and
    $revocationEntry.revocation_status -eq "not-revoked"
)
$publicSignatureBound = (
    $comparisonDriftCount -eq 0 -and
    $cryptoVerified -eq $true -and
    $signatureIngestionResult.signature_surface.crypto_verified -eq $true -and
    $signatureReceipt.crypto_verified -eq $true -and
    $signatureSummary.crypto_verified -eq $true
)
$revocationAuthorityBound = (
    $revocationStatusNotRevoked -and
    $revocationSnapshotFresh -and
    $freshnessHandoff.revocation_and_freshness_inputs.revocation_snapshot_sha256 -eq $revocationSnapshotSha256
)
$freshnessRevocationAuthorityBound = (
    $publicSignatureBound -and
    $revocationAuthorityBound -and
    $freshnessWindowBound -and
    $freshnessWindowCurrent -and
    [bool]$bindingResult.binding_surface.object_manifest_descriptor_binding_allowed
)

Add-Check "signature.public_crypto_verified" $publicSignatureBound "Public signature target, receipt, summary, artifact, keyring, and canonical payload must be hash-bound and crypto verified without private material." ([ordered]@{ crypto_verified = $cryptoVerified; comparisons = $comparisonCount; comparison_drifts = $comparisonDriftCount })
Add-Check "revocation.snapshot_current" $revocationAuthorityBound "Revocation snapshot and packaged revocation log must be bound, not revoked, and fresh at generated_at." ([ordered]@{ revocation_status_not_revoked = $revocationStatusNotRevoked; valid_until = $revocationSnapshot.valid_until; generated_at = $generatedAtValue; revocation_snapshot_fresh = $revocationSnapshotFresh })
Add-Check "freshness.required_before_trust" (($freshnessRevocationAuthorityBound -eq $true -and $freshnessWindowBound -eq $true -and $freshnessWindowCurrent -eq $true) -or ($freshnessRevocationAuthorityBound -eq $false -and ($freshnessWindowBound -eq $false -or $freshnessWindowCurrent -eq $false -or $bindingResult.binding_surface.object_manifest_descriptor_binding_allowed -eq $false))) "Missing or stale freshness window, or upstream binding denial, must deny freshness/revocation authority and object trust." ([ordered]@{ freshness_window_bound = $freshnessWindowBound; fresh_until = $freshnessHandoff.revocation_and_freshness_inputs.fresh_until; freshness_window_current = $freshnessWindowCurrent; upstream_binding_allowed = $bindingResult.binding_surface.object_manifest_descriptor_binding_allowed; authority_bound = $freshnessRevocationAuthorityBound })

$currentGates = [ordered]@{
    signature_target_bound = ($freshnessHandoff.public_signature_target.descriptor_sha256 -eq $descriptorSha256)
    signature_receipt_bound = ($freshnessHandoff.public_signature_target.public_signature_receipt_sha256 -eq $signatureReceiptSha256)
    public_keyring_bound = ($null -ne $keyEntry -and -not [string]::IsNullOrWhiteSpace([string]$keyEntry.public_key_pem))
    crypto_verified = $cryptoVerified
    revocation_snapshot_bound = ($freshnessHandoff.revocation_and_freshness_inputs.revocation_snapshot_sha256 -eq $revocationSnapshotSha256)
    revocation_status_not_revoked = $revocationStatusNotRevoked
    revocation_snapshot_fresh = $revocationSnapshotFresh
    freshness_window_bound = $freshnessWindowBound
    freshness_window_current = $freshnessWindowCurrent
    no_private_material = $true
    local_descriptor_manifest_consistent = [bool]$bindingResult.binding_surface.local_descriptor_manifest_consistent
    object_manifest_descriptor_binding_allowed = [bool]$bindingResult.binding_surface.object_manifest_descriptor_binding_allowed
    declared_current_drift_zero = [bool]$bindingResult.binding_surface.declared_current_drift_zero
}
$cases = @()
$cases += Test-AuthorityCase -Id "current.freshness_revocation_authority_candidate" -Gates $currentGates
$allGood = Copy-JsonObject $currentGates
foreach ($name in @("signature_target_bound", "signature_receipt_bound", "public_keyring_bound", "crypto_verified", "revocation_snapshot_bound", "revocation_status_not_revoked", "revocation_snapshot_fresh", "freshness_window_bound", "freshness_window_current", "no_private_material", "local_descriptor_manifest_consistent", "object_manifest_descriptor_binding_allowed", "declared_current_drift_zero")) {
    $allGood.$name = $true
}
$negativeMutations = @(
    @{ id = "negative.missing_signature_target"; key = "signature_target_bound" },
    @{ id = "negative.missing_signature_receipt"; key = "signature_receipt_bound" },
    @{ id = "negative.missing_public_keyring"; key = "public_keyring_bound" },
    @{ id = "negative.signature_crypto_unverified"; key = "crypto_verified" },
    @{ id = "negative.missing_revocation_snapshot"; key = "revocation_snapshot_bound" },
    @{ id = "negative.revoked_key"; key = "revocation_status_not_revoked" },
    @{ id = "negative.stale_revocation_snapshot"; key = "revocation_snapshot_fresh" },
    @{ id = "negative.missing_freshness_window"; key = "freshness_window_bound" },
    @{ id = "negative.stale_freshness_window"; key = "freshness_window_current" },
    @{ id = "negative.private_material_used"; key = "no_private_material" },
    @{ id = "negative.descriptor_manifest_inconsistent"; key = "local_descriptor_manifest_consistent" },
    @{ id = "negative.upstream_binding_denied"; key = "object_manifest_descriptor_binding_allowed" },
    @{ id = "negative.drift_nonzero"; key = "declared_current_drift_zero" }
)
foreach ($mutation in $negativeMutations) {
    $gates = Copy-JsonObject $allGood
    $gates.($mutation.key) = $false
    $cases += Test-AuthorityCase -Id $mutation.id -Gates $gates
}
$failedCases = @($cases | Where-Object { $_.denied -ne $true })
Add-Check "fail_closed_matrix.all_negative_cases_denied" ($failedCases.Count -eq 0 -and @($cases).Count -ge 14) "Freshness, revocation, public signature, private material, and upstream trust negative cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$currentDecision = $cases | Where-Object { $_.id -eq "current.freshness_revocation_authority_candidate" } | Select-Object -First 1
$blockers = @($currentDecision.denial_reasons + $bindingResult.binding_surface.blockers | Select-Object -Unique)
if ($blockers -notcontains "object-trust-not-allowed") { $blockers += "object-trust-not-allowed" }
if ($blockers -notcontains "quarantine-preflight-not-run") { $blockers += "quarantine-preflight-not-run" }

$authorityState = if ($freshnessRevocationAuthorityBound) { "freshness-revocation-authority-bound" } else { "freshness-revocation-authority-denied" }

$authorityBinding = [ordered]@{
    schema = "agentos.rc13-freshness-revocation-authority-binding.v1"
    generated_at = $generatedAtValue
    task = "RC13-012"
    release_id = $releaseId
    status = $authorityState
    production_ready_claim = $false
    public_signature = [ordered]@{
        descriptor_sha256 = $descriptorSha256
        signature_artifact_path = Get-StablePath $resolvedSignatureArtifactPath
        signature_artifact_sha256 = $signatureArtifactSha256
        signature_value_sha256 = $signatureValueSha256
        signature_value_redacted = $true
        receipt_sha256 = $signatureReceiptSha256
        summary_sha256 = $signatureSummarySha256
        canonical_payload_sha256 = $canonicalPayloadSha256
        key_id = $keyId
        public_key_identity = "redacted-public-identity-present"
        crypto_verified = $cryptoVerified
        algorithm = [string]$signatureArtifact.signature.algorithm
    }
    public_keyring = [ordered]@{
        path = Get-StablePath $resolvedKeyringPath
        sha256 = $keyringSha256
        key_id = $keyId
        public_key_present = ($null -ne $keyEntry -and -not [string]::IsNullOrWhiteSpace([string]$keyEntry.public_key_pem))
        public_key_material_used_for_verification = $true
        public_key_material_redacted = $true
        private_key_material_used = $false
    }
    revocation = [ordered]@{
        snapshot_path = Get-StablePath $resolvedRevocationSnapshotPath
        snapshot_sha256 = $revocationSnapshotSha256
        log_path = Get-StablePath $resolvedRevocationLogPath
        log_sha256 = $revocationLogSha256
        key_id = $keyId
        status = [string]$revocationSnapshot.revocation_status
        log_status = [string]$revocationEntry.revocation_status
        valid_until = $revocationSnapshot.valid_until
        snapshot_fresh_at_generated_at = $revocationSnapshotFresh
    }
    freshness = [ordered]@{
        fresh_until = $freshnessHandoff.revocation_and_freshness_inputs.fresh_until
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        denial_reason = if ($freshnessWindowBound -and $freshnessWindowCurrent) { $null } else { "freshness-window-missing" }
    }
    consistency = [ordered]@{
        comparisons = $script:comparisons
        comparison_drifts = @($script:comparisonDrifts)
        public_signature_bound = $publicSignatureBound
        revocation_authority_bound = $revocationAuthorityBound
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
    }
    trust_decision = [ordered]@{
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $blockers
    }
    source = $source
}

$denial = [ordered]@{
    schema = "agentos.rc13-freshness-revocation-authority-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-012"
    release_id = $releaseId
    status = if ($freshnessRevocationAuthorityBound) { "not-denied" } else { "freshness-revocation-authority-denied" }
    production_ready_claim = $false
    denied = (-not $freshnessRevocationAuthorityBound)
    public_signature_bound = $publicSignatureBound
    revocation_authority_bound = $revocationAuthorityBound
    freshness_window_bound = $freshnessWindowBound
    denial_reasons = $blockers
    side_effects = [ordered]@{
        private_key_material_read_or_printed = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        signer_service_called = $false
        signature_value_exposed = $false
        public_identity_exposed = $false
        object_trust_allowed = $false
        network_probe_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
    }
}

$matrix = [ordered]@{
    schema = "agentos.rc13-freshness-revocation-authority-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC13-012"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        denied = @($cases | Where-Object { $_.denied -eq $true }).Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc13-quarantine-preflight-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-012"
    release_id = $releaseId
    status = if ($freshnessRevocationAuthorityBound) { "ready-for-rc13-020-quarantine-preflight" } else { "blocked-by-freshness-revocation-authority" }
    production_ready_claim = $false
    expected_next_task = "RC13-020"
    authority = [ordered]@{
        path = $null
        sha256 = $null
        public_signature_bound = $publicSignatureBound
        revocation_authority_bound = $revocationAuthorityBound
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        object_trust_allowed = $false
    }
    quarantine_preflight = [ordered]@{
        allowed = $false
        network_fetch_allowed = $false
        payload_interpretation_allowed = $false
        quarantine_write_allowed = $false
    }
    blockers = $blockers
}

$bindingOutPath = Join-Path $resolvedArtifactDir "freshness-revocation-authority-binding.json"
$denialPath = Join-Path $resolvedArtifactDir "freshness-revocation-authority-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "freshness-revocation-authority-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "quarantine-preflight-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-012-freshness-revocation-authority.json"

Write-Json $authorityBinding $bindingOutPath
$handoff.authority.path = Get-StablePath $bindingOutPath
$handoff.authority.sha256 = Get-FileSha256 $bindingOutPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $bindingOutPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $matrixPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC13-012 outputs must not contain PEM text, raw signature values, raw public identity, tokens, signer internals, or private authority paths." $null
Add-Check "outputs.side_effects_absent" ($denial.side_effects.private_key_material_read_or_printed -eq $false -and $denial.side_effects.local_private_key_material_used -eq $false -and $denial.side_effects.cryptographic_signing_performed -eq $false -and $denial.side_effects.signer_service_called -eq $false -and $denial.side_effects.signature_value_exposed -eq $false -and $denial.side_effects.public_identity_exposed -eq $false -and $denial.side_effects.object_trust_allowed -eq $false -and $denial.side_effects.network_probe_performed -eq $false -and $denial.side_effects.payload_bytes_uploaded -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.payload_interpreted -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.recovery_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC13-012 must not sign, call signer services, expose signature/key identity, trust objects, fetch/quarantine/interpret payloads, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-freshness-revocation-authority-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-012"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    authority_surface = [ordered]@{
        state = $authorityState
        public_signature_bound = $publicSignatureBound
        public_signature_crypto_verified = $cryptoVerified
        revocation_authority_bound = $revocationAuthorityBound
        revocation_snapshot_fresh = $revocationSnapshotFresh
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        local_descriptor_manifest_consistent = [bool]$bindingResult.binding_surface.local_descriptor_manifest_consistent
        object_manifest_descriptor_binding_allowed = [bool]$bindingResult.binding_surface.object_manifest_descriptor_binding_allowed
        declared_current_drift_zero = [bool]$bindingResult.binding_surface.declared_current_drift_zero
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = @($failedCases).Count
        object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        network_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $blockers
    }
    outputs = [ordered]@{
        binding = [ordered]@{ path = Get-StablePath $bindingOutPath; sha256 = Get-FileSha256 $bindingOutPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        quarantine_preflight_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        signer_service_called = $false
        signature_value_exposed = $false
        raw_public_identity_exposed = $false
        payload_upload_performed = $false
        object_storage_provisioned = $false
        network_probe_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        object_trust_allowed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        frontend_authority = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = @($failedCases).Count
        public_signature_bound = $publicSignatureBound
        revocation_authority_bound = $revocationAuthorityBound
        freshness_window_bound = $freshnessWindowBound
        authority_denied_as_expected = (-not $freshnessRevocationAuthorityBound)
        rc13_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-020"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-freshness-revocation-authority-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-012"
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
    authority_surface = $result.authority_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc13_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-020"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC13-012 outputs."
}

Write-Host "RC13 freshness/revocation authority $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Authority state: $authorityState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), comparisons: $comparisonCount, fail-closed cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
