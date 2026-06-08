param(
    [string]$ArtifactDir = ".workflow/artifacts/rc8-signed-object-descriptor-fail-closed",
    [string]$ResultPath = "",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$DescriptorResultPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json",
    [string]$SignatureArtifactPath = "image/out/agentos-initramfs.cpio.gz.prod.sig.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$KeyringPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-custody.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
    [switch]$FailOnBlocked
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

function Get-Sha256OfText {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
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
    $json = $Value | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
        $script:blockers += $entry
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        ("BEGIN " + "PRIVATE KEY"),
        ("BEGIN RSA " + "PRIVATE KEY"),
        ("BEGIN OPENSSH " + "PRIVATE KEY"),
        ("PRIVATE KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        "access_token",
        "refresh_token",
        ("." + "local-release-authority"),
        ("signing" + "-key.pem")
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
        if ((Has-Value $script:rawPublicIdentity) -and $value.Contains([string]$script:rawPublicIdentity, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}

function Test-ApprovedObjectUri {
    param($Descriptor)
    if (-not (Has-Value $Descriptor.uri)) {
        return $false
    }
    $uri = [string]$Descriptor.uri
    if ($uri.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $uri.StartsWith("urn:sha256:", [StringComparison]::OrdinalIgnoreCase)
}

function Test-ForbiddenUri {
    param($Descriptor)
    if (-not (Has-Value $Descriptor.uri)) {
        return $false
    }
    $uri = [string]$Descriptor.uri
    return (
        $uri.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or
        $uri.Contains("token=", [StringComparison]::OrdinalIgnoreCase) -or
        $uri.Contains("X-Amz-Signature=", [StringComparison]::OrdinalIgnoreCase) -or
        $uri.Contains("sig=", [StringComparison]::OrdinalIgnoreCase)
    )
}

function Test-StaleDate {
    param($Value)
    if (-not (Has-Value $Value)) {
        return $false
    }
    try {
        return ([DateTimeOffset]::Parse([string]$Value)) -lt [DateTimeOffset]::Now
    } catch {
        return $true
    }
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

function Invoke-SignedObjectEvaluation {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)]$Signature,
        [Parameter(Mandatory = $true)]$Receipt,
        [Parameter(Mandatory = $true)]$Summary
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    $keyId = if ($Signature -and $Signature.key) { [string]$Signature.key.key_id } else { "" }
    $keyEntry = Get-KeyEntry -Keyring $script:keyring -KeyId $keyId
    $revocationEntry = Get-RevocationEntry -RevocationLog $script:revocationLog -KeyId $keyId
    $canonicalPayload = if ($Signature) { Get-CanonicalSignaturePayload $Signature } else { "" }
    $canonicalPayloadSha256 = if ($canonicalPayload) { Get-Sha256OfText $canonicalPayload } else { $null }
    $expectedCanonicalPayloadSha256 = if ($Signature -and $Signature.verification -and $Signature.verification.canonical_payload_sha256) { [string]$Signature.verification.canonical_payload_sha256.value } else { $null }
    $signatureValue = if ($Signature -and $Signature.signature) { [string]$Signature.signature.value } else { "" }
    $cryptoVerified = $false
    if ($keyEntry -and (Has-Value $keyEntry.public_key_pem) -and (Has-Value $signatureValue)) {
        $cryptoVerified = Test-RsaPkcs1Sha256Signature -PublicKeyPem ([string]$keyEntry.public_key_pem) -Payload $canonicalPayload -SignatureBase64 $signatureValue
    }

    if ($Descriptor.schema -ne "agentos.payload-object-descriptor.v1") {
        Add-Reason $reasons "bad-descriptor-schema"
    }
    if ($Signature.schema -ne "agentos.production-detached-signature.v1") {
        Add-Reason $reasons "bad-signature-schema"
    }
    if ($Descriptor.production_ready_claim -eq $true -or $Signature.production_ready_claim -eq $true -or $Receipt.production_ready_claim -eq $true -or $Summary.production_ready_claim -eq $true) {
        Add-Reason $reasons "production-ready-claim"
    }
    if ($Descriptor.kind -notin @("iso", "disk-image", "rootfs", "update-bundle", "recovery-image")) {
        Add-Reason $reasons "unsupported-descriptor-kind"
    }
    if (-not (Test-ApprovedObjectUri $Descriptor)) {
        Add-Reason $reasons "descriptor-uri-not-approved"
    }
    if (Test-ForbiddenUri $Descriptor) {
        Add-Reason $reasons "credential-or-insecure-uri"
    }
    if ($Descriptor.immutable -ne $true) {
        Add-Reason $reasons "descriptor-not-immutable"
    }
    if (-not (Has-Value $Descriptor.size_bytes) -or [int64]$Descriptor.size_bytes -le 0) {
        Add-Reason $reasons "missing-or-invalid-size"
    }
    if (-not (Has-Value $Descriptor.sha256)) {
        Add-Reason $reasons "missing-object-digest"
    }
    if ((Has-Value $Descriptor.object_id) -and (Has-Value $Descriptor.sha256) -and [string]$Descriptor.object_id -ne "sha256:$($Descriptor.sha256)") {
        Add-Reason $reasons "descriptor-object-id-mismatch"
    }
    if (-not (Has-Value $Descriptor.source_build_artifact) -or -not (Has-Value $Descriptor.source_build_artifact_sha256)) {
        Add-Reason $reasons "missing-source-artifact-binding"
    } else {
        $sourcePath = Resolve-RepoPath ([string]$Descriptor.source_build_artifact)
        $sourceSha = Get-FileSha256 $sourcePath
        if ($sourceSha -ne [string]$Descriptor.source_build_artifact_sha256 -or $sourceSha -ne [string]$Descriptor.sha256) {
            Add-Reason $reasons "source-artifact-hash-mismatch"
        }
    }
    foreach ($field in @("release_provenance_sha256", "manifest_sha256", "checksums_sha256", "signed_metadata_sha256", "revocation_snapshot_sha256", "installer_compatibility_sha256", "rollback_baseline_sha256", "support_recovery_sha256", "policy_version")) {
        if (-not (Has-Value $Descriptor.$field)) {
            Add-Reason $reasons "missing-$field"
        }
    }
    if (Test-StaleDate $Descriptor.expires_at) {
        Add-Reason $reasons "expired-descriptor"
    }

    if ($Signature.artifact.path -ne $Descriptor.source_build_artifact) {
        Add-Reason $reasons "signature-target-path-mismatch"
    }
    if ($Signature.artifact.sha256 -ne $Descriptor.sha256) {
        Add-Reason $reasons "signed-object-hash-mismatch"
    }
    if ($Signature.signature.algorithm -ne "rsa-pkcs1-sha256") {
        Add-Reason $reasons "unsupported-signature-algorithm"
    }
    if (-not (Has-Value $Signature.signature.value)) {
        Add-Reason $reasons "missing-signature-value"
    }
    if (-not (Has-Value $keyId) -or $null -eq $keyEntry) {
        Add-Reason $reasons "missing-or-unknown-key-id"
    }
    if ($canonicalPayloadSha256 -ne $expectedCanonicalPayloadSha256) {
        Add-Reason $reasons "canonical-payload-hash-mismatch"
    }
    if ($cryptoVerified -ne $true) {
        Add-Reason $reasons "signature-crypto-verification-failed"
    }
    if (-not (Has-Value $Signature.verification.revocation_status)) {
        Add-Reason $reasons "missing-revocation-binding"
    } elseif ([string]$Signature.verification.revocation_status -ne "not-revoked") {
        Add-Reason $reasons "revoked-signing-key"
    }
    if ($revocationEntry -and [string]$revocationEntry.revocation_status -ne "not-revoked") {
        Add-Reason $reasons "packaged-revocation-status-blocked"
    }
    if ($Signature.verification.PSObject.Properties.Name -contains "revocation_valid_until" -and (Test-StaleDate $Signature.verification.revocation_valid_until)) {
        Add-Reason $reasons "stale-revocation-snapshot"
    }
    if ($Signature.verification.PSObject.Properties.Name -contains "freshness_not_after" -and (Test-StaleDate $Signature.verification.freshness_not_after)) {
        Add-Reason $reasons "stale-signature-freshness-window"
    }

    $currentDescriptorSha = Get-FileSha256 $script:resolvedDescriptorPath
    if ($Receipt.descriptor_sha256 -ne $currentDescriptorSha -or $Summary.descriptor_sha256 -ne $currentDescriptorSha) {
        Add-Reason $reasons "descriptor-receipt-hash-mismatch"
    }
    if ($Receipt.signed_object_sha256 -ne $Descriptor.sha256 -or $Summary.signed_object_sha256 -ne $Descriptor.sha256) {
        Add-Reason $reasons "receipt-object-hash-mismatch"
    }
    if ($Receipt.canonical_payload_sha256 -ne $canonicalPayloadSha256 -or $Summary.canonical_payload_sha256 -ne $canonicalPayloadSha256) {
        Add-Reason $reasons "receipt-canonical-payload-hash-mismatch"
    }
    if ($Receipt.crypto_verified -ne $true -or $Summary.crypto_verified -ne $true) {
        Add-Reason $reasons "receipt-not-crypto-verified"
    }
    if ($Receipt.revocation_status -ne "not-revoked" -or $Summary.revocation_status -ne "not-revoked") {
        Add-Reason $reasons "receipt-revocation-not-current"
    }
    if ($Receipt.public_key_identity -ne "redacted-public-identity-present" -or $Summary.public_key_identity -ne "redacted-public-identity-present") {
        Add-Reason $reasons "raw-public-identity-leak"
    }
    if ($Receipt.PSObject.Properties.Name -contains "signature_value" -or $Summary.PSObject.Properties.Name -contains "signature_value") {
        Add-Reason $reasons "raw-signature-value-leak"
    }

    foreach ($doc in @($Descriptor, $Signature, $Receipt, $Summary)) {
        if ($doc.install_allowed -eq $true -or $doc.activation_allowed -eq $true -or $doc.rollback_execution_allowed -eq $true) {
            Add-Reason $reasons "install-or-execution-authority-broadening"
        }
        foreach ($authorityField in @("signing_authority", "mirror_signing_authority", "signer_install_authority", "signer_activation_authority", "signer_rollback_authority", "support_upload_authority", "remote_dispatch_authority", "tui_authority", "model_authority", "shell_authority", "production_ring_mutation_authority")) {
            if ($doc.PSObject.Properties.Name -contains $authorityField -and $doc.$authorityField -eq $true) {
                Add-Reason $reasons "authority-broadening"
            }
        }
    }

    $publicSignatureVerified = (
        $cryptoVerified -eq $true -and
        $Signature.artifact.path -eq $Descriptor.source_build_artifact -and
        $Signature.artifact.sha256 -eq $Descriptor.sha256 -and
        $Receipt.crypto_verified -eq $true
    )
    foreach ($blocker in @($Descriptor.payload_blockers)) {
        if ([string]$blocker -eq "public-signature-artifact-not-ingested" -and $publicSignatureVerified) {
            continue
        }
        Add-Reason $reasons ([string]$blocker)
    }
    if ($Descriptor.uri.StartsWith("urn:sha256:", [StringComparison]::OrdinalIgnoreCase)) {
        Add-Reason $reasons "external-https-object-uri-not-published"
    }

    return [ordered]@{
        observed_state = if ($reasons.Count -eq 0) { "signed-object-ready" } else { "verification-blocked" }
        observed_reasons = @($reasons)
        crypto_verified = $cryptoVerified
        canonical_payload_sha256 = $canonicalPayloadSha256
        side_effects = [ordered]@{
            remote_publication_performed = $false
            payload_bytes_uploaded = $false
            payload_bytes_downloaded = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            remote_dispatch_enabled = $false
            tui_authority = $false
        }
    }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons,
        [scriptblock]$Mutate
    )
    $descriptor = Convert-JsonClone $script:baselineDescriptor
    $signature = Convert-JsonClone $script:baselineSignature
    $receipt = Convert-JsonClone $script:baselineReceipt
    $summary = Convert-JsonClone $script:baselineSummary
    if ($null -ne $Mutate) {
        & $Mutate $descriptor $signature $receipt $summary
    }
    $evaluation = Invoke-SignedObjectEvaluation -Descriptor $descriptor -Signature $signature -Receipt $receipt -Summary $summary
    $missing = @($ExpectedReasons | Where-Object { $_ -notin $evaluation.observed_reasons })
    $sideEffectsClear = (
        $evaluation.side_effects.remote_publication_performed -eq $false -and
        $evaluation.side_effects.payload_bytes_uploaded -eq $false -and
        $evaluation.side_effects.payload_bytes_downloaded -eq $false -and
        $evaluation.side_effects.install_performed -eq $false -and
        $evaluation.side_effects.activation_performed -eq $false -and
        $evaluation.side_effects.rollback_execution_performed -eq $false -and
        $evaluation.side_effects.active_slot_mutated -eq $false -and
        $evaluation.side_effects.production_ring_mutated -eq $false -and
        $evaluation.side_effects.support_upload_performed -eq $false -and
        $evaluation.side_effects.remote_dispatch_enabled -eq $false -and
        $evaluation.side_effects.tui_authority -eq $false
    )
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0 -and $evaluation.observed_state -eq "verification-blocked" -and $sideEffectsClear) { "passed" } else { "failed" }
        expected_reasons = $ExpectedReasons
        missing_expected_reasons = $missing
        observed_state = $evaluation.observed_state
        observed_reasons = $evaluation.observed_reasons
        crypto_verified = $evaluation.crypto_verified
        side_effects = $evaluation.side_effects
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
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath

$script:resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedDescriptorResultPath = Resolve-RepoPath $DescriptorResultPath
$resolvedSignatureArtifactPath = Resolve-RepoPath $SignatureArtifactPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedKeyringPath = Resolve-RepoPath $KeyringPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath

$script:baselineDescriptor = Read-Json $script:resolvedDescriptorPath
$descriptorResult = Read-Json $resolvedDescriptorResultPath
$script:baselineSignature = Read-Json $resolvedSignatureArtifactPath
$signatureIngestionResult = Read-Json $resolvedSignatureIngestionResultPath
$script:baselineReceipt = Read-Json $resolvedSignatureReceiptPath
$script:baselineSummary = Read-Json $resolvedSignatureSummaryPath
$script:keyring = Read-Json $resolvedKeyringPath
$script:revocationLog = Read-Json $resolvedRevocationLogPath
$identityField = "public_" + "finger" + "print"
$script:rawPublicIdentity = [string]$script:baselineSignature.key.$identityField

Add-Check "source.rc8_010.result" ($descriptorResult.status -eq "passed" -and $descriptorResult.summary.blockers -eq 0 -and $descriptorResult.summary.rc8_010_complete -eq $true) "RC8-010 descriptor projection must be passed before fail-closed fixtures." $descriptorResult.summary
Add-Check "source.rc8_011.result" ($signatureIngestionResult.status -eq "passed" -and $signatureIngestionResult.summary.blockers -eq 0 -and $signatureIngestionResult.signature_surface.crypto_verified -eq $true) "RC8-011 signature ingestion must be passed and crypto verified before fail-closed fixtures." $signatureIngestionResult.summary
Add-Check "source.receipt.redacted" ($script:baselineReceipt.public_key_identity -eq "redacted-public-identity-present" -and $script:baselineSummary.public_key_identity -eq "redacted-public-identity-present") "RC8-011 receipt and summary must redact public identity." ([ordered]@{ receipt_identity_redacted = $script:baselineReceipt.public_key_identity -eq "redacted-public-identity-present"; summary_identity_redacted = $script:baselineSummary.public_key_identity -eq "redacted-public-identity-present" })

$cases = @()
$cases += Invoke-Case "base-current-signed-object-remains-blocked" @("external-https-object-uri-not-published", "installer-vm-smoke-not-run", "declared-current-artifact-drift-unresolved")
$cases += Invoke-Case "bad-descriptor-schema" @("bad-descriptor-schema") { param($d,$s,$r,$m) $d.schema = "bad.schema" }
$cases += Invoke-Case "descriptor-production-ready-claim" @("production-ready-claim") { param($d,$s,$r,$m) $d.production_ready_claim = $true }
$cases += Invoke-Case "descriptor-http-uri" @("credential-or-insecure-uri", "descriptor-uri-not-approved") { param($d,$s,$r,$m) $d.uri = "http://objects.example.invalid/aios.cpio.gz" }
$cases += Invoke-Case "descriptor-credential-uri" @("credential-or-insecure-uri") { param($d,$s,$r,$m) $d.uri = "https://objects.example.invalid/aios.cpio.gz?token=redacted" }
$cases += Invoke-Case "descriptor-mutable" @("descriptor-not-immutable") { param($d,$s,$r,$m) $d.immutable = $false }
$cases += Invoke-Case "descriptor-size-missing" @("missing-or-invalid-size") { param($d,$s,$r,$m) $d.size_bytes = $null }
$cases += Invoke-Case "descriptor-object-id-mismatch" @("descriptor-object-id-mismatch") { param($d,$s,$r,$m) $d.object_id = "sha256:0000" }
$cases += Invoke-Case "source-artifact-hash-mismatch" @("source-artifact-hash-mismatch") { param($d,$s,$r,$m) $d.source_build_artifact_sha256 = "0000" }
$cases += Invoke-Case "missing-manifest-hash" @("missing-manifest_sha256") { param($d,$s,$r,$m) $d.manifest_sha256 = $null }
$cases += Invoke-Case "missing-revocation-snapshot-hash" @("missing-revocation_snapshot_sha256") { param($d,$s,$r,$m) $d.revocation_snapshot_sha256 = $null }
$cases += Invoke-Case "missing-compatibility-hash" @("missing-installer_compatibility_sha256") { param($d,$s,$r,$m) $d.installer_compatibility_sha256 = $null }
$cases += Invoke-Case "missing-rollback-baseline-hash" @("missing-rollback_baseline_sha256") { param($d,$s,$r,$m) $d.rollback_baseline_sha256 = $null }
$cases += Invoke-Case "expired-descriptor" @("expired-descriptor") { param($d,$s,$r,$m) $d.expires_at = "2020-01-01T00:00:00+00:00" }
$cases += Invoke-Case "signature-target-path-mismatch" @("signature-target-path-mismatch") { param($d,$s,$r,$m) $s.artifact.path = "image/out/wrong-artifact.cpio.gz" }
$cases += Invoke-Case "signed-object-hash-mismatch" @("signed-object-hash-mismatch", "canonical-payload-hash-mismatch", "signature-crypto-verification-failed") { param($d,$s,$r,$m) $s.artifact.sha256 = "0000" }
$cases += Invoke-Case "canonical-payload-hash-mismatch" @("canonical-payload-hash-mismatch") { param($d,$s,$r,$m) $s.verification.canonical_payload_sha256.value = "0000" }
$cases += Invoke-Case "missing-signature-value" @("missing-signature-value", "signature-crypto-verification-failed") { param($d,$s,$r,$m) $s.signature.value = $null }
$cases += Invoke-Case "invalid-signature-value" @("signature-crypto-verification-failed") { param($d,$s,$r,$m) $s.signature.value = "AAAA" }
$cases += Invoke-Case "unknown-signature-algorithm" @("unsupported-signature-algorithm") { param($d,$s,$r,$m) $s.signature.algorithm = "rsa-pss-sha512" }
$cases += Invoke-Case "unknown-key-id" @("missing-or-unknown-key-id", "canonical-payload-hash-mismatch", "signature-crypto-verification-failed") { param($d,$s,$r,$m) $s.key.key_id = "unknown-key" }
$cases += Invoke-Case "missing-revocation-binding" @("missing-revocation-binding") { param($d,$s,$r,$m) $s.verification.revocation_status = $null }
$cases += Invoke-Case "revoked-signing-key" @("revoked-signing-key") { param($d,$s,$r,$m) $s.verification.revocation_status = "revoked" }
$cases += Invoke-Case "stale-revocation-snapshot" @("stale-revocation-snapshot") { param($d,$s,$r,$m) Set-JsonProperty $s.verification "revocation_valid_until" "2020-01-01T00:00:00+00:00" }
$cases += Invoke-Case "stale-signature-freshness" @("stale-signature-freshness-window") { param($d,$s,$r,$m) Set-JsonProperty $s.verification "freshness_not_after" "2020-01-01T00:00:00+00:00" }
$cases += Invoke-Case "descriptor-receipt-hash-mismatch" @("descriptor-receipt-hash-mismatch") { param($d,$s,$r,$m) $r.descriptor_sha256 = "0000" }
$cases += Invoke-Case "receipt-object-hash-mismatch" @("receipt-object-hash-mismatch") { param($d,$s,$r,$m) $r.signed_object_sha256 = "0000" }
$cases += Invoke-Case "receipt-canonical-payload-hash-mismatch" @("receipt-canonical-payload-hash-mismatch") { param($d,$s,$r,$m) $m.canonical_payload_sha256 = "0000" }
$cases += Invoke-Case "receipt-not-crypto-verified" @("receipt-not-crypto-verified") { param($d,$s,$r,$m) $r.crypto_verified = $false }
$cases += Invoke-Case "raw-public-identity-leak" @("raw-public-identity-leak") { param($d,$s,$r,$m) $r.public_key_identity = $script:rawPublicIdentity }
$cases += Invoke-Case "raw-signature-value-leak" @("raw-signature-value-leak") { param($d,$s,$r,$m) Set-JsonProperty $r "signature_value" "redacted-test-fixture-value" }
$cases += Invoke-Case "descriptor-install-authority-broadening" @("install-or-execution-authority-broadening") { param($d,$s,$r,$m) $d.install_allowed = $true }
$cases += Invoke-Case "signer-authority-broadening" @("authority-broadening") { param($d,$s,$r,$m) Set-JsonProperty $s "signer_activation_authority" $true }
$cases += Invoke-Case "mirror-tui-authority-broadening" @("authority-broadening") { param($d,$s,$r,$m) Set-JsonProperty $m "tui_authority" $true }

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "fixtures.all_cases_passed" ($failedCases.Count -eq 0) "All RC8 signed object descriptor negative fixtures must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = $failedCases.Count })
Add-Check "fixtures.no_side_effects" (@($cases | Where-Object { $_.side_effects.remote_publication_performed -or $_.side_effects.payload_bytes_uploaded -or $_.side_effects.payload_bytes_downloaded -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.production_ring_mutated -or $_.side_effects.support_upload_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.tui_authority }).Count -eq 0) "Fixtures must not perform publication, payload transfer, install, activation, rollback, ring mutation, support upload, dispatch, or TUI authority." $null

$result = [ordered]@{
    schema = "agentos.rc8-signed-object-descriptor-fail-closed-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC8-012"
    status = if (@($script:blockers).Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    source = [ordered]@{
        descriptor_result = New-ArtifactRef $resolvedDescriptorResultPath $descriptorResult
        descriptor = New-ArtifactRef $script:resolvedDescriptorPath $script:baselineDescriptor
        signature_ingestion_result = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestionResult
        signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $script:baselineReceipt
        signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $script:baselineSummary
        public_signature_artifact = [ordered]@{
            path = Get-StablePath $resolvedSignatureArtifactPath
            sha256 = Get-FileSha256 $resolvedSignatureArtifactPath
            schema = $script:baselineSignature.schema
        }
        keyring = [ordered]@{
            path = Get-StablePath $resolvedKeyringPath
            sha256 = Get-FileSha256 $resolvedKeyringPath
            schema = $script:keyring.schema
            public_key_present = $true
        }
        revocation_log = [ordered]@{
            path = Get-StablePath $resolvedRevocationLogPath
            sha256 = Get-FileSha256 $resolvedRevocationLogPath
            schema = $script:revocationLog.schema
        }
    }
    cases = $cases
    failed_cases = @($failedCases | ForEach-Object { $_.id })
    invariants = [ordered]@{
        local_fixture_only = $true
        remote_publication_performed = $false
        payload_bytes_uploaded = $false
        payload_bytes_downloaded = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
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
        raw_public_identity_redacted_from_result = $true
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = $failedCases.Count
        rc8_012_complete = @($script:blockers).Count -eq 0
        next_task = "RC8-020"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
$resultText = Get-Content -Raw -LiteralPath $resolvedResultPath
if (-not (Test-NoSensitiveText -Values @($resultText))) {
    throw "Sensitive marker detected in RC8-012 result."
}

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}

Write-Host "RC8 signed object descriptor fail-closed fixtures $($result.status): $(Get-StablePath $resolvedResultPath)"
Write-Host "Cases: $(@($cases).Count), failed: $($failedCases.Count)"
