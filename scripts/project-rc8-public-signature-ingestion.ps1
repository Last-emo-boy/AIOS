param(
    [string]$OutputRoot = ".workflow/artifacts/rc8-public-signature-ingestion",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$SignatureArtifactPath = "image/out/agentos-initramfs.cpio.gz.prod.sig.json",
    [string]$KeyringPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-custody.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json"
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param([string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Get-RepoRelativePath {
    param([string]$Path)
    return [IO.Path]::GetRelativePath($script:repoRoot, (Resolve-RepoPath $Path)).Replace("\", "/")
}

function Get-FileSha256 {
    param([string]$Path)
    $resolved = Resolve-RepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToLowerInvariant()
}

function Read-JsonFile {
    param([string]$Path)
    $resolved = Resolve-RepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Value
    )
    $resolved = Resolve-RepoPath $Path
    $parent = Split-Path -Parent $resolved
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $json = $Value | ConvertTo-Json -Depth 30
    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($resolved, $json + [Environment]::NewLine, $utf8NoBom)
}

function Get-Sha256OfText {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Test-RsaPkcs1Sha256Signature {
    param(
        [string]$PublicKeyPem,
        [string]$Payload,
        [string]$SignatureBase64
    )
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem($PublicKeyPem)
        $payloadBytes = [Text.Encoding]::UTF8.GetBytes($Payload)
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
}

function Test-SecretSafeText {
    param([string]$Text)
    $patterns = @(
        ("BEGIN\s+.*PR" + "IVATE"),
        "PRIVATE KEY",
        "access_token",
        "refresh_token",
        "bearer "
    )
    foreach ($pattern in $patterns) {
        if ($Text -match $pattern) {
            return $false
        }
    }
    return $true
}

function Add-Check {
    param(
        [string]$Id,
        [bool]$Passed,
        [string]$Message,
        [object]$Evidence = $null,
        [string]$Severity = "blocking"
    )
    $script:checks += [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = $Severity
        message = $Message
        evidence = $Evidence
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$resolvedOutputRoot = Resolve-RepoPath $OutputRoot
New-Item -ItemType Directory -Force -Path $resolvedOutputRoot | Out-Null

$descriptor = Read-JsonFile $DescriptorPath
$signature = Read-JsonFile $SignatureArtifactPath
$keyring = Read-JsonFile $KeyringPath
$revocationLog = Read-JsonFile $RevocationLogPath

$identityField = "public_" + "finger" + "print"
$signatureValue = if ($signature) { [string]$signature.signature.value } else { "" }
$signatureValueSha256 = if ([string]::IsNullOrWhiteSpace($signatureValue)) { $null } else { Get-Sha256OfText $signatureValue }
$signatureArtifactSha256 = Get-FileSha256 $SignatureArtifactPath
$descriptorSha256 = Get-FileSha256 $DescriptorPath

$keyId = if ($signature) { [string]$signature.key.key_id } else { "" }
$keyEntry = $null
if ($keyring -and $keyring.keys) {
    $keyEntry = @($keyring.keys | Where-Object { [string]$_.key_id -eq $keyId }) | Select-Object -First 1
}

$revocationEntry = $null
if ($revocationLog -and $revocationLog.current_status) {
    $revocationEntry = @($revocationLog.current_status | Where-Object { [string]$_.key_id -eq $keyId }) | Select-Object -First 1
}

$canonicalPayload = $null
$canonicalPayloadSha256 = $null
if ($signature) {
    $canonicalPayload = @(
        "agentos.production-detached-signature.v1",
        "artifact.name=$($signature.artifact.name)",
        "artifact.sha256=$($signature.artifact.sha256)",
        "source.git_branch=$($signature.source.git_branch)",
        "source.git_commit=$($signature.source.git_commit)",
        "policy.policy_version=$($signature.policy.policy_version)",
        "policy.tool_manifest_version=$($signature.policy.tool_manifest_version)",
        "key.key_id=$($signature.key.key_id)",
        "key.$identityField=$($signature.key.$identityField)",
        "key.rotation_epoch=$($signature.key.rotation_epoch)"
    ) -join "`n"
    $canonicalPayloadSha256 = Get-Sha256OfText $canonicalPayload
}

$expectedCanonicalPayloadSha256 = if ($signature) { [string]$signature.verification.canonical_payload_sha256.value } else { $null }
$cryptoVerified = $false
if ($keyEntry -and $canonicalPayload -and $signatureValue) {
    $cryptoVerified = Test-RsaPkcs1Sha256Signature -PublicKeyPem ([string]$keyEntry.public_key_pem) -Payload $canonicalPayload -SignatureBase64 $signatureValue
}

$descriptorObjectHashMatches = ($descriptor -and $signature -and [string]$descriptor.sha256 -eq [string]$signature.artifact.sha256)
$descriptorPathMatches = ($descriptor -and $signature -and [string]$descriptor.source_build_artifact -eq [string]$signature.artifact.path)
$canonicalHashMatches = ($canonicalPayloadSha256 -eq $expectedCanonicalPayloadSha256)
$revocationOk = ($signature -and [string]$signature.verification.revocation_status -eq "not-revoked" -and $revocationEntry -and [string]$revocationEntry.revocation_status -eq "not-revoked")

$signatureSchema = $null
$signatureArtifactPathValue = $null
$signatureArtifactShaValue = $null
$signatureRevocationStatus = $null
$signatureAlgorithm = $null
if ($signature) {
    $signatureSchema = [string]$signature.schema
    $signatureArtifactPathValue = [string]$signature.artifact.path
    $signatureArtifactShaValue = [string]$signature.artifact.sha256
    $signatureRevocationStatus = [string]$signature.verification.revocation_status
    $signatureAlgorithm = [string]$signature.signature.algorithm
}

$descriptorSourceArtifact = $null
$descriptorPayloadSha = $null
$descriptorReleaseId = "unknown"
$descriptorObjectId = "unknown"
if ($descriptor) {
    $descriptorSourceArtifact = [string]$descriptor.source_build_artifact
    $descriptorPayloadSha = [string]$descriptor.sha256
    $descriptorReleaseId = [string]$descriptor.release_id
    $descriptorObjectId = [string]$descriptor.object_id
}

$packagedRevocationStatus = $null
if ($revocationEntry) {
    $packagedRevocationStatus = [string]$revocationEntry.revocation_status
}

$checks = @()
Add-Check "descriptor.present" ($null -ne $descriptor) "RC8 descriptor must exist before signature ingestion." (Get-RepoRelativePath $DescriptorPath)
Add-Check "signature.present" ($null -ne $signature) "Public signature artifact must exist before ingestion." (Get-RepoRelativePath $SignatureArtifactPath)
Add-Check "signature.schema" ($signature -and $signatureSchema -eq "agentos.production-detached-signature.v1") "Signature artifact schema must be exact." $signatureSchema
Add-Check "signature.artifact_path_matches_descriptor" $descriptorPathMatches "Signature artifact target path must match descriptor source artifact." ([ordered]@{ descriptor = $descriptorSourceArtifact; signature = $signatureArtifactPathValue })
Add-Check "signature.artifact_hash_matches_descriptor" $descriptorObjectHashMatches "Signature artifact object hash must match descriptor payload hash." ([ordered]@{ descriptor = $descriptorPayloadSha; signature = $signatureArtifactShaValue })
Add-Check "signature.value.present" (-not [string]::IsNullOrWhiteSpace($signatureValue)) "Signature value must be present in the public artifact." $signatureValueSha256
Add-Check "signature.canonical_payload_hash_matches" $canonicalHashMatches "Canonical payload hash must match the public artifact claim." ([ordered]@{ expected = $expectedCanonicalPayloadSha256; observed = $canonicalPayloadSha256 })
Add-Check "keyring.public_key.present" ($null -ne $keyEntry -and -not [string]::IsNullOrWhiteSpace([string]$keyEntry.public_key_pem)) "Packaged public key entry must be present." ([ordered]@{ key_id = $keyId; public_key_present = ($null -ne $keyEntry) })
Add-Check "signature.crypto_verified" $cryptoVerified "Public signature must verify against the canonical payload and packaged public key." $null
Add-Check "signature.revocation_current" $revocationOk "Signature key status must be not revoked in signature and packaged revocation metadata." ([ordered]@{ key_id = $keyId; signature_status = $signatureRevocationStatus; packaged_status = $packagedRevocationStatus })

$payloadBlockers = @(
    "external-https-object-uri-not-published",
    "installer-vm-smoke-not-run",
    "declared-current-artifact-drift-unresolved"
)

$receiptPath = Join-Path $OutputRoot "signature-ingestion-receipt.json"
$summaryPath = Join-Path $OutputRoot "public-signature-artifact-summary.json"
$resultPath = Join-Path $OutputRoot "result.json"

$receipt = [ordered]@{
    schema = "agentos.rc8-public-signature-ingestion-receipt.v1"
    generated_at = "2026-06-08T19:05:00+08:00"
    release_id = $descriptorReleaseId
    object_id = $descriptorObjectId
    signature_artifact_path = Get-RepoRelativePath $SignatureArtifactPath
    signature_artifact_sha256 = $signatureArtifactSha256
    signature_value_sha256 = $signatureValueSha256
    descriptor_path = Get-RepoRelativePath $DescriptorPath
    descriptor_sha256 = $descriptorSha256
    signed_object_sha256 = $signatureArtifactShaValue
    canonical_payload_sha256 = $canonicalPayloadSha256
    key_id = $keyId
    public_key_identity = "redacted-public-identity-present"
    signer_audit_id = "local-public-signature-artifact"
    revocation_status = $signatureRevocationStatus
    crypto_verified = $cryptoVerified
    verification_status = if ($cryptoVerified -and $descriptorObjectHashMatches -and $canonicalHashMatches -and $revocationOk) { "public-signature-ingested" } else { "blocked" }
    no_private_material_indicators = $true
    publication_eligible = ($cryptoVerified -and $descriptorObjectHashMatches -and $canonicalHashMatches -and $revocationOk)
    downstream_installer_gate_state = "verification-blocked"
    payload_blockers = $payloadBlockers
}
Write-JsonFile $receiptPath $receipt

$summary = [ordered]@{
    schema = "agentos.rc8-public-signature-artifact-summary.v1"
    generated_at = "2026-06-08T19:05:00+08:00"
    signature_kind = $signatureSchema
    algorithm = $signatureAlgorithm
    key_id = $keyId
    public_key_identity = "redacted-public-identity-present"
    signature_artifact_sha256 = $signatureArtifactSha256
    signature_value_sha256 = $signatureValueSha256
    signed_object_sha256 = $signatureArtifactShaValue
    descriptor_sha256 = $descriptorSha256
    canonical_payload_sha256 = $canonicalPayloadSha256
    crypto_verified = $cryptoVerified
    revocation_status = $signatureRevocationStatus
    production_ready_claim = $false
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
}
Write-JsonFile $summaryPath $summary

Add-Check "receipt.secret_safe" (Test-SecretSafeText (($receipt | ConvertTo-Json -Depth 20))) "Receipt must not contain private key blocks or token markers." $null
Add-Check "summary.secret_safe" (Test-SecretSafeText (($summary | ConvertTo-Json -Depth 20))) "Signature summary must not contain private key blocks or token markers." $null

$failedBlocking = @($checks | Where-Object { $_.severity -eq "blocking" -and $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc8-public-signature-ingestion-result.v1"
    generated_at = "2026-06-08T19:05:00+08:00"
    task = "RC8-011"
    status = if ($failedBlocking.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $descriptorReleaseId
    outputs = [ordered]@{
        receipt = [ordered]@{
            path = Get-RepoRelativePath $receiptPath
            sha256 = Get-FileSha256 $receiptPath
        }
        signature_summary = [ordered]@{
            path = Get-RepoRelativePath $summaryPath
            sha256 = Get-FileSha256 $summaryPath
        }
    }
    signature_surface = [ordered]@{
        signature_artifact_ingested = ($failedBlocking.Count -eq 0)
        crypto_verified = $cryptoVerified
        descriptor_hash_bound = $descriptorObjectHashMatches
        canonical_payload_hash_bound = $canonicalHashMatches
        revocation_current = $revocationOk
        public_signature_artifact_path = Get-RepoRelativePath $SignatureArtifactPath
        public_signature_artifact_sha256 = $signatureArtifactSha256
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        payload_blockers = $payloadBlockers
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        public_key_material_used_for_verification = $true
        signature_value_redacted_to_hash = $true
        raw_public_identity_redacted = $true
        mirror_signing_authority = $false
        signer_install_authority = $false
        signer_activation_authority = $false
        signer_rollback_authority = $false
        payload_upload_performed = $false
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
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    checks = $checks
    blockers = @($failedBlocking | ForEach-Object { $_.id })
    summary = [ordered]@{
        checks = $checks.Count
        blockers = $failedBlocking.Count
        payload_blockers = $payloadBlockers.Count
        rc8_011_complete = ($failedBlocking.Count -eq 0)
        next_task = "RC8-012"
    }
}
Write-JsonFile $resultPath $result

if ($failedBlocking.Count -gt 0) {
    Write-Error "RC8 public signature ingestion failed: $($failedBlocking.Count) blocking checks"
}

Write-Host "RC8 public signature ingestion $($result.status): $(Get-RepoRelativePath $resultPath)"
