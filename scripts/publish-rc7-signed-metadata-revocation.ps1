param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$SignerDomain = "sign.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-signed-metadata-revocation",
    [string]$ResultPath = "",
    [string]$Rc7ContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/signed-payload-consumption-controlled-execution-contract.md",
    [string]$Rc6FinalAuditPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/evidence/FINAL-AUDIT-20260608-production-distro-rc6.json",
    [string]$HostedPayloadResultPath = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json",
    [string]$HostedPayloadIndexPath = ".workflow/artifacts/rc6-hosted-payload-metadata/hosted-payload-index.json",
    [string]$HostedInstallBootstrapPath = ".workflow/artifacts/rc6-hosted-payload-metadata/install-bootstrap.json",
    [string]$HostedChannelIndexPath = ".workflow/artifacts/rc6-hosted-payload-metadata/hosted-channel-index-after-payload-metadata.json",
    [string]$PayloadManifestPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-manifest.json",
    [string]$PayloadChecksumsPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-checksums.json",
    [string]$PayloadSignaturesPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-signatures.json",
    [string]$KeyCustodyPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-custody.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
    [int]$SshConnectTimeoutSeconds = 10,
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

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

function ConvertFrom-JsonTextSafe {
    param([Parameter(Mandatory = $true)][string]$Text)
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
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

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        $Command
    )
    $output = & ssh @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "Remote command failed ($exitCode): $text"
    }
    return $text
}

function Set-RemoteTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Mode = "0644"
    )
    $encoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($Text))
    $parent = [IO.Path]::GetDirectoryName($Path) -replace "\\", "/"
    $command = "set -eu; install -d -m 0755 '$parent'; printf '%s' '$encoded' | base64 -d > '$Path'; chmod '$Mode' '$Path'"
    Invoke-Remote $command | Out-Null
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$HostDomain = $Domain,
        [string]$Method = "GET"
    )
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$HostDomain`:80`:$RemoteHost",
        "-sS",
        "-X", $Method,
        "-w", "`n%{http_code}",
        $Url
    )
    $output = & curl.exe @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).TrimEnd()
    $parts = [regex]::Split($text, "\r?\n")
    $statusText = $parts[-1]
    $body = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join "`n") } else { "" }
    $statusCode = 0
    [void][int]::TryParse($statusText, [ref]$statusCode)
    return [ordered]@{
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        url = $Url
        method = $Method
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
        ("PRIVATE KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        "access_token",
        "refresh_token",
        ".local-release-authority",
        ("signing" + "-key.pem")
    )
    if (Has-Value $script:publicFingerprint) {
        $markers += $script:publicFingerprint
    }
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.Contains($marker, [StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }
    return $true
}

function Get-SanitizedRevocationStatus {
    param($RevocationLog)
    return @($RevocationLog.current_status | ForEach-Object {
        [ordered]@{
            key_id = $_.key_id
            revocation_status = $_.revocation_status
            checked_at = $_.checked_at
        }
    })
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$script:publicFingerprint = $null

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath

$resolvedRc7ContractPath = Resolve-RepoPath $Rc7ContractPath
$resolvedRc6FinalAuditPath = Resolve-RepoPath $Rc6FinalAuditPath
$resolvedHostedPayloadResultPath = Resolve-RepoPath $HostedPayloadResultPath
$resolvedHostedPayloadIndexPath = Resolve-RepoPath $HostedPayloadIndexPath
$resolvedHostedInstallBootstrapPath = Resolve-RepoPath $HostedInstallBootstrapPath
$resolvedHostedChannelIndexPath = Resolve-RepoPath $HostedChannelIndexPath
$resolvedPayloadManifestPath = Resolve-RepoPath $PayloadManifestPath
$resolvedPayloadChecksumsPath = Resolve-RepoPath $PayloadChecksumsPath
$resolvedPayloadSignaturesPath = Resolve-RepoPath $PayloadSignaturesPath
$resolvedKeyCustodyPath = Resolve-RepoPath $KeyCustodyPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath

$generatedAt = (Get-Date).ToString("o")
$validUntil = (Get-Date).AddDays(7).ToString("o")

$rc6FinalAudit = Read-Json $resolvedRc6FinalAuditPath
$hostedResult = Read-Json $resolvedHostedPayloadResultPath
$hostedPayloadIndex = Read-Json $resolvedHostedPayloadIndexPath
$hostedInstall = Read-Json $resolvedHostedInstallBootstrapPath
$hostedChannel = Read-Json $resolvedHostedChannelIndexPath
$payloadManifest = Read-Json $resolvedPayloadManifestPath
$payloadChecksums = Read-Json $resolvedPayloadChecksumsPath
$payloadSignatures = Read-Json $resolvedPayloadSignaturesPath
$keyCustody = Read-Json $resolvedKeyCustodyPath
$revocationLog = Read-Json $resolvedRevocationLogPath
$rc7ContractText = Get-Content -Raw -LiteralPath $resolvedRc7ContractPath

$releaseId = $hostedResult.payload_surface.release_id
$payloadBasePath = $hostedResult.payload_surface.base_path
$productionKey = @($keyCustody.keys | Where-Object { $_.key_id -eq "agentos-production-root-v1" } | Select-Object -First 1)[0]
$revocationStatus = @($revocationLog.current_status | Where-Object { $_.key_id -eq "agentos-production-root-v1" } | Select-Object -First 1)[0]
if ($null -ne $productionKey) {
    $script:publicFingerprint = [string]$productionKey.public_fingerprint
}

$rc6FinalAuditHash = Get-FileSha256 $resolvedRc6FinalAuditPath
$hostedPayloadResultHash = Get-FileSha256 $resolvedHostedPayloadResultPath
$hostedPayloadIndexHash = Get-FileSha256 $resolvedHostedPayloadIndexPath
$hostedInstallHash = Get-FileSha256 $resolvedHostedInstallBootstrapPath
$payloadManifestFileHash = Get-FileSha256 $resolvedPayloadManifestPath
$payloadChecksumsFileHash = Get-FileSha256 $resolvedPayloadChecksumsPath
$payloadSignaturesFileHash = Get-FileSha256 $resolvedPayloadSignaturesPath
$keyCustodyHash = Get-FileSha256 $resolvedKeyCustodyPath
$revocationLogHash = Get-FileSha256 $resolvedRevocationLogPath
$rc7ContractHash = Get-FileSha256 $resolvedRc7ContractPath

Add-Check "source.rc6_final_audit.pass" ($rc6FinalAudit.verdict -eq "PASS" -and $rc6FinalAudit.production_ready_claim -eq $false) "RC6 final audit must pass while remaining non-GA." ([ordered]@{ verdict = $rc6FinalAudit.verdict; production_ready_claim = $rc6FinalAudit.production_ready_claim })
Add-Check "source.hosted_payload.ready" ($hostedResult.status -eq "passed" -and $hostedResult.summary.blockers -eq 0) "RC6 hosted payload metadata must be passed before RC7 signed metadata projection." $hostedResult.summary
Add-Check "source.payload.blocked" ($hostedResult.payload_surface.status -eq "verification-blocked" -and $hostedResult.payload_surface.install_allowed -eq $false) "Payload candidate must still be verification-blocked before RC7 projection." $hostedResult.payload_surface
Add-Check "source.rc7_contract.present" ((Has-Value $rc7ContractHash) -and $rc7ContractText.Contains("Signed Payload Consumption", [StringComparison]::OrdinalIgnoreCase)) "RC7 signed payload consumption contract must exist." (Get-StablePath $resolvedRc7ContractPath)
Add-Check "source.key_custody.public_only" ($keyCustody.schema -eq "agentos.production-key-custody.v1" -and $null -ne $productionKey -and $productionKey.status -eq "active" -and $productionKey.revocation_status -eq "not-revoked") "Public key custody must expose an active non-revoked production key." ([ordered]@{ key_id = if ($null -ne $productionKey) { $productionKey.key_id } else { $null }; status = if ($null -ne $productionKey) { $productionKey.status } else { $null }; revocation_status = if ($null -ne $productionKey) { $productionKey.revocation_status } else { $null } })
Add-Check "source.revocation_log.current" ($revocationLog.schema -eq "agentos.production-key-revocation-log.v1" -and $null -ne $revocationStatus -and $revocationStatus.revocation_status -eq "not-revoked") "Public revocation log must mark the production key not revoked." ([ordered]@{ key_id = if ($null -ne $revocationStatus) { $revocationStatus.key_id } else { $null }; revocation_status = if ($null -ne $revocationStatus) { $revocationStatus.revocation_status } else { $null } })

$revocationSnapshot = [ordered]@{
    schema = "agentos.rc7-revocation-snapshot.v1"
    generated_at = $generatedAt
    valid_until = $validUntil
    release_id = $releaseId
    status = "revocation-current-projected"
    production_ready_claim = $false
    key_id = if ($null -ne $productionKey) { $productionKey.key_id } else { "agentos-production-root-v1" }
    key_status = if ($null -ne $productionKey) { $productionKey.status } else { $null }
    revocation_status = if ($null -ne $revocationStatus) { $revocationStatus.revocation_status } else { $null }
    public_fingerprint_present = Has-Value $script:publicFingerprint
    public_fingerprint_sha256 = if (Has-Value $script:publicFingerprint) { Get-StringSha256 $script:publicFingerprint } else { $null }
    source_bindings = [ordered]@{
        key_custody = [ordered]@{ path = Get-StablePath $resolvedKeyCustodyPath; sha256 = $keyCustodyHash; schema = $keyCustody.schema }
        revocation_log = [ordered]@{ path = Get-StablePath $resolvedRevocationLogPath; sha256 = $revocationLogHash; schema = $revocationLog.schema }
    }
    current_status = Get-SanitizedRevocationStatus $revocationLog
    events_count = @($revocationLog.events).Count
    mirror_is_root_of_trust = $false
    signing_authority_on_mirror = $false
    install_allowed = $false
    activation_allowed = $false
}
$revocationSnapshotText = Get-JsonText $revocationSnapshot
$revocationSnapshotContentHash = Get-StringSha256 $revocationSnapshotText

$signatureClaims = [ordered]@{
    schema = "agentos.rc7-signature-claims.v1"
    release_id = $releaseId
    rc6_final_audit_sha256 = $rc6FinalAuditHash
    hosted_payload_result_sha256 = $hostedPayloadResultHash
    payload_manifest_content_sha256 = $hostedResult.output_hashes.payload_manifest_content_sha256
    payload_checksums_content_sha256 = $hostedResult.output_hashes.payload_checksums_content_sha256
    previous_payload_signatures_content_sha256 = $hostedResult.output_hashes.payload_signatures_content_sha256
    revocation_snapshot_sha256 = $revocationSnapshotContentHash
    signer_key_id = if ($null -ne $productionKey) { $productionKey.key_id } else { "agentos-production-root-v1" }
    policy_version = "production-distro-rc7-signed-consumption-v1"
    expires_at = $validUntil
}
$signatureClaimsText = Get-JsonText $signatureClaims
$signatureClaimsHash = Get-StringSha256 $signatureClaimsText

$signedMetadata = [ordered]@{
    schema = "agentos.rc7-signed-metadata-projection.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    status = "signed-metadata-projected-verification-blocked"
    production_ready_claim = $false
    signer_endpoint_domain = $SignerDomain
    signer_boundary = "external-public-artifact-only"
    signer_key_id = if ($null -ne $productionKey) { $productionKey.key_id } else { "agentos-production-root-v1" }
    public_fingerprint_present = Has-Value $script:publicFingerprint
    public_fingerprint_sha256 = if (Has-Value $script:publicFingerprint) { Get-StringSha256 $script:publicFingerprint } else { $null }
    signature_claims_sha256 = $signatureClaimsHash
    signature_claims = $signatureClaims
    revocation_snapshot_path = "$payloadBasePath/revocations.json"
    revocation_snapshot_sha256 = $revocationSnapshotContentHash
    public_signature_projection_available = $true
    cryptographic_signature_present = $false
    signature_available = $false
    signature_value = $null
    algorithm = "rsa-pss-sha256"
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    remaining_blockers = @(
        "cryptographic-signature-not-present",
        "installer-compatibility-contract-pending",
        "rollback-baseline-not-published-to-install-metadata",
        "large-payload-storage-policy-and-object-storage-pending",
        "installable-media-declared-hash-drift",
        "tls-required-before-ga-claim",
        "exact-operator-approval-not-granted"
    )
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signing_authority_on_mirror = $false
        signer_can_install = $false
        signer_can_activate = $false
        signer_can_execute_rollback = $false
        signer_can_dispatch_fleet = $false
        tui_authority = $false
    }
}
$signedMetadataText = Get-JsonText $signedMetadata
$signedMetadataContentHash = Get-StringSha256 $signedMetadataText

$rc7PayloadSignatures = [ordered]@{
    schema = "agentos.rc7-installable-payload-signatures.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    status = "signature-projection-published-verification-blocked"
    production_ready_claim = $false
    signer_endpoint_domain = $SignerDomain
    signer_key_id = $signedMetadata.signer_key_id
    public_fingerprint_present = $signedMetadata.public_fingerprint_present
    public_fingerprint_sha256 = $signedMetadata.public_fingerprint_sha256
    signed_metadata_path = "$payloadBasePath/signed-metadata.json"
    signed_metadata_sha256 = $signedMetadataContentHash
    revocation_snapshot_path = "$payloadBasePath/revocations.json"
    revocation_snapshot_sha256 = $revocationSnapshotContentHash
    signature_claims_sha256 = $signatureClaimsHash
    public_signature_projection_available = $true
    cryptographic_signature_present = $false
    signature_available = $false
    signature_value = $null
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    signing_authority_on_mirror = $false
    required_signature_bindings = @(
        "release-id",
        "payload-manifest-sha256",
        "payload-checksums-sha256",
        "revocation-snapshot-sha256",
        "policy-version",
        "expiry"
    )
    blocking_reason = "RC7-002 publishes the public signature envelope and revocation snapshot projection, but no external cryptographic signature value is present yet."
}
$rc7PayloadSignaturesText = Get-JsonText $rc7PayloadSignatures
$rc7PayloadSignaturesContentHash = Get-StringSha256 $rc7PayloadSignaturesText

$rc7PayloadIndex = [ordered]@{
    schema = "agentos.rc7-hosted-payload-index.v1"
    generated_at = $generatedAt
    status = "signed-metadata-projected"
    production_ready_claim = $false
    domain = $Domain
    signer_endpoint_domain = $SignerDomain
    channel = "production-candidate-rc7"
    storage_mode = "metadata-only"
    large_artifact_storage_deferred = $true
    tls_required_before_ga_claim = $true
    entries = @(
        [ordered]@{
            id = $releaseId
            release_id = $releaseId
            status = "verification-blocked"
            reason = "Public signature envelope and revocation snapshot projection are published, but install remains blocked until an external cryptographic signature, compatibility contract, rollback baseline, TLS evidence, storage policy, and drift reconciliation exist."
            manifest_path = "$payloadBasePath/manifest.json"
            checksums_path = "$payloadBasePath/checksums.json"
            signatures_path = "$payloadBasePath/signatures.json"
            signed_metadata_path = "$payloadBasePath/signed-metadata.json"
            revocations_path = "$payloadBasePath/revocations.json"
            manifest_sha256 = $hostedResult.output_hashes.payload_manifest_content_sha256
            manifest_file_sha256 = $payloadManifestFileHash
            checksums_sha256 = $hostedResult.output_hashes.payload_checksums_content_sha256
            checksums_file_sha256 = $payloadChecksumsFileHash
            signatures_sha256 = $rc7PayloadSignaturesContentHash
            signed_metadata_sha256 = $signedMetadataContentHash
            revocation_snapshot_sha256 = $revocationSnapshotContentHash
            install_allowed = $false
            activation_allowed = $false
            rollback_execution_allowed = $false
            large_payload_deferred = $true
            public_signature_projection_available = $true
            cryptographic_signature_present = $false
            signature_available = $false
            revocation_snapshot_available = $true
            installable_media_declared_hash_drift_count = $hostedResult.payload_surface.installable_media_declared_hash_drift_count
        }
    )
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        support_upload_authority = $false
        tui_authority = $false
    }
}
$rc7PayloadIndexText = Get-JsonText $rc7PayloadIndex
$rc7PayloadIndexContentHash = Get-StringSha256 $rc7PayloadIndexText

$rc7InstallBootstrap = [ordered]@{
    schema = "agentos.rc7-install-bootstrap.v1"
    generated_at = $generatedAt
    status = "signed-metadata-preflight-only"
    production_ready_claim = $false
    domain = $Domain
    signer_endpoint_domain = $SignerDomain
    channel = "production-candidate-rc7"
    default_release_id = $releaseId
    payload_index_path = "/payloads/index.json"
    current_state = "verification-blocked"
    install_allowed = $false
    activation_allowed = $false
    tls_required_before_ga_claim = $true
    storage_policy = "metadata-only"
    endpoints = [ordered]@{
        payload_index = "/payloads/index.json"
        payload_manifest = "$payloadBasePath/manifest.json"
        payload_checksums = "$payloadBasePath/checksums.json"
        payload_signatures = "$payloadBasePath/signatures.json"
        signed_metadata = "$payloadBasePath/signed-metadata.json"
        revocations = "$payloadBasePath/revocations.json"
    }
    blockers = @(
        "cryptographic-signature-not-present",
        "installer-compatibility-contract-pending",
        "rollback-baseline-not-published-to-install-metadata",
        "large-payload-storage-policy-and-object-storage-pending",
        "installable-media-declared-hash-drift",
        "tls-required-before-ga-claim",
        "exact-operator-approval-not-granted"
    )
    projection = [ordered]@{
        rc6_final_audit_sha256 = $rc6FinalAuditHash
        rc7_contract_sha256 = $rc7ContractHash
        payload_index_sha256 = $rc7PayloadIndexContentHash
        signed_metadata_sha256 = $signedMetadataContentHash
        revocation_snapshot_sha256 = $revocationSnapshotContentHash
        payload_signatures_sha256 = $rc7PayloadSignaturesContentHash
        public_signature_projection_available = $true
        cryptographic_signature_present = $false
        revocation_snapshot_available = $true
    }
    forbidden_authority = @(
        "signing",
        "install",
        "activation",
        "rollback-execution",
        "active-slot-mutation",
        "production-ring-mutation",
        "support-upload",
        "remote-dispatch",
        "tui-authority"
    )
}
$rc7InstallBootstrapText = Get-JsonText $rc7InstallBootstrap
$rc7InstallBootstrapContentHash = Get-StringSha256 $rc7InstallBootstrapText

$preservedEntries = @()
if ($null -ne $hostedChannel -and $null -ne $hostedChannel.entries) {
    $preservedEntries = @($hostedChannel.entries | Where-Object {
        $_.id -notin @("rc7-payload-index", "rc7-current-payload-signatures", "rc7-current-signed-metadata", "rc7-current-revocations", "rc7-install-bootstrap")
    })
}
$rc7Entries = @(
    [ordered]@{
        id = "rc7-payload-index"
        status = "available"
        path = "/payloads/index.json"
        kind = "payload-metadata-index"
        sha256 = $rc7PayloadIndexContentHash
        install_allowed = $false
        activation_allowed = $false
    },
    [ordered]@{
        id = "rc7-current-payload-signatures"
        status = "projection-published"
        path = "$payloadBasePath/signatures.json"
        kind = "payload-signature-projection"
        sha256 = $rc7PayloadSignaturesContentHash
        signature_available = $false
        cryptographic_signature_present = $false
        install_allowed = $false
    },
    [ordered]@{
        id = "rc7-current-signed-metadata"
        status = "projection-published"
        path = "$payloadBasePath/signed-metadata.json"
        kind = "signed-metadata-projection"
        sha256 = $signedMetadataContentHash
        install_allowed = $false
    },
    [ordered]@{
        id = "rc7-current-revocations"
        status = "available"
        path = "$payloadBasePath/revocations.json"
        kind = "revocation-snapshot"
        sha256 = $revocationSnapshotContentHash
        revocation_status = $revocationSnapshot.revocation_status
        install_allowed = $false
    },
    [ordered]@{
        id = "rc7-install-bootstrap"
        status = "available"
        path = "/install/bootstrap.json"
        kind = "installer-bootstrap-metadata"
        sha256 = $rc7InstallBootstrapContentHash
        install_allowed = $false
        activation_allowed = $false
    }
)
$rc7Channel = [ordered]@{
    schema = "agentos.rc7-hosted-channel-index.v1"
    status = "signed-metadata-projected"
    channel = "production-candidate-rc7"
    domain = $Domain
    signer_endpoint_domain = $SignerDomain
    generated_at = $generatedAt
    production_ready_claim = $false
    storage_mode = "metadata-only"
    entries = @($preservedEntries + $rc7Entries)
    support_recovery = $hostedChannel.support_recovery
    payload_channel = [ordered]@{
        index_path = "/payloads/index.json"
        install_bootstrap_path = "/install/bootstrap.json"
        default_release_id = $releaseId
        payload_index_sha256 = $rc7PayloadIndexContentHash
        install_bootstrap_sha256 = $rc7InstallBootstrapContentHash
        payload_manifest_sha256 = $hostedResult.output_hashes.payload_manifest_content_sha256
        payload_checksums_sha256 = $hostedResult.output_hashes.payload_checksums_content_sha256
        payload_signatures_sha256 = $rc7PayloadSignaturesContentHash
        signed_metadata_sha256 = $signedMetadataContentHash
        revocation_snapshot_sha256 = $revocationSnapshotContentHash
        metadata_only = $true
        public_signature_projection_available = $true
        cryptographic_signature_present = $false
        signature_available = $false
        revocation_snapshot_available = $true
        install_allowed = $false
        installable_media_declared_hash_drift_count = $hostedResult.payload_surface.installable_media_declared_hash_drift_count
    }
    authority = [ordered]@{
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        tui_authority = $false
    }
}
$rc7ChannelText = Get-JsonText $rc7Channel
$rc7ChannelContentHash = Get-StringSha256 $rc7ChannelText

$signedMetadataPath = Join-Path $resolvedArtifactDir "signed-metadata.json"
$revocationSnapshotPath = Join-Path $resolvedArtifactDir "revocation-snapshot.json"
$payloadSignaturesPathOut = Join-Path $resolvedArtifactDir "payload-signatures-after-rc7.json"
$payloadIndexPathOut = Join-Path $resolvedArtifactDir "hosted-payload-index-after-signed-metadata.json"
$installBootstrapPathOut = Join-Path $resolvedArtifactDir "install-bootstrap-after-signed-metadata.json"
$channelPathOut = Join-Path $resolvedArtifactDir "hosted-channel-index-after-signed-metadata.json"
$signatureClaimsPathOut = Join-Path $resolvedArtifactDir "signature-claims.json"

Write-Json -Value $signatureClaims -Path $signatureClaimsPathOut
Write-Json -Value $signedMetadata -Path $signedMetadataPath
Write-Json -Value $revocationSnapshot -Path $revocationSnapshotPath
Write-Json -Value $rc7PayloadSignatures -Path $payloadSignaturesPathOut
Write-Json -Value $rc7PayloadIndex -Path $payloadIndexPathOut
Write-Json -Value $rc7InstallBootstrap -Path $installBootstrapPathOut
Write-Json -Value $rc7Channel -Path $channelPathOut

$localOutputTexts = @(
    (Get-Content -Raw -LiteralPath $signatureClaimsPathOut),
    (Get-Content -Raw -LiteralPath $signedMetadataPath),
    (Get-Content -Raw -LiteralPath $revocationSnapshotPath),
    (Get-Content -Raw -LiteralPath $payloadSignaturesPathOut),
    (Get-Content -Raw -LiteralPath $payloadIndexPathOut),
    (Get-Content -Raw -LiteralPath $installBootstrapPathOut),
    (Get-Content -Raw -LiteralPath $channelPathOut)
)

Add-Check "projection.signed_metadata.hash_bound" ($signedMetadata.signature_claims_sha256 -eq $signatureClaimsHash -and $signedMetadata.revocation_snapshot_sha256 -eq $revocationSnapshotContentHash) "Signed metadata projection must bind signature claims and revocation snapshot." ([ordered]@{ signature_claims_sha256 = $signatureClaimsHash; revocation_snapshot_sha256 = $revocationSnapshotContentHash })
Add-Check "projection.signature.not_real" ($signedMetadata.cryptographic_signature_present -eq $false -and $signedMetadata.signature_available -eq $false -and $rc7PayloadSignatures.signature_available -eq $false) "RC7-002 must not claim a real cryptographic signature." ([ordered]@{ signed_metadata = $signedMetadata.status; signatures = $rc7PayloadSignatures.status })
Add-Check "projection.revocation.available" ($revocationSnapshot.revocation_status -eq "not-revoked" -and $rc7PayloadSignatures.revocation_snapshot_sha256 -eq $revocationSnapshotContentHash) "Revocation snapshot projection must be available and hash-bound." ([ordered]@{ revocation_status = $revocationSnapshot.revocation_status; sha256 = $revocationSnapshotContentHash })
Add-Check "projection.install.blocked" ($rc7InstallBootstrap.install_allowed -eq $false -and $rc7InstallBootstrap.current_state -eq "verification-blocked" -and $rc7PayloadIndex.entries[0].install_allowed -eq $false) "Installer bootstrap and payload index must remain verification-blocked." $rc7InstallBootstrap.blockers
Add-Check "projection.no_authority" ($rc7PayloadIndex.authority.signing_authority -eq $false -and $rc7Channel.authority.activation_authority -eq $false -and $rc7Channel.authority.rollback_execution_authority -eq $false -and $rc7Channel.authority.remote_dispatch_authority -eq $false -and $rc7Channel.authority.tui_authority -eq $false) "RC7 projection must not grant signing, activation, rollback, remote dispatch, or TUI authority." $rc7Channel.authority
Add-Check "projection.secret_safe" (Test-NoSensitiveText -Values $localOutputTexts) "RC7 signed metadata and revocation outputs must not contain private key paths, PEM private blocks, tokens, or raw public fingerprint." $null

Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/signed-metadata.json" -Text $signedMetadataText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/revocations.json" -Text $revocationSnapshotText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/signatures.json" -Text $rc7PayloadSignaturesText
Set-RemoteTextFile -Path "/srv/aios-mirror/payloads/index.json" -Text $rc7PayloadIndexText
Set-RemoteTextFile -Path "/srv/aios-mirror/install/bootstrap.json" -Text $rc7InstallBootstrapText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text $rc7ChannelText

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; cd /srv/aios-mirror; sha256sum payloads/index.json install/bootstrap.json channel/index.json $($payloadBasePath.TrimStart('/'))/signatures.json $($payloadBasePath.TrimStart('/'))/signed-metadata.json $($payloadBasePath.TrimStart('/'))/revocations.json"

$payloadIndexResponse = Invoke-Curl "http://$Domain/payloads/index.json"
$payloadSignaturesResponse = Invoke-Curl "http://$Domain$payloadBasePath/signatures.json"
$signedMetadataResponse = Invoke-Curl "http://$Domain$payloadBasePath/signed-metadata.json"
$revocationsResponse = Invoke-Curl "http://$Domain$payloadBasePath/revocations.json"
$installResponse = Invoke-Curl "http://$Domain/install/bootstrap.json"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$payloadDirResponse = Invoke-Curl "http://$Domain$payloadBasePath/"
$postResponse = Invoke-Curl "http://$Domain$payloadBasePath/signatures.json" -Method "POST"
$signerHealthResponse = Invoke-Curl "http://$SignerDomain/health.json" -HostDomain $SignerDomain

$payloadIndexLive = ConvertFrom-JsonTextSafe $payloadIndexResponse.body
$payloadSignaturesLive = ConvertFrom-JsonTextSafe $payloadSignaturesResponse.body
$signedMetadataLive = ConvertFrom-JsonTextSafe $signedMetadataResponse.body
$revocationsLive = ConvertFrom-JsonTextSafe $revocationsResponse.body
$installLive = ConvertFrom-JsonTextSafe $installResponse.body
$channelLive = ConvertFrom-JsonTextSafe $channelResponse.body

$remoteHttpReady = $payloadIndexResponse.status_code -eq 200 -and
    $payloadSignaturesResponse.status_code -eq 200 -and
    $signedMetadataResponse.status_code -eq 200 -and
    $revocationsResponse.status_code -eq 200 -and
    $installResponse.status_code -eq 200 -and
    $channelResponse.status_code -eq 200

$remoteSemanticsReady = $null -ne $payloadIndexLive -and
    $null -ne $payloadSignaturesLive -and
    $null -ne $signedMetadataLive -and
    $null -ne $revocationsLive -and
    $null -ne $installLive -and
    $null -ne $channelLive -and
    $payloadIndexLive.entries[0].release_id -eq $releaseId -and
    $payloadIndexLive.entries[0].status -eq "verification-blocked" -and
    $payloadIndexLive.entries[0].signature_available -eq $false -and
    $payloadIndexLive.entries[0].revocation_snapshot_available -eq $true -and
    $payloadSignaturesLive.cryptographic_signature_present -eq $false -and
    $payloadSignaturesLive.revocation_snapshot_sha256 -eq $revocationSnapshotContentHash -and
    $signedMetadataLive.signature_claims_sha256 -eq $signatureClaimsHash -and
    $signedMetadataLive.cryptographic_signature_present -eq $false -and
    $revocationsLive.revocation_status -eq "not-revoked" -and
    $installLive.current_state -eq "verification-blocked" -and
    $channelLive.payload_channel.install_allowed -eq $false

$remoteHashReady = $null -ne $payloadIndexLive -and
    $null -ne $installLive -and
    $null -ne $channelLive -and
    $payloadIndexLive.entries[0].signed_metadata_sha256 -eq $signedMetadataContentHash -and
    $payloadIndexLive.entries[0].revocation_snapshot_sha256 -eq $revocationSnapshotContentHash -and
    $payloadIndexLive.entries[0].signatures_sha256 -eq $rc7PayloadSignaturesContentHash -and
    $installLive.projection.signed_metadata_sha256 -eq $signedMetadataContentHash -and
    $installLive.projection.revocation_snapshot_sha256 -eq $revocationSnapshotContentHash -and
    $channelLive.payload_channel.signed_metadata_sha256 -eq $signedMetadataContentHash -and
    $channelLive.payload_channel.revocation_snapshot_sha256 -eq $revocationSnapshotContentHash

$remoteSecretSafe = Test-NoSensitiveText -Values @(
    $payloadIndexResponse.body,
    $payloadSignaturesResponse.body,
    $signedMetadataResponse.body,
    $revocationsResponse.body,
    $installResponse.body,
    $channelResponse.body
)

Add-Check "remote.nginx.active" ($remoteCheck -match "active") "Nginx must remain active after RC7 signed metadata projection publication." ($remoteCheck -split "`n")
Add-Check "remote.http.ready" $remoteHttpReady "RC7 signed metadata, revocations, signatures, install bootstrap, and channel metadata must be reachable." ([ordered]@{
    payload_index = $payloadIndexResponse.status_code
    signatures = $payloadSignaturesResponse.status_code
    signed_metadata = $signedMetadataResponse.status_code
    revocations = $revocationsResponse.status_code
    install = $installResponse.status_code
    channel = $channelResponse.status_code
})
Add-Check "remote.semantics.blocked" $remoteSemanticsReady "Live RC7 metadata must publish projection evidence while keeping install blocked." ([ordered]@{
    release_id = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].release_id } else { $null }
    install_state = if ($null -ne $installLive) { $installLive.current_state } else { $null }
    cryptographic_signature_present = if ($null -ne $payloadSignaturesLive) { $payloadSignaturesLive.cryptographic_signature_present } else { $null }
    revocation_status = if ($null -ne $revocationsLive) { $revocationsLive.revocation_status } else { $null }
})
Add-Check "remote.hash_bindings.match" $remoteHashReady "Live RC7 metadata must carry local signed metadata and revocation hashes." ([ordered]@{
    signed_metadata_sha256 = $signedMetadataContentHash
    revocation_snapshot_sha256 = $revocationSnapshotContentHash
    payload_signatures_sha256 = $rc7PayloadSignaturesContentHash
})
Add-Check "remote.secret_safe" $remoteSecretSafe "Remote RC7 metadata responses must not expose private key paths, PEM private blocks, tokens, or raw public fingerprint." $null
Add-Check "remote.directory_listing.blocked" (@(403, 404) -contains $payloadDirResponse.status_code) "Payload release directory listing must remain blocked." $payloadDirResponse.status_code
Add-Check "remote.write_methods.blocked" (@(403, 405) -contains $postResponse.status_code) "POST to payload signature metadata must remain blocked." $postResponse.status_code
Add-Check "signer.endpoint.separate" ($SignerDomain -ne $Domain -and $signerHealthResponse.status_code -in @(200, 301, 302, 404)) "Signer endpoint must remain separate from mirror; RC7-002 does not require calling it for signing." ([ordered]@{ signer_domain = $SignerDomain; mirror_domain = $Domain; health_status = $signerHealthResponse.status_code })

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-signed-metadata-revocation-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-002"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        signer_domain = $SignerDomain
        static_root = "/srv/aios-mirror"
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source = [ordered]@{
        rc7_contract = [ordered]@{ path = Get-StablePath $resolvedRc7ContractPath; sha256 = $rc7ContractHash }
        rc6_final_audit = [ordered]@{ path = Get-StablePath $resolvedRc6FinalAuditPath; sha256 = $rc6FinalAuditHash }
        hosted_payload_result = [ordered]@{ path = Get-StablePath $resolvedHostedPayloadResultPath; sha256 = $hostedPayloadResultHash }
        hosted_payload_index = [ordered]@{ path = Get-StablePath $resolvedHostedPayloadIndexPath; sha256 = $hostedPayloadIndexHash }
        hosted_install_bootstrap = [ordered]@{ path = Get-StablePath $resolvedHostedInstallBootstrapPath; sha256 = $hostedInstallHash }
        payload_manifest = [ordered]@{ path = Get-StablePath $resolvedPayloadManifestPath; sha256 = $payloadManifestFileHash }
        payload_checksums = [ordered]@{ path = Get-StablePath $resolvedPayloadChecksumsPath; sha256 = $payloadChecksumsFileHash }
        previous_payload_signatures = [ordered]@{ path = Get-StablePath $resolvedPayloadSignaturesPath; sha256 = $payloadSignaturesFileHash }
        key_custody = [ordered]@{ path = Get-StablePath $resolvedKeyCustodyPath; sha256 = $keyCustodyHash; public_fingerprint_present = Has-Value $script:publicFingerprint }
        revocation_log = [ordered]@{ path = Get-StablePath $resolvedRevocationLogPath; sha256 = $revocationLogHash }
    }
    local_outputs = [ordered]@{
        signature_claims = Get-StablePath $signatureClaimsPathOut
        signed_metadata = Get-StablePath $signedMetadataPath
        revocation_snapshot = Get-StablePath $revocationSnapshotPath
        payload_signatures = Get-StablePath $payloadSignaturesPathOut
        hosted_payload_index = Get-StablePath $payloadIndexPathOut
        install_bootstrap = Get-StablePath $installBootstrapPathOut
        hosted_channel_index = Get-StablePath $channelPathOut
    }
    published_endpoints = @(
        "http://$Domain/payloads/index.json",
        "http://$Domain$payloadBasePath/signatures.json",
        "http://$Domain$payloadBasePath/signed-metadata.json",
        "http://$Domain$payloadBasePath/revocations.json",
        "http://$Domain/install/bootstrap.json",
        "http://$Domain/channel/index.json"
    )
    output_hashes = [ordered]@{
        signature_claims_sha256 = $signatureClaimsHash
        signed_metadata_sha256 = $signedMetadataContentHash
        revocation_snapshot_sha256 = $revocationSnapshotContentHash
        payload_signatures_sha256 = $rc7PayloadSignaturesContentHash
        hosted_payload_index_sha256 = $rc7PayloadIndexContentHash
        install_bootstrap_sha256 = $rc7InstallBootstrapContentHash
        hosted_channel_index_sha256 = $rc7ChannelContentHash
    }
    payload_surface = [ordered]@{
        release_id = $releaseId
        base_path = $payloadBasePath
        status = "verification-blocked"
        public_signature_projection_available = $true
        cryptographic_signature_present = $false
        signature_available = $false
        revocation_snapshot_available = $true
        revocation_status = $revocationSnapshot.revocation_status
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        external_signer_called_for_signature = $false
        mirror_is_root_of_trust = $false
        signing_authority_on_mirror = $false
        payload_upload_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_002_complete = $passed
        next_task = "RC7-003"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC7 signed metadata and revocation projection $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
