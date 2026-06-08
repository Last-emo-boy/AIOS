param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-installer-signed-consumption",
    [string]$ResultPath = "",
    [string]$Rc7SignedMetadataResultPath = ".workflow/artifacts/rc7-signed-metadata-revocation/result.json",
    [string]$Rc7CompatibilityContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/installer-compatibility-rollback-baseline-contract.md",
    [string]$Rc6PreflightResultPath = ".workflow/artifacts/rc6-bootstrap-installer-preflight/result.json",
    [string]$Rc6PreflightReportPath = ".workflow/artifacts/rc6-bootstrap-installer-preflight/preflight-report.json",
    [string]$Rc6InstallerFailClosedResultPath = ".workflow/artifacts/rc6-installer-fail-closed/result.json",
    [int]$CurlTimeoutSeconds = 15,
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
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
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
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

function Invoke-CurlPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = "GET"
    )
    $url = "http://$Domain$Path"
    $args = @(
        "--noproxy", "*",
        "--max-time", "$CurlTimeoutSeconds",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-X", $Method,
        "-w", "`n%{http_code}",
        $url
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
        path = $Path
        url = $url
        method = $Method
        exit_code = $exitCode
        status_code = $statusCode
        body_sha256 = Get-StringSha256 $body
        json = if ($statusCode -eq 200) { ConvertFrom-JsonTextSafe $body } else { $null }
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
        $script:taskBlockers += $entry
    }
}

function Add-InstallerStep {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "blocked" }
        message = $Message
        evidence = $Evidence
    }
    $script:installerSteps += $entry
    if (-not $Passed) {
        $script:installerBlockers += $entry
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        ("BEGIN" + " " + "PRIVATE" + " " + "KEY"),
        ("PRIVATE" + " " + "KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ".local-release-authority",
        ("signing" + "-key.pem")
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
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
$script:taskBlockers = @()
$script:installerSteps = @()
$script:installerBlockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath
$reportPath = Join-Path $resolvedArtifactDir "consumption-report.json"

$resolvedRc7SignedMetadataResultPath = Resolve-RepoPath $Rc7SignedMetadataResultPath
$resolvedRc7CompatibilityContractPath = Resolve-RepoPath $Rc7CompatibilityContractPath
$resolvedRc6PreflightResultPath = Resolve-RepoPath $Rc6PreflightResultPath
$resolvedRc6PreflightReportPath = Resolve-RepoPath $Rc6PreflightReportPath
$resolvedRc6InstallerFailClosedResultPath = Resolve-RepoPath $Rc6InstallerFailClosedResultPath

$generatedAt = (Get-Date).ToString("o")
$rc7SignedResult = Read-Json $resolvedRc7SignedMetadataResultPath
$rc7CompatibilityContractText = Get-Content -Raw -LiteralPath $resolvedRc7CompatibilityContractPath
$rc6PreflightResult = Read-Json $resolvedRc6PreflightResultPath
$rc6PreflightReport = Read-Json $resolvedRc6PreflightReportPath
$rc6InstallerFailClosed = Read-Json $resolvedRc6InstallerFailClosedResultPath

Add-Check "source.rc7_signed_metadata.result" ($rc7SignedResult.status -eq "passed" -and $rc7SignedResult.summary.blockers -eq 0) "RC7-002 signed metadata and revocation projection must be passed." $rc7SignedResult.summary
Add-Check "source.rc7_003_contract.present" ($rc7CompatibilityContractText.Contains("/install/compatibility.json") -and $rc7CompatibilityContractText.Contains("/install/rollback-baseline.json")) "RC7-003 compatibility and rollback baseline contract must define both install endpoints." (Get-StablePath $resolvedRc7CompatibilityContractPath)
Add-Check "source.rc6_preflight.blocked_expected" ($rc6PreflightResult.status -eq "passed" -and $rc6PreflightResult.preflight.state -eq "verification-blocked" -and $rc6PreflightResult.preflight.blockers -ge 4) "RC6 preflight should be passed as a task while remaining verification-blocked." $rc6PreflightResult.preflight
Add-Check "source.rc6_fail_closed.result" ($rc6InstallerFailClosed.status -eq "passed" -and $rc6InstallerFailClosed.summary.failed_cases -eq 0) "RC6 installer fail-closed fixtures must pass before projecting RC7 consumption." $rc6InstallerFailClosed.summary

$fetches = [ordered]@{}
foreach ($path in @("/channel/index.json", "/install/bootstrap.json", "/payloads/index.json")) {
    $fetches[$path] = Invoke-CurlPath $path
}

$payloadIndex = $fetches["/payloads/index.json"].json
$installBootstrap = $fetches["/install/bootstrap.json"].json
$channelIndex = $fetches["/channel/index.json"].json
$entry = if ($null -ne $payloadIndex -and $null -ne $payloadIndex.entries) { @($payloadIndex.entries)[0] } else { $null }

$payloadPaths = @()
if ($null -ne $entry) {
    foreach ($path in @($entry.manifest_path, $entry.checksums_path, $entry.signatures_path, $entry.signed_metadata_path, $entry.revocations_path)) {
        if ((Has-Value $path) -and -not $fetches.Contains($path)) {
            $payloadPaths += $path
        }
    }
}
foreach ($path in $payloadPaths) {
    $fetches[$path] = Invoke-CurlPath $path
}

$compatibilityFetch = Invoke-CurlPath "/install/compatibility.json"
$rollbackFetch = Invoke-CurlPath "/install/rollback-baseline.json"

$manifest = if ($null -ne $entry -and (Has-Value $entry.manifest_path)) { $fetches[$entry.manifest_path].json } else { $null }
$checksums = if ($null -ne $entry -and (Has-Value $entry.checksums_path)) { $fetches[$entry.checksums_path].json } else { $null }
$signatures = if ($null -ne $entry -and (Has-Value $entry.signatures_path)) { $fetches[$entry.signatures_path].json } else { $null }
$signedMetadata = if ($null -ne $entry -and (Has-Value $entry.signed_metadata_path)) { $fetches[$entry.signed_metadata_path].json } else { $null }
$revocations = if ($null -ne $entry -and (Has-Value $entry.revocations_path)) { $fetches[$entry.revocations_path].json } else { $null }

$requiredFetches = @(
    $fetches["/channel/index.json"],
    $fetches["/install/bootstrap.json"],
    $fetches["/payloads/index.json"]
)
foreach ($path in $payloadPaths) {
    $requiredFetches += $fetches[$path]
}

$allRequiredFetched = (@($requiredFetches | Where-Object { $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0)
$expectedPayloadIndexHash = $rc7SignedResult.output_hashes.hosted_payload_index_sha256
$expectedInstallHash = $rc7SignedResult.output_hashes.install_bootstrap_sha256
$expectedChannelHash = $rc7SignedResult.output_hashes.hosted_channel_index_sha256
$expectedSignaturesHash = $rc7SignedResult.output_hashes.payload_signatures_sha256
$expectedSignedMetadataHash = $rc7SignedResult.output_hashes.signed_metadata_sha256
$expectedRevocationHash = $rc7SignedResult.output_hashes.revocation_snapshot_sha256

$payloadIndexHashMatches = $installBootstrap.projection.payload_index_sha256 -eq $expectedPayloadIndexHash -and $channelIndex.payload_channel.payload_index_sha256 -eq $expectedPayloadIndexHash
$installHashMatches = $channelIndex.payload_channel.install_bootstrap_sha256 -eq $expectedInstallHash
$channelHashMatches = $null -ne $channelIndex -and $channelIndex.schema -eq "agentos.rc7-hosted-channel-index.v1"
$signaturesHashMatches = $null -ne $entry -and (Has-Value $entry.signatures_path) -and $entry.signatures_sha256 -eq $expectedSignaturesHash -and $installBootstrap.projection.payload_signatures_sha256 -eq $expectedSignaturesHash -and $channelIndex.payload_channel.payload_signatures_sha256 -eq $expectedSignaturesHash
$signedMetadataHashMatches = $null -ne $entry -and (Has-Value $entry.signed_metadata_path) -and $entry.signed_metadata_sha256 -eq $expectedSignedMetadataHash -and $signatures.signed_metadata_sha256 -eq $expectedSignedMetadataHash -and $installBootstrap.projection.signed_metadata_sha256 -eq $expectedSignedMetadataHash -and $channelIndex.payload_channel.signed_metadata_sha256 -eq $expectedSignedMetadataHash
$revocationHashMatches = $null -ne $entry -and (Has-Value $entry.revocations_path) -and $entry.revocation_snapshot_sha256 -eq $expectedRevocationHash -and $signatures.revocation_snapshot_sha256 -eq $expectedRevocationHash -and $installBootstrap.projection.revocation_snapshot_sha256 -eq $expectedRevocationHash -and $channelIndex.payload_channel.revocation_snapshot_sha256 -eq $expectedRevocationHash
$hostedByteHashesMatch = (
    $fetches["/payloads/index.json"].body_sha256 -eq $expectedPayloadIndexHash -and
    $fetches["/install/bootstrap.json"].body_sha256 -eq $expectedInstallHash -and
    $fetches["/channel/index.json"].body_sha256 -eq $expectedChannelHash -and
    $null -ne $entry -and
    (Has-Value $entry.signatures_path) -and
    (Has-Value $entry.signed_metadata_path) -and
    (Has-Value $entry.revocations_path) -and
    $fetches[$entry.signatures_path].body_sha256 -eq $expectedSignaturesHash -and
    $fetches[$entry.signed_metadata_path].body_sha256 -eq $expectedSignedMetadataHash -and
    $fetches[$entry.revocations_path].body_sha256 -eq $expectedRevocationHash
)

$schemasRecognized = (
    $payloadIndex.schema -eq "agentos.rc7-hosted-payload-index.v1" -and
    $installBootstrap.schema -eq "agentos.rc7-install-bootstrap.v1" -and
    $channelIndex.schema -eq "agentos.rc7-hosted-channel-index.v1" -and
    $manifest.schema -eq "agentos.rc6-installable-payload-manifest.v1" -and
    $checksums.schema -eq "agentos.rc6-installable-payload-checksums.v1" -and
    $signatures.schema -eq "agentos.rc7-installable-payload-signatures.v1" -and
    $signedMetadata.schema -eq "agentos.rc7-signed-metadata-projection.v1" -and
    $revocations.schema -eq "agentos.rc7-revocation-snapshot.v1"
)
$productionReadyFalse = (
    $payloadIndex.production_ready_claim -eq $false -and
    $installBootstrap.production_ready_claim -eq $false -and
    $channelIndex.production_ready_claim -eq $false -and
    $manifest.production_ready_claim -eq $false -and
    $signatures.production_ready_claim -eq $false -and
    $signedMetadata.production_ready_claim -eq $false -and
    $revocations.production_ready_claim -eq $false
)

$signedMetadataObserved = (
    $null -ne $signedMetadata -and
    $signatures.public_signature_projection_available -eq $true -and
    $signedMetadata.public_signature_projection_available -eq $true -and
    (Has-Value $signatures.signed_metadata_path) -and
    $signedMetadataHashMatches
)
$revocationObserved = (
    $null -ne $revocations -and
    $revocations.revocation_status -eq "not-revoked" -and
    (Has-Value $signatures.revocation_snapshot_path) -and
    $revocationHashMatches
)
$signatureClaimsBound = (
    $null -ne $signedMetadata -and
    $signedMetadata.signature_claims.release_id -eq $entry.release_id -and
    $signedMetadata.signature_claims.revocation_snapshot_sha256 -eq $expectedRevocationHash -and
    $signedMetadata.signature_claims.payload_manifest_content_sha256 -eq $entry.manifest_sha256 -and
    $signatures.signature_claims_sha256 -eq $signedMetadata.signature_claims_sha256
)
$cryptographicSignaturePresent = (
    $signatures.cryptographic_signature_present -eq $true -and
    $signatures.signature_available -eq $true -and
    $signedMetadata.cryptographic_signature_present -eq $true -and
    (Has-Value $signedMetadata.signature_value)
)
$compatibilityPublishedAndBound = (
    $compatibilityFetch.status_code -eq 200 -and
    $null -ne $compatibilityFetch.json -and
    $compatibilityFetch.json.schema -eq "agentos.rc7-installer-compatibility.v1" -and
    $installBootstrap.projection.installer_compatibility_sha256 -eq $compatibilityFetch.body_sha256
)
$rollbackPublishedAndBound = (
    $rollbackFetch.status_code -eq 200 -and
    $null -ne $rollbackFetch.json -and
    $rollbackFetch.json.schema -eq "agentos.rc7-rollback-baseline.v1" -and
    $installBootstrap.projection.rollback_baseline_sha256 -eq $rollbackFetch.body_sha256
)
$storageAndDriftResolved = (
    $payloadIndex.storage_mode -ne "metadata-only" -and
    $entry.large_payload_deferred -eq $false -and
    $entry.installable_media_declared_hash_drift_count -eq 0
)
$tlsGateSatisfied = $false
$exactApprovalPresent = $false

Add-Check "live.required_rc7_endpoints" $allRequiredFetched "RC7 signed consumption must fetch channel, install bootstrap, payload index, manifest, checksums, signatures, signed metadata, and revocations as JSON." (@($requiredFetches | ForEach-Object { [ordered]@{ path = $_.path; status = $_.status_code; parsed = $null -ne $_.json } }))
Add-Check "live.metadata_references_match_rc7_publication" ($payloadIndexHashMatches -and $installHashMatches -and $channelHashMatches -and $signaturesHashMatches -and $signedMetadataHashMatches -and $revocationHashMatches) "Live hosted metadata references must match RC7-002 publication result hashes." ([ordered]@{
    payload_index = $payloadIndexHashMatches
    install_bootstrap = $installHashMatches
    channel_index = $channelHashMatches
    signatures = $signaturesHashMatches
    signed_metadata = $signedMetadataHashMatches
    revocations = $revocationHashMatches
})
Add-Check "live.schemas_and_non_ga" ($schemasRecognized -and $productionReadyFalse) "Live metadata schemas must be recognized and production_ready_claim must remain false." ([ordered]@{ schemas_recognized = $schemasRecognized; production_ready_false = $productionReadyFalse })
Add-Check "consumption.signature_and_revocation_observed" ($signedMetadataObserved -and $revocationObserved -and $signatureClaimsBound) "Installer projection must observe signed metadata projection, revocation snapshot, and hash-bound signature claims." ([ordered]@{
    signed_metadata_observed = $signedMetadataObserved
    revocation_observed = $revocationObserved
    signature_claims_bound = $signatureClaimsBound
})

Add-InstallerStep "fetch-rc7-signed-consumption-metadata" $allRequiredFetched "Fetched RC7 signed consumption metadata surface with local DNS bypassed." (@($requiredFetches | ForEach-Object { $_.path }))
Add-InstallerStep "verify-schema-and-production-ready-false" ($schemasRecognized -and $productionReadyFalse) "Schemas are recognized and production_ready_claim remains false."
Add-InstallerStep "verify-hosted-publication-hash-bindings" ($payloadIndexHashMatches -and $installHashMatches -and $channelHashMatches -and $signaturesHashMatches) "Hosted channel, install bootstrap, payload index, and signatures match RC7 publication hashes." ([ordered]@{
    payload_index_sha256 = if ($null -ne $installBootstrap) { $installBootstrap.projection.payload_index_sha256 } else { $null }
    install_bootstrap_sha256 = if ($null -ne $channelIndex) { $channelIndex.payload_channel.install_bootstrap_sha256 } else { $null }
    channel_index_schema = if ($null -ne $channelIndex) { $channelIndex.schema } else { $null }
    signatures_sha256 = if ($null -ne $entry) { $entry.signatures_sha256 } else { $null }
})
Add-InstallerStep "verify-hosted-byte-hash-canonicalization" $hostedByteHashesMatch "Downloaded endpoint byte hashes must match advertised publication hashes before install can advance." ([ordered]@{
    payload_index_body_sha256 = $fetches["/payloads/index.json"].body_sha256
    expected_payload_index_sha256 = $expectedPayloadIndexHash
    install_bootstrap_body_sha256 = $fetches["/install/bootstrap.json"].body_sha256
    expected_install_bootstrap_sha256 = $expectedInstallHash
    channel_index_body_sha256 = $fetches["/channel/index.json"].body_sha256
    expected_channel_index_sha256 = $expectedChannelHash
    signatures_body_sha256 = if ($null -ne $entry -and (Has-Value $entry.signatures_path)) { $fetches[$entry.signatures_path].body_sha256 } else { $null }
    expected_signatures_sha256 = $expectedSignaturesHash
    signed_metadata_body_sha256 = if ($null -ne $entry -and (Has-Value $entry.signed_metadata_path)) { $fetches[$entry.signed_metadata_path].body_sha256 } else { $null }
    expected_signed_metadata_sha256 = $expectedSignedMetadataHash
    revocations_body_sha256 = if ($null -ne $entry -and (Has-Value $entry.revocations_path)) { $fetches[$entry.revocations_path].body_sha256 } else { $null }
    expected_revocations_sha256 = $expectedRevocationHash
})
Add-InstallerStep "verify-signed-metadata-reference" $signedMetadataObserved "Signed metadata projection is referenced by signatures metadata and payload index." ([ordered]@{
    signed_metadata_path = if ($null -ne $signatures) { $signatures.signed_metadata_path } else { $null }
    signed_metadata_sha256 = if ($null -ne $signatures) { $signatures.signed_metadata_sha256 } else { $null }
})
Add-InstallerStep "verify-revocation-snapshot-reference" $revocationObserved "Revocation snapshot projection is referenced by signatures metadata and payload index." ([ordered]@{
    revocation_snapshot_path = if ($null -ne $signatures) { $signatures.revocation_snapshot_path } else { $null }
    revocation_snapshot_sha256 = if ($null -ne $signatures) { $signatures.revocation_snapshot_sha256 } else { $null }
    revocation_status = if ($null -ne $revocations) { $revocations.revocation_status } else { $null }
})
Add-InstallerStep "verify-signature-claims-binding" $signatureClaimsBound "Signed metadata claims bind release id, payload manifest, and revocation snapshot." ([ordered]@{
    release_id = if ($null -ne $signedMetadata) { $signedMetadata.signature_claims.release_id } else { $null }
    payload_manifest_content_sha256 = if ($null -ne $signedMetadata) { $signedMetadata.signature_claims.payload_manifest_content_sha256 } else { $null }
    revocation_snapshot_sha256 = if ($null -ne $signedMetadata) { $signedMetadata.signature_claims.revocation_snapshot_sha256 } else { $null }
})
Add-InstallerStep "verify-cryptographic-signature-value" $cryptographicSignaturePresent "A real cryptographic signature value must be present before install can advance." ([ordered]@{
    cryptographic_signature_present = if ($null -ne $signatures) { $signatures.cryptographic_signature_present } else { $null }
    signature_available = if ($null -ne $signatures) { $signatures.signature_available } else { $null }
})
Add-InstallerStep "verify-installer-compatibility-publication" $compatibilityPublishedAndBound "Installer compatibility metadata must be published and hash-bound from install bootstrap." ([ordered]@{
    endpoint_status = $compatibilityFetch.status_code
    schema = if ($null -ne $compatibilityFetch.json) { $compatibilityFetch.json.schema } else { $null }
    install_bootstrap_reference = if ($installBootstrap.projection.PSObject.Properties.Name -contains "installer_compatibility_sha256") { $installBootstrap.projection.installer_compatibility_sha256 } else { $null }
})
Add-InstallerStep "verify-rollback-baseline-publication" $rollbackPublishedAndBound "Rollback baseline metadata must be published and hash-bound from install bootstrap." ([ordered]@{
    endpoint_status = $rollbackFetch.status_code
    schema = if ($null -ne $rollbackFetch.json) { $rollbackFetch.json.schema } else { $null }
    install_bootstrap_reference = if ($installBootstrap.projection.PSObject.Properties.Name -contains "rollback_baseline_sha256") { $installBootstrap.projection.rollback_baseline_sha256 } else { $null }
})
Add-InstallerStep "verify-storage-policy-and-drift-reconciliation" $storageAndDriftResolved "Large payload storage policy and declared/current hash drift must be resolved before install." ([ordered]@{
    storage_mode = if ($null -ne $payloadIndex) { $payloadIndex.storage_mode } else { $null }
    large_payload_deferred = if ($null -ne $entry) { $entry.large_payload_deferred } else { $null }
    installable_media_declared_hash_drift_count = if ($null -ne $entry) { $entry.installable_media_declared_hash_drift_count } else { $null }
})
Add-InstallerStep "verify-tls-ga-gate" $tlsGateSatisfied "TLS evidence is required before any GA or install-authorized claim." ([ordered]@{
    validation_protocol = "http"
    tls_required_before_ga_claim = if ($null -ne $installBootstrap) { $installBootstrap.tls_required_before_ga_claim } else { $null }
})
Add-InstallerStep "verify-exact-operator-approval" $exactApprovalPresent "Exact operator approval is not present in this metadata-only projection." ([ordered]@{
    exact_approval_present = $exactApprovalPresent
    agentcore_planspec_issued = $false
    security_execution_engine_approved = $false
})

$installerState = if (@($script:installerBlockers).Count -eq 0) { "signed-consumption-ready" } else { "verification-blocked" }
$sideEffects = [ordered]@{
    metadata_preflight_only = $true
    validation_used_local_dns = $false
    local_private_key_material_used = $false
    private_key_material_read_or_printed = $false
    cryptographic_signing_performed = $false
    install_allowed = $false
    install_performed = $false
    activation_allowed = $false
    activation_performed = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    active_slot_mutated = $false
    production_ring_mutated = $false
    support_upload_performed = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
}

Add-Check "consumption.expected_blocked_state" ($installerState -eq "verification-blocked" -and @($script:installerBlockers).Count -ge 5 -and $installBootstrap.install_allowed -eq $false -and $entry.install_allowed -eq $false) "Installer consumption should observe signed metadata/revocation but remain verification-blocked." ([ordered]@{
    state = $installerState
    installer_blockers = @($script:installerBlockers).Count
    install_allowed = if ($null -ne $installBootstrap) { $installBootstrap.install_allowed } else { $null }
})
Add-Check "consumption.no_side_effects" ($sideEffects.install_performed -eq $false -and $sideEffects.activation_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.tui_authority -eq $false) "RC7-010 must not install, activate, rollback, mutate rings, dispatch, or grant TUI authority." $sideEffects

$fetchedEndpointSummary = @($fetches.Values | ForEach-Object {
    [ordered]@{
        path = $_.path
        status_code = $_.status_code
        parsed_json = $null -ne $_.json
        body_sha256 = $_.body_sha256
    }
})
$optionalEndpointSummary = @(
    [ordered]@{
        path = $compatibilityFetch.path
        status_code = $compatibilityFetch.status_code
        parsed_json = $null -ne $compatibilityFetch.json
        body_sha256 = $compatibilityFetch.body_sha256
    },
    [ordered]@{
        path = $rollbackFetch.path
        status_code = $rollbackFetch.status_code
        parsed_json = $null -ne $rollbackFetch.json
        body_sha256 = $rollbackFetch.body_sha256
    }
)

$report = [ordered]@{
    schema = "agentos.rc7-installer-signed-consumption-report.v1"
    generated_at = $generatedAt
    production_ready_claim = $false
    release_id = if ($null -ne $entry) { $entry.release_id } else { $null }
    domain = $Domain
    validation_used_local_dns = $false
    validation_resolve_override = "$Domain`:80`:$RemoteHost"
    state = $installerState
    allowed_outputs = @(
        "consumption-report",
        "signed-metadata-observation",
        "revocation-observation",
        "remaining-blockers-list"
    )
    source = [ordered]@{
        rc7_signed_metadata_revocation = New-ArtifactRef $resolvedRc7SignedMetadataResultPath $rc7SignedResult
        rc7_installer_compatibility_rollback_contract = [ordered]@{
            path = Get-StablePath $resolvedRc7CompatibilityContractPath
            sha256 = Get-FileSha256 $resolvedRc7CompatibilityContractPath
            present = Test-Path -LiteralPath $resolvedRc7CompatibilityContractPath -PathType Leaf
        }
        rc6_bootstrap_preflight_result = New-ArtifactRef $resolvedRc6PreflightResultPath $rc6PreflightResult
        rc6_bootstrap_preflight_report = New-ArtifactRef $resolvedRc6PreflightReportPath $rc6PreflightReport
        rc6_installer_fail_closed = New-ArtifactRef $resolvedRc6InstallerFailClosedResultPath $rc6InstallerFailClosed
    }
    observed = [ordered]@{
        signed_metadata_reference_observed = $signedMetadataObserved
        revocation_snapshot_observed = $revocationObserved
        signature_claims_bound = $signatureClaimsBound
        public_signature_projection_available = if ($null -ne $signatures) { $signatures.public_signature_projection_available } else { $null }
        cryptographic_signature_present = if ($null -ne $signatures) { $signatures.cryptographic_signature_present } else { $null }
        signature_available = if ($null -ne $signatures) { $signatures.signature_available } else { $null }
        compatibility_contract_published = $compatibilityPublishedAndBound
        rollback_baseline_published = $rollbackPublishedAndBound
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    rc6_blocker_delta = [ordered]@{
        previous_preflight_blockers = @($rc6PreflightReport.blockers | ForEach-Object { $_.id })
        resolved_by_rc7_002_projection = @(
            "verify-signature-or-signed-metadata-reference",
            "verify-revocation-snapshot"
        )
        still_blocked_after_rc7_010 = @($script:installerBlockers | ForEach-Object { $_.id })
    }
    fetched_endpoints = $fetchedEndpointSummary
    optional_unpublished_endpoints = $optionalEndpointSummary
    installer_steps = $script:installerSteps
    installer_blockers = $script:installerBlockers
    side_effects = $sideEffects
}

Write-Json $report $reportPath
$reportHash = Get-FileSha256 $reportPath

Add-Check "report.generated" ((Test-Path -LiteralPath $reportPath -PathType Leaf) -and (Has-Value $reportHash)) "Consumption report must be generated." (Get-StablePath $reportPath)
$reportText = Get-Content -Raw -LiteralPath $reportPath
Add-Check "report.secret_safe" (Test-NoSensitiveText -Values @($reportText, ($script:checks | ConvertTo-Json -Depth 100), ($script:installerSteps | ConvertTo-Json -Depth 100))) "Consumption report and checks must not contain private key or token markers."

$result = [ordered]@{
    schema = "agentos.rc7-installer-signed-consumption-result.v1"
    generated_at = $generatedAt
    task = "RC7-010"
    status = if (@($script:taskBlockers).Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    report = [ordered]@{
        path = Get-StablePath $reportPath
        sha256 = $reportHash
        state = $installerState
        installer_blockers = @($script:installerBlockers).Count
    }
    fetched_endpoints = $fetchedEndpointSummary
    source = $report.source
    consumption_summary = [ordered]@{
        signed_metadata_observed = $signedMetadataObserved
        revocation_snapshot_observed = $revocationObserved
        signature_claims_bound = $signatureClaimsBound
        cryptographic_signature_present = if ($null -ne $signatures) { $signatures.cryptographic_signature_present } else { $null }
        signature_available = if ($null -ne $signatures) { $signatures.signature_available } else { $null }
        compatibility_contract_published = $compatibilityPublishedAndBound
        rollback_baseline_published = $rollbackPublishedAndBound
        installer_state = $installerState
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    invariants = $sideEffects
    checks = $script:checks
    task_blockers = $script:taskBlockers
    installer_steps = $script:installerSteps
    installer_blockers = $script:installerBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:taskBlockers).Count
        installer_steps = @($script:installerSteps).Count
        installer_blockers = @($script:installerBlockers).Count
        rc7_010_complete = @($script:taskBlockers).Count -eq 0
        next_task = "RC7-011"
    }
}

Write-Json $result $resolvedResultPath

if ($FailOnBlocked -and @($script:taskBlockers).Count -gt 0) {
    exit 1
}

Write-Host "RC7 installer signed consumption projection: $($result.status)"
Write-Host "Task blockers: $(@($script:taskBlockers).Count)"
Write-Host "Installer blockers: $(@($script:installerBlockers).Count)"
Write-Host "Result: $(Get-StablePath $resolvedResultPath)"
