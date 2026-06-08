param(
    [string]$OutputRoot = ".workflow/artifacts/rc8-real-payload-object-descriptor",
    [string]$PayloadPath = "image/out/agentos-initramfs.cpio.gz",
    [string]$PayloadManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$AlphaRootfsManifestPath = "image/out/agentos-alpha-rootfs.manifest.json",
    [string]$ReleaseProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$Rc6PayloadManifestPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-manifest.json",
    [string]$Rc7SignedMetadataPath = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json",
    [string]$Rc7RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$Rc7CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$Rc7RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json"
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

function Get-FileSize {
    param([string]$Path)
    $resolved = Resolve-RepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        return $null
    }
    return (Get-Item -LiteralPath $resolved).Length
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

function New-SourceBinding {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Schema = "",
        [string]$Status = ""
    )
    $resolved = Resolve-RepoPath $Path
    return [ordered]@{
        name = $Name
        path = (Get-RepoRelativePath $Path)
        sha256 = Get-FileSha256 $Path
        size_bytes = Get-FileSize $Path
        present = (Test-Path -LiteralPath $resolved -PathType Leaf)
        schema = $Schema
        status = $Status
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$resolvedOutputRoot = Resolve-RepoPath $OutputRoot
New-Item -ItemType Directory -Force -Path $resolvedOutputRoot | Out-Null

$payloadManifest = Read-JsonFile $PayloadManifestPath
$releaseProvenance = Read-JsonFile $ReleaseProvenancePath
$rc6PayloadManifest = Read-JsonFile $Rc6PayloadManifestPath

$payloadSha256 = Get-FileSha256 $PayloadPath
$payloadSize = Get-FileSize $PayloadPath
$manifestDeclaredPayloadSha256 = if ($payloadManifest) { [string]$payloadManifest.artifact_sha256 } else { $null }
$payloadMatchesManifest = ($null -ne $payloadSha256 -and $payloadSha256 -eq $manifestDeclaredPayloadSha256)

$sourceBindings = [ordered]@{
    payload_bytes = New-SourceBinding "payload_bytes" $PayloadPath "" "present"
    payload_manifest = New-SourceBinding "payload_manifest" $PayloadManifestPath "agentos-initramfs-manifest" "present"
    alpha_rootfs_manifest = New-SourceBinding "alpha_rootfs_manifest" $AlphaRootfsManifestPath "agentos-alpha-rootfs-manifest" "present"
    release_provenance = New-SourceBinding "release_provenance" $ReleaseProvenancePath "agentos.production-candidate.provenance.v1" ([string]$releaseProvenance.promotion.status)
    rc6_payload_manifest = New-SourceBinding "rc6_payload_manifest" $Rc6PayloadManifestPath "agentos.rc6-installable-payload-manifest.v1" ([string]$rc6PayloadManifest.payload_status)
    rc7_signed_metadata = New-SourceBinding "rc7_signed_metadata" $Rc7SignedMetadataPath "agentos.rc7-signed-metadata-projection.v1" "projection"
    rc7_revocation_snapshot = New-SourceBinding "rc7_revocation_snapshot" $Rc7RevocationSnapshotPath "agentos.rc7-revocation-snapshot.v1" "projection"
    rc7_compatibility = New-SourceBinding "rc7_compatibility" $Rc7CompatibilityPath "agentos.rc7-installer-compatibility.v1" "projection"
    rc7_rollback_baseline = New-SourceBinding "rc7_rollback_baseline" $Rc7RollbackBaselinePath "agentos.rc7-rollback-baseline.v1" "projection"
    support_recovery = New-SourceBinding "support_recovery" $SupportRecoveryPath "agentos.rc5-hosted-support-recovery-index.v1" "projection"
}

$driftedComponents = @()
if ($rc6PayloadManifest -and $rc6PayloadManifest.drift_policy -and $rc6PayloadManifest.drift_policy.drifted_components) {
    $driftedComponents = @($rc6PayloadManifest.drift_policy.drifted_components)
}

$payloadBlockers = @()
if (-not $sourceBindings.payload_bytes.present) { $payloadBlockers += "payload-bytes-missing" }
if (-not $sourceBindings.payload_manifest.present) { $payloadBlockers += "payload-manifest-missing" }
if (-not $payloadMatchesManifest) { $payloadBlockers += "payload-byte-hash-does-not-match-manifest" }
$payloadBlockers += "external-https-object-uri-not-published"
$payloadBlockers += "public-signature-artifact-not-ingested"
$payloadBlockers += "installer-vm-smoke-not-run"
if ($driftedComponents.Count -gt 0) { $payloadBlockers += "declared-current-artifact-drift-unresolved" }

$releaseId = "production-distro-rc8-current-artifacts"
$objectId = if ($payloadSha256) { "sha256:$payloadSha256" } else { "missing" }
$candidateUri = if ($payloadSha256) { "urn:sha256:$payloadSha256" } else { $null }

$descriptor = [ordered]@{
    schema = "agentos.payload-object-descriptor.v1"
    release_id = $releaseId
    object_id = $objectId
    kind = "update-bundle"
    uri = $candidateUri
    size_bytes = $payloadSize
    sha256 = $payloadSha256
    sha512 = $null
    content_type = "application/gzip"
    compression = "gzip"
    range_request_supported = $false
    immutable = $true
    published_at = "2026-06-08T18:35:00+08:00"
    expires_at = $null
    storage_provider_class = "repo-local-evidence-pending-external-object-store"
    source_build_artifact = (Get-RepoRelativePath $PayloadPath)
    source_build_artifact_sha256 = $payloadSha256
    release_provenance_sha256 = $sourceBindings.release_provenance.sha256
    manifest_sha256 = $sourceBindings.payload_manifest.sha256
    checksums_sha256 = $sourceBindings.rc6_payload_manifest.sha256
    signed_metadata_sha256 = $sourceBindings.rc7_signed_metadata.sha256
    revocation_snapshot_sha256 = $sourceBindings.rc7_revocation_snapshot.sha256
    installer_compatibility_sha256 = $sourceBindings.rc7_compatibility.sha256
    rollback_baseline_sha256 = $sourceBindings.rc7_rollback_baseline.sha256
    support_recovery_sha256 = $sourceBindings.support_recovery.sha256
    policy_version = "rc8-object-descriptor-v1"
    production_ready_claim = $false
    descriptor_state = "candidate-verification-blocked"
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    payload_blockers = $payloadBlockers
}

$checks = @()
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

Add-Check "payload.bytes.present" $sourceBindings.payload_bytes.present "Payload byte file must exist before descriptor projection." $sourceBindings.payload_bytes
Add-Check "payload.manifest.present" $sourceBindings.payload_manifest.present "Payload manifest must exist before descriptor projection." $sourceBindings.payload_manifest
Add-Check "payload.hash.matches_manifest" $payloadMatchesManifest "Payload byte digest must match the local build manifest." ([ordered]@{ expected = $manifestDeclaredPayloadSha256; observed = $payloadSha256 })
Add-Check "descriptor.schema" ($descriptor.schema -eq "agentos.payload-object-descriptor.v1") "Descriptor schema must match RC8 contract." $descriptor.schema
Add-Check "descriptor.non_ga" ($descriptor.production_ready_claim -eq $false -and $descriptor.install_allowed -eq $false -and $descriptor.activation_allowed -eq $false) "Descriptor projection must remain non-GA and install-blocked." ([ordered]@{ production_ready_claim = $descriptor.production_ready_claim; install_allowed = $descriptor.install_allowed; activation_allowed = $descriptor.activation_allowed })
Add-Check "descriptor.uri.not_https_publication" ($descriptor.uri -like "urn:sha256:*") "RC8-010 records repo-local immutable object identity and keeps external HTTPS publication blocked." $descriptor.uri "informational"
Add-Check "descriptor.source_bindings.present" (@($sourceBindings.GetEnumerator() | Where-Object { -not $_.Value.present }).Count -eq 0) "All descriptor source bindings must exist." $sourceBindings
Add-Check "descriptor.secret_safe" (Test-SecretSafeText (($descriptor | ConvertTo-Json -Depth 20))) "Descriptor must not contain private key blocks or token markers." $null
Add-Check "payload.blockers.expected" ($payloadBlockers.Count -ge 3) "Descriptor must record remaining blockers instead of authorizing install." $payloadBlockers

$descriptorPath = Join-Path $OutputRoot "payload-object-descriptor.json"
$reportPath = Join-Path $OutputRoot "descriptor-report.json"
$checksumsPath = Join-Path $OutputRoot "payload-object-checksums.json"
$resultPath = Join-Path $OutputRoot "result.json"

Write-JsonFile $descriptorPath $descriptor

$checksums = [ordered]@{
    schema = "agentos.rc8-payload-object-checksums.v1"
    generated_at = "2026-06-08T18:35:00+08:00"
    release_id = $releaseId
    object_id = $objectId
    payload_path = (Get-RepoRelativePath $PayloadPath)
    size_bytes = $payloadSize
    sha256 = $payloadSha256
    manifest_declared_sha256 = $manifestDeclaredPayloadSha256
    hash_matches_manifest = $payloadMatchesManifest
}
Write-JsonFile $checksumsPath $checksums

$report = [ordered]@{
    schema = "agentos.rc8-real-payload-object-descriptor-report.v1"
    generated_at = "2026-06-08T18:35:00+08:00"
    release_id = $releaseId
    descriptor_path = (Get-RepoRelativePath $descriptorPath)
    descriptor_sha256 = Get-FileSha256 $descriptorPath
    payload_path = (Get-RepoRelativePath $PayloadPath)
    payload_sha256 = $payloadSha256
    payload_size_bytes = $payloadSize
    payload_matches_manifest = $payloadMatchesManifest
    source_bindings = $sourceBindings
    drifted_components = $driftedComponents
    payload_blockers = $payloadBlockers
    descriptor_state = "candidate-verification-blocked"
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
}
Write-JsonFile $reportPath $report

$failedBlocking = @($checks | Where-Object { $_.severity -eq "blocking" -and $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc8-real-payload-object-descriptor-result.v1"
    generated_at = "2026-06-08T18:35:00+08:00"
    task = "RC8-010"
    status = if ($failedBlocking.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    outputs = [ordered]@{
        descriptor = [ordered]@{
            path = (Get-RepoRelativePath $descriptorPath)
            sha256 = Get-FileSha256 $descriptorPath
        }
        checksums = [ordered]@{
            path = (Get-RepoRelativePath $checksumsPath)
            sha256 = Get-FileSha256 $checksumsPath
        }
        report = [ordered]@{
            path = (Get-RepoRelativePath $reportPath)
            sha256 = Get-FileSha256 $reportPath
        }
    }
    payload_surface = [ordered]@{
        descriptor_state = "candidate-verification-blocked"
        object_id = $objectId
        payload_size_bytes = $payloadSize
        payload_sha256 = $payloadSha256
        external_https_object_uri_published = $false
        public_signature_artifact_ingested = $false
        installer_vm_smoke_run = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        payload_blockers = $payloadBlockers
    }
    invariants = [ordered]@{
        mirror_metadata_only = $true
        mirror_large_payload_storage_used = $false
        descriptor_published_to_mirror = $false
        payload_bytes_uploaded = $false
        payload_bytes_downloaded = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
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
        rc8_010_complete = ($failedBlocking.Count -eq 0)
        next_task = "RC8-011"
    }
}
Write-JsonFile $resultPath $result

if ($failedBlocking.Count -gt 0) {
    Write-Error "RC8 real payload object descriptor projection failed: $($failedBlocking.Count) blocking checks"
}

Write-Host "RC8 real payload object descriptor $($result.status): $(Get-RepoRelativePath $resultPath)"
