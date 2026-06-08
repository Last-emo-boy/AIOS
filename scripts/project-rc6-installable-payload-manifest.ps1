param(
    [string]$ArtifactDir = ".workflow/artifacts/rc6-installable-payload-manifest",
    [string]$ResultPath = "",
    [string]$ProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$ReleaseChannelMetadataPath = ".workflow/artifacts/release/release-channel-metadata.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc1-installable-media/installable-media-manifest.json",
    [string]$InstallableMediaResultPath = ".workflow/artifacts/rc1-installable-media/result.json",
    [string]$Rc5FinalAuditPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/FINAL-AUDIT-20260608-production-distro-rc5.json",
    [string]$Rc6ContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/installable-signed-payload-channel-contract.md",
    [string]$Rc6BoundaryPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/bootstrap-installer-consumption-boundary.md",
    [string]$Rc6ThreatModelPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/tls-storage-signed-payload-threat-model.md",
    [string]$Rc6MirrorPortalResultPath = ".workflow/artifacts/rc6-mirror-portal/result.json",
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

function Resolve-ArtifactPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    $repoCandidate = Join-Path $script:repoRoot $Path
    if (Test-Path -LiteralPath $repoCandidate -PathType Leaf) {
        return [IO.Path]::GetFullPath($repoCandidate)
    }
    $releaseCandidate = Join-Path $script:releaseArtifactRoot $Path
    if (Test-Path -LiteralPath $releaseCandidate -PathType Leaf) {
        return [IO.Path]::GetFullPath($releaseCandidate)
    }
    return [IO.Path]::GetFullPath($repoCandidate)
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
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.Contains($marker, [StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }
    return $true
}

function New-SourceBinding {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Schema = "",
        [string]$Status = ""
    )
    $resolved = Resolve-RepoPath $Path
    return [ordered]@{
        name = $Name
        path = Get-StablePath $resolved
        sha256 = Get-FileSha256 $resolved
        present = Test-Path -LiteralPath $resolved -PathType Leaf
        schema = $Schema
        status = $Status
    }
}

function New-MediaComponent {
    param([Parameter(Mandatory = $true)][string]$Name)
    $artifact = $script:mediaManifest.artifacts.$Name
    if ($null -eq $artifact) {
        return [ordered]@{
            id = $Name
            path = $null
            declared_sha256 = $null
            observed_sha256 = $null
            present = $false
            hash_matches_declared = $false
        }
    }
    $resolved = Resolve-ArtifactPath $artifact.path
    $observed = Get-FileSha256 $resolved
    $declared = $artifact.sha256
    return [ordered]@{
        id = $Name
        path = Get-StablePath $resolved
        declared_sha256 = $declared
        observed_sha256 = $observed
        present = Test-Path -LiteralPath $resolved -PathType Leaf
        hash_matches_declared = (Has-Value $declared) -and (Has-Value $observed) -and ($declared -eq $observed)
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

$resolvedProvenancePath = Resolve-RepoPath $ProvenancePath
$script:releaseArtifactRoot = Split-Path -Parent $resolvedProvenancePath
$resolvedReleaseChannelPath = Resolve-RepoPath $ReleaseChannelMetadataPath
$resolvedMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedMediaResultPath = Resolve-RepoPath $InstallableMediaResultPath
$resolvedRc5FinalAuditPath = Resolve-RepoPath $Rc5FinalAuditPath
$resolvedRc6ContractPath = Resolve-RepoPath $Rc6ContractPath
$resolvedRc6BoundaryPath = Resolve-RepoPath $Rc6BoundaryPath
$resolvedRc6ThreatModelPath = Resolve-RepoPath $Rc6ThreatModelPath
$resolvedRc6MirrorPortalResultPath = Resolve-RepoPath $Rc6MirrorPortalResultPath

$generatedAt = (Get-Date).ToString("o")
$releaseId = "production-distro-rc6-current-artifacts"
$payloadBasePath = "/payloads/aios/$releaseId"

$provenance = Read-Json $resolvedProvenancePath
$releaseChannel = Read-Json $resolvedReleaseChannelPath
$script:mediaManifest = Read-Json $resolvedMediaManifestPath
$mediaResult = Read-Json $resolvedMediaResultPath
$rc5FinalAudit = Read-Json $resolvedRc5FinalAuditPath
$rc6PortalResult = Read-Json $resolvedRc6MirrorPortalResultPath

Add-Check "source.provenance.schema" ($provenance.schema -eq "agentos.production-candidate.provenance.v1") "Release provenance schema must be production candidate." $provenance.schema
Add-Check "source.provenance.promotable" ($provenance.promotion.status -eq "promotable" -and @($provenance.promotion.blockers).Count -eq 0) "Release provenance must be promotable with zero blockers." $provenance.promotion
Add-Check "source.release_channel.schema" ($releaseChannel.schema -eq "agentos.release-channel-metadata.v1" -and $releaseChannel.production_ready_claim -eq $false) "Release channel metadata must be non-GA and schema-bound." ([ordered]@{ schema = $releaseChannel.schema; production_ready_claim = $releaseChannel.production_ready_claim })
Add-Check "source.media_manifest.schema" ($script:mediaManifest.schema -eq "agentos.installable-media-manifest.v1" -and $script:mediaManifest.status -eq "passed") "RC1 installable media manifest must be passed." ([ordered]@{ schema = $script:mediaManifest.schema; status = $script:mediaManifest.status })
Add-Check "source.media_result.passed" ($mediaResult.status -eq "passed") "RC1 installable media result must be passed." $mediaResult.status
Add-Check "source.rc5_final_audit.pass" ($rc5FinalAudit.verdict -eq "PASS") "RC5 final audit must pass before RC6 payload projection." $rc5FinalAudit.verdict
Add-Check "source.rc6_portal.passed" ($rc6PortalResult.status -eq "passed" -and $rc6PortalResult.summary.blockers -eq 0) "RC6 mirror portal must be passed before payload manifest projection." $rc6PortalResult.summary

$sourceBindings = [ordered]@{
    provenance = New-SourceBinding -Name "release_provenance" -Path $ProvenancePath -Schema $provenance.schema -Status $provenance.promotion.status
    release_channel_metadata = New-SourceBinding -Name "release_channel_metadata" -Path $ReleaseChannelMetadataPath -Schema $releaseChannel.schema -Status $releaseChannel.promotion_gate.status
    installable_media_manifest = New-SourceBinding -Name "rc1_installable_media_manifest" -Path $InstallableMediaManifestPath -Schema $script:mediaManifest.schema -Status $script:mediaManifest.status
    installable_media_result = New-SourceBinding -Name "rc1_installable_media_result" -Path $InstallableMediaResultPath -Schema $mediaResult.schema -Status $mediaResult.status
    rc5_final_audit = New-SourceBinding -Name "rc5_final_audit" -Path $Rc5FinalAuditPath -Schema $rc5FinalAudit.schema -Status $rc5FinalAudit.verdict
    rc6_contract = New-SourceBinding -Name "rc6_payload_channel_contract" -Path $Rc6ContractPath
    rc6_boundary = New-SourceBinding -Name "rc6_bootstrap_installer_boundary" -Path $Rc6BoundaryPath
    rc6_threat_model = New-SourceBinding -Name "rc6_tls_storage_signed_payload_threat_model" -Path $Rc6ThreatModelPath
    rc6_mirror_portal = New-SourceBinding -Name "rc6_mirror_portal_result" -Path $Rc6MirrorPortalResultPath -Schema $rc6PortalResult.schema -Status $rc6PortalResult.status
}

foreach ($binding in @($sourceBindings.Values)) {
    Add-Check "source_binding.$($binding.name).present" ($binding.present -and (Has-Value $binding.sha256)) "Source binding must be present and hash-bound." $binding
}

$componentNames = @(
    "alpha_rootfs_manifest",
    "rootfs_runtime_manifest",
    "update_metadata",
    "release_channel_metadata",
    "sbom",
    "dependency_inventory",
    "qemu_runtime_smoke",
    "production_incident_runbook_replay"
)
$components = @()
foreach ($name in $componentNames) {
    $component = New-MediaComponent -Name $name
    $components += $component
    Add-Check "component.$name.present" $component.present "Payload component must resolve to a local source artifact." $component
    Add-Check "component.$name.observed_hash" (Has-Value $component.observed_sha256) "Payload component must have an observed hash for the current artifact projection." $component
    Add-Check "component.$name.declared_hash_recorded" (Has-Value $component.declared_sha256) "Payload component must retain the installable media declared hash for drift evidence." $component
}

$driftedComponents = @($components | Where-Object { $_.present -and (Has-Value $_.declared_sha256) -and (Has-Value $_.observed_sha256) -and -not $_.hash_matches_declared })

$payloadManifest = [ordered]@{
    schema = "agentos.rc6-installable-payload-manifest.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    status = "metadata-projected"
    payload_status = "verification-blocked"
    production_ready_claim = $false
    channel = "production-candidate-rc6"
    source_bindings = $sourceBindings
    media_id = $script:mediaManifest.media_id
    payload_components = @($components)
    storage_policy = [ordered]@{
        mirror_storage_mode = "metadata-only"
        large_payload_storage_enabled = $false
        large_payload_url = $null
        large_payload_sha256 = $null
        large_payload_size_bytes = $null
        large_payload_deferred_until_policy_upgrade = $true
    }
    drift_policy = [ordered]@{
        current_artifact_projection = $true
        installable_media_declared_hash_drift_count = @($driftedComponents).Count
        drifted_components = @($driftedComponents | ForEach-Object { $_.id })
        drift_blocks_install = $true
    }
    signature_policy = [ordered]@{
        signature_required_before_install = $true
        signature_available = $false
        signed_metadata_reference = $null
        revocation_snapshot_required = $true
        placeholder_is_authority = $false
    }
    install_policy = [ordered]@{
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        current_state = "verification-blocked"
        allowed_rc6_states = @("metadata-unavailable", "metadata-candidate", "verification-blocked", "install-preflight-ready")
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
        "tui-authority",
        "shell-authority",
        "model-replay-authority"
    )
}
$payloadManifestText = Get-JsonText $payloadManifest
$payloadManifestHash = Get-StringSha256 $payloadManifestText

$payloadChecksums = [ordered]@{
    schema = "agentos.rc6-installable-payload-checksums.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    production_ready_claim = $false
    payload_manifest_sha256 = $payloadManifestHash
    component_hashes = @($components | ForEach-Object {
        [ordered]@{
            id = $_.id
            path = $_.path
            sha256 = $_.observed_sha256
            declared_sha256 = $_.declared_sha256
            hash_matches_declared = $_.hash_matches_declared
        }
    })
    large_payload_hashes_deferred = $true
    install_allowed = $false
}
$payloadChecksumsText = Get-JsonText $payloadChecksums
$payloadChecksumsHash = Get-StringSha256 $payloadChecksumsText

$payloadSignatures = [ordered]@{
    schema = "agentos.rc6-installable-payload-signatures.v1"
    generated_at = $generatedAt
    release_id = $releaseId
    status = "signature-required-before-install"
    production_ready_claim = $false
    signature_available = $false
    install_allowed = $false
    activation_allowed = $false
    signing_authority_on_mirror = $false
    required_signature_bindings = @(
        "release-id",
        "payload-manifest-sha256",
        "payload-checksums-sha256",
        "revocation-snapshot-sha256",
        "policy-version",
        "expiry"
    )
    blocking_reason = "RC6-010 projects current artifacts only; no public detached payload signature is published in this task."
}
$payloadSignaturesText = Get-JsonText $payloadSignatures
$payloadSignaturesHash = Get-StringSha256 $payloadSignaturesText

$payloadIndex = [ordered]@{
    schema = "agentos.rc6-installable-payload-index-projection.v1"
    generated_at = $generatedAt
    status = "metadata-projected"
    production_ready_claim = $false
    channel = "production-candidate-rc6"
    storage_mode = "metadata-only"
    entries = @(
        [ordered]@{
            id = $releaseId
            release_id = $releaseId
            status = "verification-blocked"
            manifest_path = "$payloadBasePath/manifest.json"
            checksums_path = "$payloadBasePath/checksums.json"
            signatures_path = "$payloadBasePath/signatures.json"
            manifest_sha256 = $payloadManifestHash
            checksums_sha256 = $payloadChecksumsHash
            signatures_sha256 = $payloadSignaturesHash
            install_allowed = $false
            activation_allowed = $false
            rollback_execution_allowed = $false
            large_payload_deferred = $true
        }
    )
}
$payloadIndexText = Get-JsonText $payloadIndex
$payloadIndexHash = Get-StringSha256 $payloadIndexText

$outputManifestPath = Join-Path $resolvedArtifactDir "payload-manifest.json"
$outputChecksumsPath = Join-Path $resolvedArtifactDir "payload-checksums.json"
$outputSignaturesPath = Join-Path $resolvedArtifactDir "payload-signatures.json"
$outputIndexPath = Join-Path $resolvedArtifactDir "payload-index.json"

Write-Json -Value $payloadManifest -Path $outputManifestPath
Write-Json -Value $payloadChecksums -Path $outputChecksumsPath
Write-Json -Value $payloadSignatures -Path $outputSignaturesPath
Write-Json -Value $payloadIndex -Path $outputIndexPath

$outputTexts = @(
    (Get-Content -Raw -LiteralPath $outputManifestPath),
    (Get-Content -Raw -LiteralPath $outputChecksumsPath),
    (Get-Content -Raw -LiteralPath $outputSignaturesPath),
    (Get-Content -Raw -LiteralPath $outputIndexPath)
)

Add-Check "payload_manifest.schema" ($payloadManifest.schema -eq "agentos.rc6-installable-payload-manifest.v1") "Payload manifest schema must be exact." $payloadManifest.schema
Add-Check "payload_manifest.verification_blocked" ($payloadManifest.payload_status -eq "verification-blocked" -and $payloadManifest.install_policy.install_allowed -eq $false) "Payload manifest must remain verification-blocked and not installable." $payloadManifest.install_policy
Add-Check "payload_manifest.storage_deferred" ($payloadManifest.storage_policy.large_payload_storage_enabled -eq $false -and $payloadManifest.storage_policy.large_payload_deferred_until_policy_upgrade -eq $true) "Large payload storage must remain deferred." $payloadManifest.storage_policy
Add-Check "payload_signatures.required" ($payloadSignatures.signature_available -eq $false -and $payloadSignatures.signing_authority_on_mirror -eq $false) "Signature metadata must require a future public signature and grant no mirror signing authority." $payloadSignatures.status
Add-Check "payload_index.hash_bound" ($payloadIndex.entries[0].manifest_sha256 -eq $payloadManifestHash -and $payloadIndex.entries[0].checksums_sha256 -eq $payloadChecksumsHash -and $payloadIndex.entries[0].signatures_sha256 -eq $payloadSignaturesHash) "Payload index must bind manifest, checksums, and signatures hashes." $payloadIndex.entries[0]
Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values $outputTexts) "RC6 payload projection outputs must not contain private key or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-installable-payload-manifest-result.v1"
    generated_at = $generatedAt
    task = "RC6-010"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    release_id = $releaseId
    outputs = [ordered]@{
        payload_manifest = [ordered]@{ path = Get-StablePath $outputManifestPath; sha256 = Get-FileSha256 $outputManifestPath; content_sha256 = $payloadManifestHash }
        payload_checksums = [ordered]@{ path = Get-StablePath $outputChecksumsPath; sha256 = Get-FileSha256 $outputChecksumsPath; content_sha256 = $payloadChecksumsHash }
        payload_signatures = [ordered]@{ path = Get-StablePath $outputSignaturesPath; sha256 = Get-FileSha256 $outputSignaturesPath; content_sha256 = $payloadSignaturesHash }
        payload_index = [ordered]@{ path = Get-StablePath $outputIndexPath; sha256 = Get-FileSha256 $outputIndexPath; content_sha256 = $payloadIndexHash }
    }
    source_bindings = $sourceBindings
    component_count = @($components).Count
    payload_surface = [ordered]@{
        base_path = $payloadBasePath
        status = "verification-blocked"
        storage_mode = "metadata-only"
        large_payload_deferred = $true
        signature_available = $false
        installable_media_declared_hash_drift_count = @($driftedComponents).Count
        install_allowed = $false
        activation_allowed = $false
    }
    invariants = [ordered]@{
        metadata_projection_only = $true
        large_payload_storage_enabled = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        signature_available = $false
        install_allowed = $false
        activation_allowed = $false
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
        drifted_components = @($driftedComponents).Count
        rc6_010_complete = $passed
        next_task = "RC6-011"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC6 installable payload manifest $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
