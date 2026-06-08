param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-external-object-publication",
    [string]$ExternalObjectUri = "",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$DescriptorResultPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$HostedPayloadIndexPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-payload-index.json",
    [string]$InstallBootstrapPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/install-bootstrap.json",
    [string]$HostedChannelIndexPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-channel-index.json",
    [string]$MirrorStatusPath = ".workflow/artifacts/rc8-mirror-consistency-refresh/mirror-status.json",
    [string]$ContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/external-object-descriptor-drift-reconciliation-contract.md",
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

function Test-ExternalObjectUri {
    param([string]$Uri)
    $blockers = @()
    $classification = "missing"
    $normalized = $null
    $uriObject = $null

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        $blockers += "external-https-object-uri-not-published"
        return [ordered]@{
            ok = $false
            classification = $classification
            normalized_uri = $null
            blockers = $blockers
        }
    }

    $candidate = $Uri.Trim()
    if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uriObject)) {
        $blockers += "external-object-uri-not-absolute"
        return [ordered]@{
            ok = $false
            classification = "invalid-uri"
            normalized_uri = $candidate
            blockers = $blockers
        }
    }

    $normalized = $uriObject.AbsoluteUri
    if ($uriObject.Scheme -ne "https") {
        $blockers += "external-object-uri-not-https"
    }
    if ($uriObject.UserInfo) {
        $blockers += "external-object-uri-credential-bearing"
    }
    if ($uriObject.Query) {
        $queryLower = $uriObject.Query.ToLowerInvariant()
        if ($queryLower.Contains("token") -or
            $queryLower.Contains("signature") -or
            $queryLower.Contains("credential") -or
            $queryLower.Contains("expires") -or
            $queryLower.Contains("access_key")) {
            $blockers += "external-object-uri-presigned-or-credential-bearing"
        } else {
            $blockers += "external-object-uri-query-not-immutable"
        }
    }
    $hostLower = $uriObject.Host.ToLowerInvariant()
    if ($hostLower -in @("localhost", "127.0.0.1", "::1") -or $hostLower.EndsWith(".local")) {
        $blockers += "external-object-uri-local-host"
    }
    $pathLower = $uriObject.AbsolutePath.ToLowerInvariant()
    if ($pathLower.Contains("/latest") -or $pathLower.Contains("/current") -or $pathLower.Contains("/mutable")) {
        $blockers += "external-object-uri-mutable-path"
    }
    if ($pathLower.Contains("/upload") -or
        $pathLower.Contains("/admin") -or
        $pathLower.Contains("/activate") -or
        $pathLower.Contains("/rollback") -or
        $pathLower.Contains("/dispatch") -or
        $pathLower.Contains("/support/upload")) {
        $blockers += "external-object-uri-authority-bearing"
    }

    if ($blockers.Count -eq 0) {
        $classification = "external-https-immutable-candidate"
    } else {
        $classification = "external-uri-denied"
    }

    return [ordered]@{
        ok = ($blockers.Count -eq 0)
        classification = $classification
        normalized_uri = $normalized
        blockers = $blockers
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedDescriptorResultPath = Resolve-RepoPath $DescriptorResultPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedHostedPayloadIndexPath = Resolve-RepoPath $HostedPayloadIndexPath
$resolvedInstallBootstrapPath = Resolve-RepoPath $InstallBootstrapPath
$resolvedHostedChannelIndexPath = Resolve-RepoPath $HostedChannelIndexPath
$resolvedMirrorStatusPath = Resolve-RepoPath $MirrorStatusPath
$resolvedContractPath = Resolve-RepoPath $ContractPath

$descriptor = Read-Json $resolvedDescriptorPath
$descriptorResult = Read-Json $resolvedDescriptorResultPath
$signatureIngestion = Read-Json $resolvedSignatureIngestionResultPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$hostedPayloadIndex = Read-Json $resolvedHostedPayloadIndexPath
$installBootstrap = Read-Json $resolvedInstallBootstrapPath
$hostedChannelIndex = Read-Json $resolvedHostedChannelIndexPath
$mirrorStatus = Read-Json $resolvedMirrorStatusPath

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$descriptor.release_id
$sourceArtifactPath = [string]$descriptor.source_build_artifact
$resolvedSourceArtifactPath = Resolve-RepoPath $sourceArtifactPath
$sourceArtifactSha256 = Get-FileSha256 $resolvedSourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $resolvedSourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $resolvedSourceArtifactPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$signatureReceiptSha256 = Get-FileSha256 $resolvedSignatureReceiptPath
$signatureSummarySha256 = Get-FileSha256 $resolvedSignatureSummaryPath
$hostedPayloadIndexSha256 = Get-FileSha256 $resolvedHostedPayloadIndexPath
$installBootstrapSha256 = Get-FileSha256 $resolvedInstallBootstrapPath
$hostedChannelIndexSha256 = Get-FileSha256 $resolvedHostedChannelIndexPath
$uriPolicy = Test-ExternalObjectUri $ExternalObjectUri

$knownDriftUnresolved = @($descriptor.payload_blockers + $hostedPayloadIndex.entries[0].payload_blockers + $installBootstrap.blockers + $mirrorStatus.blockers) -contains "declared-current-artifact-drift-unresolved"
$publicationBlockers = @()
foreach ($blocker in @($uriPolicy.blockers)) {
    if ($publicationBlockers -notcontains $blocker) {
        $publicationBlockers += $blocker
    }
}
if ($knownDriftUnresolved -and $publicationBlockers -notcontains "declared-current-artifact-drift-unresolved") {
    $publicationBlockers += "declared-current-artifact-drift-unresolved"
}
if ($signatureReceipt.crypto_verified -ne $true -and $publicationBlockers -notcontains "public-signature-not-crypto-verified") {
    $publicationBlockers += "public-signature-not-crypto-verified"
}
if ($sourceArtifactSha256 -ne [string]$descriptor.sha256 -and $publicationBlockers -notcontains "source-artifact-digest-mismatch") {
    $publicationBlockers += "source-artifact-digest-mismatch"
}
if ($sourceArtifactSize -ne [int64]$descriptor.size_bytes -and $publicationBlockers -notcontains "source-artifact-size-mismatch") {
    $publicationBlockers += "source-artifact-size-mismatch"
}

$downstreamExecutionBlockers = @(
    "installer-quarantine-fetch-not-run",
    "two-node-canary-target-set-not-enrolled",
    "exact-operator-approval-pending",
    "agentcore-planspec-not-bound",
    "security-execution-approval-not-bound",
    "controlled-execution-not-authorized"
)

$publicationAllowed = ($uriPolicy.ok -eq $true -and $publicationBlockers.Count -eq 0)
$externalObjectUrlPublished = $publicationAllowed
$publicationState = if ($publicationAllowed) { "external-object-publication-candidate" } else { "publication-denied" }

$sourceBindings = [ordered]@{
    contract = New-ArtifactRef $resolvedContractPath
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    descriptor_result = New-ArtifactRef $resolvedDescriptorResultPath $descriptorResult
    signature_ingestion_result = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestion
    signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    hosted_payload_index = New-ArtifactRef $resolvedHostedPayloadIndexPath $hostedPayloadIndex
    install_bootstrap = New-ArtifactRef $resolvedInstallBootstrapPath $installBootstrap
    hosted_channel_index = New-ArtifactRef $resolvedHostedChannelIndexPath $hostedChannelIndex
    mirror_status = New-ArtifactRef $resolvedMirrorStatusPath $mirrorStatus
    source_payload_bytes = New-ArtifactRef $resolvedSourceArtifactPath
}

Add-Check "source.descriptor.present" ($descriptor.schema -eq "agentos.payload-object-descriptor.v1" -and $descriptorResult.status -eq "passed") "RC8 payload descriptor must exist and pass before RC9 external object publication." ([ordered]@{ descriptor = $sourceBindings.descriptor; descriptor_result = $sourceBindings.descriptor_result })
Add-Check "source.payload.bytes_match_descriptor" ($sourceArtifactSha256 -eq [string]$descriptor.sha256 -and $sourceArtifactSize -eq [int64]$descriptor.size_bytes) "Current payload bytes must match the descriptor digest and size." ([ordered]@{ path = Get-StablePath $resolvedSourceArtifactPath; expected_sha256 = $descriptor.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $descriptor.size_bytes; observed_size_bytes = $sourceArtifactSize })
Add-Check "source.signature.verified" ($signatureIngestion.status -eq "passed" -and $signatureReceipt.crypto_verified -eq $true) "Public signature receipt must be ingested and crypto verified before publication projection." ([ordered]@{ signature_ingestion_status = $signatureIngestion.status; receipt_crypto_verified = $signatureReceipt.crypto_verified })
Add-Check "source.mirror.metadata_only" ($hostedPayloadIndex.large_payload_bytes_hosted_on_mirror -eq $false -and $installBootstrap.payload_bytes_hosted_on_mirror -eq $false -and $hostedChannelIndex.payload_channel.payload_bytes_hosted_on_mirror -eq $false) "Mirror must remain metadata-only and must not host payload bytes." ([ordered]@{ payload_index_storage_mode = $hostedPayloadIndex.storage_mode; payload_bytes_hosted_on_mirror = $installBootstrap.payload_bytes_hosted_on_mirror })
Add-Check "publication.uri_policy_handled" (($uriPolicy.ok -eq $true -and $publicationAllowed -eq $true) -or ($uriPolicy.ok -eq $false -and $publicationAllowed -eq $false -and $publicationBlockers.Count -gt 0)) "External object URI policy must either accept a stable HTTPS URI or produce denial evidence." ([ordered]@{ classification = $uriPolicy.classification; blockers = $publicationBlockers })
Add-Check "publication.drift_blocks_install" (-not $publicationAllowed -or -not $knownDriftUnresolved) "Unresolved declared/current drift must block external object trust and install authorization." ([ordered]@{ declared_current_artifact_drift_unresolved = $knownDriftUnresolved })

$projectedDescriptor = [ordered]@{
    schema = "agentos.payload-object-descriptor.v1"
    release_id = $releaseId
    object_id = [string]$descriptor.object_id
    kind = [string]$descriptor.kind
    uri = if ($publicationAllowed) { $uriPolicy.normalized_uri } else { $null }
    uri_policy = if ($publicationAllowed) { "external-https-immutable" } else { "missing-external-https-immutable" }
    size_bytes = [int64]$descriptor.size_bytes
    sha256 = [string]$descriptor.sha256
    sha512 = $descriptor.sha512
    content_type = [string]$descriptor.content_type
    compression = [string]$descriptor.compression
    range_request_supported = [bool]$descriptor.range_request_supported
    immutable = [bool]$descriptor.immutable
    published_at = $generatedAt
    expires_at = $null
    storage_provider_class = if ($publicationAllowed) { "external-object-storage-candidate" } else { "external-object-storage-missing" }
    source_build_artifact = $sourceArtifactPath
    source_build_artifact_sha256 = $sourceArtifactSha256
    source_build_artifact_size_bytes = $sourceArtifactSize
    release_provenance_sha256 = [string]$descriptor.release_provenance_sha256
    manifest_sha256 = [string]$descriptor.manifest_sha256
    checksums_sha256 = [string]$descriptor.checksums_sha256
    signed_metadata_sha256 = [string]$descriptor.signed_metadata_sha256
    public_signature_receipt_sha256 = $signatureReceiptSha256
    public_signature_summary_sha256 = $signatureSummarySha256
    revocation_snapshot_sha256 = [string]$descriptor.revocation_snapshot_sha256
    installer_compatibility_sha256 = [string]$descriptor.installer_compatibility_sha256
    rollback_baseline_sha256 = [string]$descriptor.rollback_baseline_sha256
    support_recovery_sha256 = [string]$descriptor.support_recovery_sha256
    declared_current_reconciliation_sha256 = $null
    policy_version = "rc9-external-object-publication-v1"
    production_ready_claim = $false
    descriptor_state = $publicationState
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
}

$candidate = [ordered]@{
    schema = "agentos.rc9-external-object-publication-candidate.v1"
    generated_at = $generatedAt
    task = "RC9-010"
    release_id = $releaseId
    status = $publicationState
    production_ready_claim = $false
    previous_descriptor = [ordered]@{
        path = Get-StablePath $resolvedDescriptorPath
        sha256 = $descriptorSha256
        uri = [string]$descriptor.uri
        uri_policy = "repo-local-immutable-identity"
    }
    external_object = [ordered]@{
        uri = if ($publicationAllowed) { $uriPolicy.normalized_uri } else { $null }
        uri_classification = $uriPolicy.classification
        publication_allowed = $publicationAllowed
        external_object_url_published = $externalObjectUrlPublished
        credential_free = ($publicationAllowed -eq $true)
        immutable = ($publicationAllowed -eq $true)
        size_bound = ($sourceArtifactSize -eq [int64]$descriptor.size_bytes)
        sha256_bound = ($sourceArtifactSha256 -eq [string]$descriptor.sha256)
        manifest_bound = ($null -ne $descriptor.manifest_sha256)
        checksum_set_bound = ($null -ne $descriptor.checksums_sha256)
        public_signature_bound = ($signatureReceipt.crypto_verified -eq $true)
        revocation_bound = ($null -ne $descriptor.revocation_snapshot_sha256)
        compatibility_bound = ($null -ne $descriptor.installer_compatibility_sha256)
        rollback_bound = ($null -ne $descriptor.rollback_baseline_sha256)
        support_recovery_bound = ($null -ne $descriptor.support_recovery_sha256)
    }
    projected_descriptor = $projectedDescriptor
    source_bindings = $sourceBindings
    mirror_publication = [ordered]@{
        domain = [string]$hostedPayloadIndex.domain
        metadata_only = $true
        payload_bytes_hosted_on_mirror = $false
        mirror_publication_allowed = $publicationAllowed
        publish_payload_bytes_to_mirror_allowed = $false
        existing_payload_index_sha256 = $hostedPayloadIndexSha256
        existing_install_bootstrap_sha256 = $installBootstrapSha256
        existing_channel_index_sha256 = $hostedChannelIndexSha256
    }
    blockers = $publicationBlockers
    downstream_execution_blockers = $downstreamExecutionBlockers
    side_effects = [ordered]@{
        payload_bytes_uploaded = $false
        payload_bytes_downloaded = $false
        mirror_metadata_mutated = $false
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
    }
}

$denial = [ordered]@{
    schema = "agentos.rc9-external-object-publication-denial.v1"
    generated_at = $generatedAt
    task = "RC9-010"
    release_id = $releaseId
    status = if ($publicationAllowed) { "not-denied" } else { "publication-denied" }
    production_ready_claim = $false
    denied = (-not $publicationAllowed)
    denial_reasons = $publicationBlockers
    missing_requirements = @(
        if (-not $uriPolicy.ok) { "immutable credential-free external HTTPS object URI" }
        if ($knownDriftUnresolved) { "declared/current artifact reconciliation evidence" }
    )
    authority_denied = @(
        "mirror-signing-authority",
        "mirror-install-authority",
        "object-storage-install-authority",
        "frontend-authority",
        "tui-authority",
        "shell-authority",
        "model-replay-authority",
        "remote-dispatch-authority",
        "support-upload-authority",
        "production-ring-mutation-authority"
    )
    preserved_boundaries = [ordered]@{
        mirror_metadata_only = $true
        signer_separate_from_mirror = $true
        external_object_storage_is_transport_only = $true
        installer_quarantine_required = $true
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc9-installer-handoff.v1"
    generated_at = $generatedAt
    task = "RC9-010"
    release_id = $releaseId
    status = if ($publicationAllowed) { "ready-for-rc9-011-reconciliation" } else { "blocked-before-quarantine" }
    production_ready_claim = $false
    descriptor = [ordered]@{
        path = Get-StablePath $resolvedDescriptorPath
        sha256 = $descriptorSha256
        external_publication_candidate_path = ".workflow/artifacts/rc9-external-object-publication/external-object-publication-candidate.json"
        external_publication_uri = if ($publicationAllowed) { $uriPolicy.normalized_uri } else { $null }
        external_publication_uri_classification = $uriPolicy.classification
    }
    expected_object = [ordered]@{
        object_id = [string]$descriptor.object_id
        size_bytes = [int64]$descriptor.size_bytes
        sha256 = [string]$descriptor.sha256
        manifest_sha256 = [string]$descriptor.manifest_sha256
        checksums_sha256 = [string]$descriptor.checksums_sha256
        public_signature_receipt_sha256 = $signatureReceiptSha256
        public_signature_summary_sha256 = $signatureSummarySha256
        revocation_snapshot_sha256 = [string]$descriptor.revocation_snapshot_sha256
        installer_compatibility_sha256 = [string]$descriptor.installer_compatibility_sha256
        rollback_baseline_sha256 = [string]$descriptor.rollback_baseline_sha256
        support_recovery_sha256 = [string]$descriptor.support_recovery_sha256
    }
    quarantine_policy = [ordered]@{
        quarantine_fetch_allowed = ($publicationAllowed -and -not $knownDriftUnresolved)
        quarantine_root_policy = "installer-owned-temp-quarantine"
        allowed_network_policy = "external-https-only-after-publication-and-reconciliation"
        interpret_before_size_digest_signature_verification = $false
    }
    denied_side_effects = @(
        "install",
        "activation",
        "rollback-execution",
        "boot-metadata-mutation",
        "active-slot-mutation",
        "active-artifact-set-mutation",
        "production-ring-mutation",
        "support-upload",
        "remote-dispatch"
    )
    blockers = @($publicationBlockers + $downstreamExecutionBlockers)
    next_task = "RC9-011"
}

$candidatePath = Join-Path $resolvedArtifactDir "external-object-publication-candidate.json"
$denialPath = Join-Path $resolvedArtifactDir "external-object-publication-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "installer-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $candidate $candidatePath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $candidatePath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-010 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null
Add-Check "outputs.non_ga_side_effects_blocked" ($candidate.production_ready_claim -eq $false -and $candidate.side_effects.install_performed -eq $false -and $candidate.side_effects.activation_performed -eq $false -and $candidate.side_effects.rollback_execution_performed -eq $false -and $handoff.quarantine_policy.interpret_before_size_digest_signature_verification -eq $false) "Publication projection must remain non-GA and must not authorize install, activation, rollback, or payload interpretation." ([ordered]@{ production_ready_claim = $candidate.production_ready_claim; install_performed = $candidate.side_effects.install_performed; activation_performed = $candidate.side_effects.activation_performed; rollback_execution_performed = $candidate.side_effects.rollback_execution_performed })

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc9-external-object-publication-result.v1"
    generated_at = $generatedAt
    task = "RC9-010"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    publication_surface = [ordered]@{
        state = $publicationState
        publication_allowed = $publicationAllowed
        external_object_url_published = $externalObjectUrlPublished
        external_object_uri_classification = $uriPolicy.classification
        payload_bytes_uploaded = $false
        payload_bytes_downloaded = $false
        payload_bytes_hosted_on_mirror = $false
        mirror_metadata_mutated = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $publicationBlockers
        downstream_execution_blockers = $downstreamExecutionBlockers
    }
    outputs = [ordered]@{
        candidate = [ordered]@{
            path = Get-StablePath $candidatePath
            sha256 = Get-FileSha256 $candidatePath
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
    source = $sourceBindings
    invariants = [ordered]@{
        mirror_metadata_only = $true
        mirror_large_payload_storage_used = $false
        signer_separate_from_mirror = $true
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
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = @($publicationBlockers + $downstreamExecutionBlockers)
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        publication_blockers = $publicationBlockers.Count
        publication_denied_as_expected = (-not $publicationAllowed)
        rc9_010_complete = ($failedChecks.Count -eq 0)
        next_task = "RC9-011"
    }
}

Write-Json $result $resultPath

$resultSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath))
if (-not $resultSecretSafe) {
    throw "Sensitive marker detected in RC9-010 result."
}

Write-Host "RC9 external object publication $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Publication state: $publicationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), publication blockers: $($publicationBlockers.Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
