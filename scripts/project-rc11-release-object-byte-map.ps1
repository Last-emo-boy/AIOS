param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-release-object-byte-map",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/real-object-trust-handoff-contract.md",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$DescriptorResultPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json",
    [string]$ObjectChecksumsPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-checksums.json",
    [string]$DescriptorReportPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/descriptor-report.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$Rc10PublicationResultPath = ".workflow/artifacts/rc10-external-object-publication/result.json",
    [string]$Rc10PublicationReportPath = ".workflow/artifacts/rc10-external-object-publication/publication-report.json",
    [string]$Rc10DriftResultPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/result.json",
    [string]$Rc10DriftReconciliationPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/artifact-drift-zero-reconciliation.json",
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

function Test-CredentialFreeUri {
    param([string]$Uri)
    if ([string]::IsNullOrWhiteSpace($Uri)) {
        return [ordered]@{
            credential_free = $true
            classification = "external-https-object-uri-not-published"
            blockers = @("external-https-object-uri-not-published")
        }
    }
    $parsed = $null
    if (-not [Uri]::TryCreate($Uri.Trim(), [UriKind]::Absolute, [ref]$parsed)) {
        return [ordered]@{
            credential_free = $false
            classification = "invalid-uri"
            blockers = @("invalid-object-uri")
        }
    }
    $blockers = @()
    if ($parsed.Scheme -ne "https") { $blockers += "non-https-object-uri" }
    if ($parsed.UserInfo) { $blockers += "credential-bearing-object-uri" }
    if ($parsed.Query) {
        $queryLower = $parsed.Query.ToLowerInvariant()
        if ($queryLower.Contains("token") -or $queryLower.Contains("signature") -or $queryLower.Contains("credential") -or $queryLower.Contains("expires") -or $queryLower.Contains("access_key")) {
            $blockers += "credential-bearing-object-uri"
        }
    }
    return [ordered]@{
        credential_free = ($blockers.Count -eq 0)
        classification = if ($blockers.Count -eq 0) { "external-https-immutable-candidate" } else { "unsafe-object-uri" }
        blockers = @($blockers | Select-Object -Unique)
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedDescriptorResultPath = Resolve-RepoPath $DescriptorResultPath
$resolvedObjectChecksumsPath = Resolve-RepoPath $ObjectChecksumsPath
$resolvedDescriptorReportPath = Resolve-RepoPath $DescriptorReportPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedRc10PublicationResultPath = Resolve-RepoPath $Rc10PublicationResultPath
$resolvedRc10PublicationReportPath = Resolve-RepoPath $Rc10PublicationReportPath
$resolvedRc10DriftResultPath = Resolve-RepoPath $Rc10DriftResultPath
$resolvedRc10DriftReconciliationPath = Resolve-RepoPath $Rc10DriftReconciliationPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$descriptor = Read-Json $resolvedDescriptorPath
$descriptorResult = Read-Json $resolvedDescriptorResultPath
$objectChecksums = Read-Json $resolvedObjectChecksumsPath
$descriptorReport = Read-Json $resolvedDescriptorReportPath
$signatureIngestion = Read-Json $resolvedSignatureIngestionResultPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$rc10PublicationResult = Read-Json $resolvedRc10PublicationResultPath
$rc10PublicationReport = Read-Json $resolvedRc10PublicationReportPath
$rc10DriftResult = Read-Json $resolvedRc10DriftResultPath
$rc10DriftReconciliation = Read-Json $resolvedRc10DriftReconciliationPath

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$descriptor.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$descriptor.source_build_artifact)
$sourceArtifactStablePath = Get-StablePath $sourceArtifactPath
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$objectChecksumsSha256 = Get-FileSha256 $resolvedObjectChecksumsPath
$signatureReceiptSha256 = Get-FileSha256 $resolvedSignatureReceiptPath
$signatureSummarySha256 = Get-FileSha256 $resolvedSignatureSummaryPath
$rc10PublicationResultSha256 = Get-FileSha256 $resolvedRc10PublicationResultPath
$rc10PublicationReportSha256 = Get-FileSha256 $resolvedRc10PublicationReportPath
$rc10DriftResultSha256 = Get-FileSha256 $resolvedRc10DriftResultPath
$rc10DriftReconciliationSha256 = Get-FileSha256 $resolvedRc10DriftReconciliationPath
$uriPolicy = Test-CredentialFreeUri $null
$rc10DriftCount = [int]$rc10DriftResult.reconciliation_surface.drift_count
$descriptorCandidateState = if ($rc10DriftCount -eq 0 -and $rc10PublicationResult.publication_surface.external_object_url_published -eq $true) {
    "current-byte-map-ready-for-external-descriptor-verification"
} else {
    "current-byte-map-candidate-verification-blocked"
}

$sourceBindings = [ordered]@{
    rc11_contract = New-ArtifactRef $resolvedContractPath
    rc8_descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    rc8_descriptor_result = New-ArtifactRef $resolvedDescriptorResultPath $descriptorResult
    rc8_object_checksums = New-ArtifactRef $resolvedObjectChecksumsPath $objectChecksums
    rc8_descriptor_report = New-ArtifactRef $resolvedDescriptorReportPath $descriptorReport
    rc8_signature_ingestion = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestion
    rc8_signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    rc8_signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    rc10_publication_result = New-ArtifactRef $resolvedRc10PublicationResultPath $rc10PublicationResult
    rc10_publication_report = New-ArtifactRef $resolvedRc10PublicationReportPath $rc10PublicationReport
    rc10_drift_result = New-ArtifactRef $resolvedRc10DriftResultPath $rc10DriftResult
    rc10_drift_reconciliation = New-ArtifactRef $resolvedRc10DriftReconciliationPath $rc10DriftReconciliation
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.present" ($contractText.Contains("external object transport into AIOS local verification")) "RC11-010 must consume the RC11 trust handoff contract." $sourceBindings.rc11_contract
Add-Check "descriptor.present" ($descriptor.schema -eq "agentos.payload-object-descriptor.v1" -and $descriptorResult.status -eq "passed") "Current payload descriptor must exist and pass before byte-map projection." ([ordered]@{ descriptor = $sourceBindings.rc8_descriptor; descriptor_result = $sourceBindings.rc8_descriptor_result })
Add-Check "payload.bytes_match_descriptor" ($sourceArtifactSha256 -eq [string]$descriptor.sha256 -and $sourceArtifactSize -eq [int64]$descriptor.size_bytes) "Current payload bytes must match descriptor size and SHA-256." ([ordered]@{ path = $sourceArtifactStablePath; expected_sha256 = $descriptor.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $descriptor.size_bytes; observed_size_bytes = $sourceArtifactSize })
Add-Check "signature.receipt.bound" ($signatureIngestion.status -eq "passed" -and $signatureReceipt.crypto_verified -eq $true -and $signatureReceiptSha256) "Byte map must bind verified public signature receipt evidence." ([ordered]@{ signature_ingestion_status = $signatureIngestion.status; receipt_crypto_verified = $signatureReceipt.crypto_verified; receipt_sha256 = $signatureReceiptSha256 })
Add-Check "rc10.blockers.carried_forward" ($rc10PublicationResult.status -eq "passed" -and $rc10DriftResult.status -eq "passed" -and $rc10DriftCount -ge 0) "RC11 byte map must carry RC10 publication and drift status forward." ([ordered]@{ publication_state = $rc10PublicationResult.publication_surface.state; drift_count = $rc10DriftCount; drift_state = $rc10DriftResult.reconciliation_surface.state })

$byteMap = [ordered]@{
    schema = "agentos.rc11-release-object-byte-map.v1"
    generated_at = $generatedAt
    task = "RC11-010"
    release_id = $releaseId
    status = $descriptorCandidateState
    production_ready_claim = $false
    current_payload = [ordered]@{
        source_path = $sourceArtifactStablePath
        source_artifact_class = "repo-local-current-payload"
        object_id = [string]$descriptor.object_id
        object_kind = [string]$descriptor.kind
        size_bytes = $sourceArtifactSize
        sha256 = $sourceArtifactSha256
        sha512 = $descriptor.sha512
        content_type = [string]$descriptor.content_type
        compression = [string]$descriptor.compression
        range_request_supported = [bool]$descriptor.range_request_supported
        immutable = [bool]$descriptor.immutable
    }
    required_bindings = [ordered]@{
        descriptor_sha256 = $descriptorSha256
        object_checksums_sha256 = $objectChecksumsSha256
        manifest_sha256 = [string]$descriptor.manifest_sha256
        checksums_sha256 = [string]$descriptor.checksums_sha256
        public_signature_target_sha256 = $descriptorSha256
        public_signature_receipt_sha256 = $signatureReceiptSha256
        public_signature_summary_sha256 = $signatureSummarySha256
        signed_metadata_sha256 = [string]$descriptor.signed_metadata_sha256
        revocation_snapshot_sha256 = [string]$descriptor.revocation_snapshot_sha256
        installer_compatibility_sha256 = [string]$descriptor.installer_compatibility_sha256
        rollback_baseline_sha256 = [string]$descriptor.rollback_baseline_sha256
        support_recovery_sha256 = [string]$descriptor.support_recovery_sha256
        rc10_publication_result_sha256 = $rc10PublicationResultSha256
        rc10_publication_report_sha256 = $rc10PublicationReportSha256
        rc10_drift_result_sha256 = $rc10DriftResultSha256
        rc10_drift_reconciliation_sha256 = $rc10DriftReconciliationSha256
    }
    rc10_carry_forward = [ordered]@{
        publication_state = [string]$rc10PublicationResult.publication_surface.state
        external_object_url_published = [bool]$rc10PublicationResult.publication_surface.external_object_url_published
        drift_state = [string]$rc10DriftResult.reconciliation_surface.state
        drift_count = $rc10DriftCount
        drift_zero = [bool]$rc10DriftResult.reconciliation_surface.drift_zero
        installer_quarantine_fetch_allowed = [bool]$rc10DriftResult.reconciliation_surface.installer_quarantine_fetch_allowed
    }
    trust_handoff = [ordered]@{
        external_object_reachability_is_trust = $false
        descriptor_classification_required = $true
        drift_zero_required_before_trust = $true
        quarantine_fetch_required_before_interpretation = $true
        agentcore_planspec_required_before_activation = $true
        security_execution_engine_required_before_activation = $true
        rollback_requires_separate_exact_approval = $true
        support_recovery_binding_required = $true
    }
    blockers = @(
        "external-https-object-uri-not-published",
        "drift-zero-not-proved-in-rc11",
        "installer-quarantine-fetch-not-run",
        "two-target-canary-not-enrolled",
        "exact-approval-not-bound",
        "agentcore-planspec-not-bound",
        "security-execution-effect-envelope-not-bound"
    )
}

$descriptorCandidate = [ordered]@{
    schema = "agentos.payload-object-descriptor.v1"
    release_id = $releaseId
    release_channel = "production-distro-rc11"
    object_id = [string]$descriptor.object_id
    object_kind = [string]$descriptor.kind
    uri = $null
    uri_policy = $uriPolicy.classification
    storage_provider_class = "aios-body-current-byte-map-no-external-object-uri"
    immutable = [bool]$descriptor.immutable
    published_at = $generatedAt
    fresh_until = $null
    size_bytes = $sourceArtifactSize
    sha256 = $sourceArtifactSha256
    sha512 = $descriptor.sha512
    content_type = [string]$descriptor.content_type
    compression = [string]$descriptor.compression
    range_request_supported = [bool]$descriptor.range_request_supported
    source_build_artifact_class = "repo-local-current-payload"
    source_build_artifact = $sourceArtifactStablePath
    source_build_artifact_sha256 = $sourceArtifactSha256
    source_build_artifact_size_bytes = $sourceArtifactSize
    release_provenance_sha256 = [string]$descriptor.release_provenance_sha256
    manifest_sha256 = [string]$descriptor.manifest_sha256
    checksums_sha256 = [string]$descriptor.checksums_sha256
    public_signature_target_sha256 = $descriptorSha256
    public_signature_receipt_sha256 = $signatureReceiptSha256
    revocation_snapshot_sha256 = [string]$descriptor.revocation_snapshot_sha256
    installer_compatibility_sha256 = [string]$descriptor.installer_compatibility_sha256
    rollback_baseline_sha256 = [string]$descriptor.rollback_baseline_sha256
    support_recovery_sha256 = [string]$descriptor.support_recovery_sha256
    declared_current_reconciliation_sha256 = $rc10DriftReconciliationSha256
    byte_map_sha256 = $null
    policy_version = "rc11-real-object-trust-handoff-v1"
    production_ready_claim = $false
    descriptor_state = $descriptorCandidateState
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
}

$byteMapPath = Join-Path $resolvedArtifactDir "release-object-byte-map.json"
$descriptorCandidatePath = Join-Path $resolvedArtifactDir "immutable-descriptor-candidate.json"
$reportPath = Join-Path $resolvedArtifactDir "descriptor-candidate-report.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-010-release-object-byte-map.json"

Write-Json $byteMap $byteMapPath
$descriptorCandidate.byte_map_sha256 = Get-FileSha256 $byteMapPath
Write-Json $descriptorCandidate $descriptorCandidatePath
$descriptorCandidateSha256 = Get-FileSha256 $descriptorCandidatePath

$report = [ordered]@{
    schema = "agentos.rc11-release-object-descriptor-candidate-report.v1"
    generated_at = $generatedAt
    task = "RC11-010"
    release_id = $releaseId
    status = $descriptorCandidateState
    production_ready_claim = $false
    candidate = [ordered]@{
        descriptor_path = Get-StablePath $descriptorCandidatePath
        descriptor_sha256 = $descriptorCandidateSha256
        byte_map_path = Get-StablePath $byteMapPath
        byte_map_sha256 = Get-FileSha256 $byteMapPath
        immutable = [bool]$descriptorCandidate.immutable
        canonical_json = $true
        size_bound = ($descriptorCandidate.size_bytes -eq $sourceArtifactSize)
        digest_bound = ($descriptorCandidate.sha256 -eq $sourceArtifactSha256)
        credential_free = [bool]$uriPolicy.credential_free
        external_https_object_uri_published = $false
    }
    source = $sourceBindings
    blockers = $byteMap.blockers
    side_effects = [ordered]@{
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
}
Write-Json $report $reportPath

Add-Check "byte_map.bindings.complete" ($byteMap.required_bindings.manifest_sha256 -and $byteMap.required_bindings.checksums_sha256 -and $byteMap.required_bindings.public_signature_receipt_sha256 -and $byteMap.required_bindings.revocation_snapshot_sha256 -and $byteMap.required_bindings.installer_compatibility_sha256 -and $byteMap.required_bindings.rollback_baseline_sha256 -and $byteMap.required_bindings.support_recovery_sha256) "Byte map must record manifest, checksum, signature, revocation, compatibility, rollback, and support/recovery bindings." $byteMap.required_bindings
Add-Check "descriptor_candidate.safe" ($descriptorCandidate.immutable -eq $true -and $descriptorCandidate.size_bytes -eq $sourceArtifactSize -and $descriptorCandidate.sha256 -eq $sourceArtifactSha256 -and $uriPolicy.credential_free -eq $true -and $descriptorCandidate.production_ready_claim -eq $false -and $descriptorCandidate.install_allowed -eq $false -and $descriptorCandidate.activation_allowed -eq $false -and $descriptorCandidate.rollback_execution_allowed -eq $false) "Descriptor candidate must be immutable, size-bound, digest-bound, credential-free, and non-authoritative." ([ordered]@{ immutable = $descriptorCandidate.immutable; size_bound = ($descriptorCandidate.size_bytes -eq $sourceArtifactSize); digest_bound = ($descriptorCandidate.sha256 -eq $sourceArtifactSha256); credential_free = $uriPolicy.credential_free })
Add-Check "outputs.side_effects_absent" ($report.side_effects.payload_upload_performed -eq $false -and $report.side_effects.install_performed -eq $false -and $report.side_effects.activation_performed -eq $false -and $report.side_effects.rollback_execution_performed -eq $false -and $report.side_effects.remote_dispatch_enabled -eq $false -and $report.side_effects.production_ring_mutated -eq $false) "RC11-010 must not upload, fetch remotely, install, activate, rollback, dispatch, or mutate production rings." $report.side_effects
Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw $byteMapPath), (Get-Content -Raw $descriptorCandidatePath), (Get-Content -Raw $reportPath))) "RC11-010 generated outputs must not contain private key paths, PEM blocks, auth tokens, or signer internals." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-release-object-byte-map-result.v1"
    generated_at = $generatedAt
    task = "RC11-010"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    byte_map_surface = [ordered]@{
        state = $descriptorCandidateState
        current_payload_size_bytes = $sourceArtifactSize
        current_payload_sha256 = $sourceArtifactSha256
        descriptor_candidate_sha256 = $descriptorCandidateSha256
        byte_map_sha256 = Get-FileSha256 $byteMapPath
        external_https_object_uri_published = $false
        drift_count_carried_forward = $rc10DriftCount
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $byteMap.blockers
    }
    outputs = [ordered]@{
        byte_map = [ordered]@{ path = Get-StablePath $byteMapPath; sha256 = Get-FileSha256 $byteMapPath }
        descriptor_candidate = [ordered]@{ path = Get-StablePath $descriptorCandidatePath; sha256 = Get-FileSha256 $descriptorCandidatePath }
        descriptor_report = [ordered]@{ path = Get-StablePath $reportPath; sha256 = Get-FileSha256 $reportPath }
    }
    source = $sourceBindings
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        frontend_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $byteMap.blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        rc11_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-011"
    }
}
Write-Json $result $resultPath

$taskEvidence = [ordered]@{
    schema = "agentos.rc11-release-object-byte-map-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-010"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $PSCommandPath
        sha256 = Get-FileSha256 $PSCommandPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    byte_map_surface = $result.byte_map_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc11_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-011"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw $resultPath), (Get-Content -Raw $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC11-010 outputs."
}

Write-Host "RC11 release object byte map $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Descriptor candidate: $(Get-StablePath $descriptorCandidatePath)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
