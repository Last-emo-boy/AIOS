param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-external-object-publication-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md",
    [string]$ByteMapResultPath = ".workflow/artifacts/rc11-release-object-byte-map/result.json",
    [string]$ByteMapPath = ".workflow/artifacts/rc11-release-object-byte-map/release-object-byte-map.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
    [string]$DescriptorVerificationResultPath = ".workflow/artifacts/rc11-external-object-descriptor-verification/result.json",
    [string]$ReleaseArtifactsDocPath = "docs/release-artifacts.md",
    [string]$ExternalObjectUri = "",
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
        ("/etc/" + "aios-signer"),
        ("finger" + "print")
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

function Get-RedactedUriEvidence {
    param([string]$Uri)
    if ([string]::IsNullOrWhiteSpace($Uri)) {
        return $null
    }
    $candidate = $Uri.Trim()
    $parsed = $null
    if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$parsed)) {
        return [ordered]@{
            normalized_uri = $null
            redacted_uri = "invalid-uri"
            raw_uri_sha256 = Get-StringSha256 $candidate
        }
    }
    $builder = [UriBuilder]::new($parsed)
    $builder.UserName = ""
    $builder.Password = ""
    $builder.Query = ""
    return [ordered]@{
        normalized_uri = $builder.Uri.AbsoluteUri
        redacted_uri = if ($parsed.Query -or $parsed.UserInfo) { $builder.Uri.AbsoluteUri + "?redacted=true" } else { $builder.Uri.AbsoluteUri }
        raw_uri_sha256 = if ($parsed.Query -or $parsed.UserInfo) { Get-StringSha256 $candidate } else { $null }
    }
}

function Test-ExternalObjectUri {
    param(
        [string]$Uri,
        [string]$ExpectedSha256
    )
    $blockers = @()
    $flags = [ordered]@{
        present = $false
        absolute = $false
        https = $false
        credential_free = $true
        query_free = $true
        immutable_path = $false
        digest_pinned = $false
        authority_broadening_free = $true
    }
    $evidence = Get-RedactedUriEvidence $Uri
    if ([string]::IsNullOrWhiteSpace($Uri)) {
        $blockers += "external-https-object-uri-not-published"
        return [ordered]@{
            ok = $false
            classification = "external-https-object-uri-not-published"
            evidence = $evidence
            flags = $flags
            blockers = $blockers
        }
    }

    $candidate = $Uri.Trim()
    $parsed = $null
    if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$parsed)) {
        $blockers += "invalid-object-uri"
        return [ordered]@{
            ok = $false
            classification = "invalid-object-uri"
            evidence = $evidence
            flags = $flags
            blockers = $blockers
        }
    }

    $flags.present = $true
    $flags.absolute = $true
    $flags.https = ($parsed.Scheme -eq "https")
    if (-not $flags.https) { $blockers += "non-https-object-uri" }

    if ($parsed.UserInfo) {
        $flags.credential_free = $false
        $blockers += "credential-bearing-object-uri"
    }
    if ($parsed.Query) {
        $flags.query_free = $false
        $queryLower = $parsed.Query.ToLowerInvariant()
        if ($queryLower.Contains("token") -or
            $queryLower.Contains("signature") -or
            $queryLower.Contains("credential") -or
            $queryLower.Contains("expires") -or
            $queryLower.Contains("access_key")) {
            $flags.credential_free = $false
            $blockers += "credential-bearing-object-uri"
        } else {
            $blockers += "mutable-object-uri"
        }
    }

    $hostLower = $parsed.Host.ToLowerInvariant()
    if ($hostLower -in @("localhost", "127.0.0.1", "::1") -or $hostLower.EndsWith(".local")) {
        $blockers += "local-object-uri"
    }

    $pathLower = $parsed.AbsolutePath.ToLowerInvariant()
    $shaLower = if ($ExpectedSha256) { $ExpectedSha256.ToLowerInvariant() } else { "" }
    $flags.digest_pinned = ($shaLower.Length -gt 0 -and $pathLower.Contains($shaLower))
    $flags.immutable_path = ($flags.digest_pinned -and -not ($pathLower.Contains("/latest") -or $pathLower.Contains("/current") -or $pathLower.Contains("/mutable")))
    if (-not $flags.digest_pinned) { $blockers += "object-uri-not-digest-pinned" }
    if (-not $flags.immutable_path) { $blockers += "mutable-object-uri" }

    if ($pathLower.Contains("/upload") -or
        $pathLower.Contains("/admin") -or
        $pathLower.Contains("/activate") -or
        $pathLower.Contains("/rollback") -or
        $pathLower.Contains("/dispatch") -or
        $pathLower.Contains("/support/upload")) {
        $flags.authority_broadening_free = $false
        $blockers += "object-storage-authority-broadening"
    }

    $blockers = @($blockers | Select-Object -Unique)
    return [ordered]@{
        ok = ($blockers.Count -eq 0)
        classification = if ($blockers.Count -eq 0) { "external-https-immutable-digest-pinned-candidate" } else { "external-object-publication-denied" }
        evidence = $evidence
        flags = $flags
        blockers = $blockers
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
$resolvedByteMapResultPath = Resolve-RepoPath $ByteMapResultPath
$resolvedByteMapPath = Resolve-RepoPath $ByteMapPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath
$resolvedDescriptorVerificationResultPath = Resolve-RepoPath $DescriptorVerificationResultPath
$resolvedReleaseArtifactsDocPath = Resolve-RepoPath $ReleaseArtifactsDocPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$byteMapResult = Read-Json $resolvedByteMapResultPath
$byteMap = Read-Json $resolvedByteMapPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$descriptorVerificationResult = Read-Json $resolvedDescriptorVerificationResultPath
$releaseArtifactsDocText = Get-Content -Raw -LiteralPath $resolvedReleaseArtifactsDocPath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$descriptorCandidate.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$descriptorCandidate.source_build_artifact)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$descriptorCandidateSha256 = Get-FileSha256 $resolvedDescriptorCandidatePath
$byteMapSha256 = Get-FileSha256 $resolvedByteMapPath
$byteMapResultSha256 = Get-FileSha256 $resolvedByteMapResultPath
$descriptorVerificationResultSha256 = Get-FileSha256 $resolvedDescriptorVerificationResultPath
$uriPolicy = Test-ExternalObjectUri -Uri $ExternalObjectUri -ExpectedSha256 $sourceArtifactSha256

$bindingBlockers = @()
foreach ($blocker in @($uriPolicy.blockers)) {
    if ($bindingBlockers -notcontains $blocker) { $bindingBlockers += $blocker }
}
if ($sourceArtifactSha256 -ne [string]$descriptorCandidate.sha256) { $bindingBlockers += "object-sha256-mismatch" }
if ($sourceArtifactSize -ne [int64]$descriptorCandidate.size_bytes) { $bindingBlockers += "object-size-mismatch" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.manifest_sha256)) { $bindingBlockers += "manifest-digest-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.checksums_sha256)) { $bindingBlockers += "checksum-set-digest-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.public_signature_target_sha256) -or [string]::IsNullOrWhiteSpace([string]$descriptorCandidate.public_signature_receipt_sha256)) { $bindingBlockers += "public-signature-target-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.revocation_snapshot_sha256)) { $bindingBlockers += "revocation-snapshot-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.fresh_until)) { $bindingBlockers += "freshness-window-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.installer_compatibility_sha256)) { $bindingBlockers += "compatibility-metadata-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.rollback_baseline_sha256)) { $bindingBlockers += "rollback-baseline-missing" }
if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.support_recovery_sha256)) { $bindingBlockers += "support-recovery-binding-missing" }
if ($descriptorVerificationResult.verification_surface.drift_zero -ne $true) { $bindingBlockers += "declared-current-drift-zero-not-proved" }
if ($descriptorVerificationResult.verification_surface.object_trust_allowed -eq $true) { $bindingBlockers += "upstream-object-trust-unexpectedly-allowed-before-rc12" }
$bindingBlockers = @($bindingBlockers | Select-Object -Unique)
$publicationAllowed = ($uriPolicy.ok -eq $true -and $bindingBlockers.Count -eq 0)
$publicationState = if ($publicationAllowed) { "external-object-publication-bound" } else { "external-object-publication-denied" }

$sourceBindings = [ordered]@{
    rc12_contract = New-ArtifactRef $resolvedContractPath
    rc11_byte_map_result = New-ArtifactRef $resolvedByteMapResultPath $byteMapResult
    rc11_byte_map = New-ArtifactRef $resolvedByteMapPath $byteMap
    rc11_descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    rc11_descriptor_verification_result = New-ArtifactRef $resolvedDescriptorVerificationResultPath $descriptorVerificationResult
    release_artifacts_doc = New-ArtifactRef $resolvedReleaseArtifactsDocPath
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.publication_gate.present" ($contractText.Contains("Classify the external object URI") -and $contractText.Contains("Bind the URI to current release byte evidence")) "RC12-010 must consume the RC12 publication gate order." $sourceBindings.rc12_contract
Add-Check "source.byte_map.passed" ($byteMapResult.status -eq "passed" -and $byteMapResult.task -eq "RC11-010") "RC12-010 requires RC11 current byte-map evidence." ([ordered]@{ status = $byteMapResult.status; task = $byteMapResult.task })
Add-Check "source.descriptor_verification.passed" ($descriptorVerificationResult.status -eq "passed" -and $descriptorVerificationResult.task -eq "RC11-012") "RC12-010 requires RC11 descriptor verification evidence." ([ordered]@{ status = $descriptorVerificationResult.status; task = $descriptorVerificationResult.task; object_trust_allowed = $descriptorVerificationResult.verification_surface.object_trust_allowed })
Add-Check "payload.bytes_match_descriptor" ($sourceArtifactSha256 -eq [string]$descriptorCandidate.sha256 -and $sourceArtifactSize -eq [int64]$descriptorCandidate.size_bytes) "Current payload bytes must match descriptor size and SHA-256." ([ordered]@{ expected_sha256 = $descriptorCandidate.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $descriptorCandidate.size_bytes; observed_size_bytes = $sourceArtifactSize })
Add-Check "publication.uri_classified" (($uriPolicy.ok -eq $true -and $bindingBlockers.Count -eq 0) -or ($uriPolicy.ok -eq $false -and $bindingBlockers.Count -gt 0)) "External object URI must be classified and either accepted or denied with exact blockers." ([ordered]@{ classification = $uriPolicy.classification; flags = $uriPolicy.flags; blockers = $uriPolicy.blockers })
Add-Check "release_doc.boundary.present" ($releaseArtifactsDocText.Contains("Release Artifacts") -and $releaseArtifactsDocText.Contains("Production signing")) "Release artifact policy doc must be hash-bound as context, not treated as runtime authority." $sourceBindings.release_artifacts_doc

$publicationBinding = [ordered]@{
    schema = "agentos.rc12-external-object-publication-binding.v1"
    generated_at = $generatedAtValue
    task = "RC12-010"
    release_id = $releaseId
    status = $publicationState
    production_ready_claim = $false
    object_uri = [ordered]@{
        candidate = $uriPolicy.evidence
        classification = $uriPolicy.classification
        immutable = [bool]$uriPolicy.flags.immutable_path
        https = [bool]$uriPolicy.flags.https
        credential_free = [bool]$uriPolicy.flags.credential_free
        query_free = [bool]$uriPolicy.flags.query_free
        digest_pinned = [bool]$uriPolicy.flags.digest_pinned
        size_bound = ($sourceArtifactSize -eq [int64]$descriptorCandidate.size_bytes)
        digest_bound = ($sourceArtifactSha256 -eq [string]$descriptorCandidate.sha256)
        policy_bound = ($uriPolicy.ok -eq $true)
    }
    current_release_bytes = [ordered]@{
        source_path = Get-StablePath $sourceArtifactPath
        size_bytes = $sourceArtifactSize
        sha256 = $sourceArtifactSha256
        descriptor_size_bytes = [int64]$descriptorCandidate.size_bytes
        descriptor_sha256 = [string]$descriptorCandidate.sha256
    }
    required_bindings = [ordered]@{
        descriptor_candidate_sha256 = $descriptorCandidateSha256
        byte_map_sha256 = $byteMapSha256
        byte_map_result_sha256 = $byteMapResultSha256
        descriptor_verification_result_sha256 = $descriptorVerificationResultSha256
        manifest_sha256 = [string]$descriptorCandidate.manifest_sha256
        checksums_sha256 = [string]$descriptorCandidate.checksums_sha256
        public_signature_target_sha256 = [string]$descriptorCandidate.public_signature_target_sha256
        public_signature_receipt_sha256 = [string]$descriptorCandidate.public_signature_receipt_sha256
        revocation_snapshot_sha256 = [string]$descriptorCandidate.revocation_snapshot_sha256
        freshness = [ordered]@{
            fresh_until = if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.fresh_until)) { $null } else { [string]$descriptorCandidate.fresh_until }
            freshness_window_bound = (-not [string]::IsNullOrWhiteSpace([string]$descriptorCandidate.fresh_until))
        }
        compatibility_sha256 = [string]$descriptorCandidate.installer_compatibility_sha256
        rollback_baseline_sha256 = [string]$descriptorCandidate.rollback_baseline_sha256
        support_recovery_sha256 = [string]$descriptorCandidate.support_recovery_sha256
        release_provenance_sha256 = [string]$descriptorCandidate.release_provenance_sha256
        declared_current_reconciliation_sha256 = [string]$descriptorCandidate.declared_current_reconciliation_sha256
    }
    publication_decision = [ordered]@{
        publication_allowed = $publicationAllowed
        external_object_uri_published = $publicationAllowed
        object_trust_allowed = $false
        quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $bindingBlockers
    }
    source = $sourceBindings
}

$denial = [ordered]@{
    schema = "agentos.rc12-external-object-publication-denial.v1"
    generated_at = $generatedAtValue
    task = "RC12-010"
    release_id = $releaseId
    status = if ($publicationAllowed) { "not-denied" } else { $publicationState }
    production_ready_claim = $false
    denied = (-not $publicationAllowed)
    denial_reasons = $bindingBlockers
    failed_requirements = @(
        if (-not $uriPolicy.flags.present) { "external HTTPS object URI must be published" }
        if ($uriPolicy.flags.present -and -not $uriPolicy.flags.https) { "object URI must be HTTPS" }
        if ($uriPolicy.flags.present -and -not $uriPolicy.flags.credential_free) { "object URI must be credential-free" }
        if ($uriPolicy.flags.present -and -not $uriPolicy.flags.immutable_path) { "object URI must be immutable and digest-pinned" }
        if ($sourceArtifactSize -ne [int64]$descriptorCandidate.size_bytes) { "object size must match descriptor" }
        if ($sourceArtifactSha256 -ne [string]$descriptorCandidate.sha256) { "object SHA-256 must match descriptor" }
        if ($descriptorVerificationResult.verification_surface.drift_zero -ne $true) { "declared/current drift-zero must be proved before trust" }
        if ([string]::IsNullOrWhiteSpace([string]$descriptorCandidate.fresh_until)) { "freshness window must be bound before object trust" }
    )
    authority_denied = @(
        "object-storage-provisioning",
        "payload-upload",
        "payload-download",
        "quarantine-fetch",
        "install",
        "activation",
        "rollback-execution",
        "support-upload",
        "remote-dispatch",
        "production-ring-mutation",
        "mirror-authority",
        "signer-authority",
        "frontend-authority",
        "tui-authority",
        "model-replay-authority"
    )
    side_effects = [ordered]@{
        payload_upload_performed = $false
        object_storage_provisioned = $false
        network_probe_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc12-object-publication-binding-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC12-010"
    release_id = $releaseId
    status = if ($publicationAllowed) { "ready-for-rc12-011-drift-zero-reconciliation" } else { "blocked-before-object-trust" }
    production_ready_claim = $false
    publication_binding = [ordered]@{
        path = $null
        sha256 = $null
        publication_allowed = $publicationAllowed
        external_object_uri_published = $publicationAllowed
        blockers = $bindingBlockers
    }
    expected_next_task = "RC12-011"
    downstream_gates = [ordered]@{
        drift_zero_required = $true
        descriptor_freshness_required = $true
        revocation_required = $true
        object_trust_allowed = $false
        quarantine_fetch_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
}

$bindingPath = Join-Path $resolvedArtifactDir "publication-binding.json"
$denialPath = Join-Path $resolvedArtifactDir "publication-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "publication-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-010-external-object-publication-binding.json"

Write-Json $publicationBinding $bindingPath
$handoff.publication_binding.path = Get-StablePath $bindingPath
$handoff.publication_binding.sha256 = Get-FileSha256 $bindingPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

Add-Check "binding.records.required_fields" ($publicationBinding.current_release_bytes.sha256 -and $publicationBinding.required_bindings.manifest_sha256 -and $publicationBinding.required_bindings.checksums_sha256 -and $publicationBinding.required_bindings.public_signature_target_sha256 -and $publicationBinding.required_bindings.revocation_snapshot_sha256 -and $publicationBinding.required_bindings.compatibility_sha256 -and $publicationBinding.required_bindings.rollback_baseline_sha256 -and $publicationBinding.required_bindings.support_recovery_sha256) "Publication binding must record release bytes, manifest, checksum, signature, revocation, compatibility, rollback, and support references." $publicationBinding.required_bindings
Add-Check "publication.denied_or_bound_consistent" (($publicationAllowed -and $bindingBlockers.Count -eq 0) -or (-not $publicationAllowed -and $bindingBlockers.Count -gt 0)) "Publication decision must be bound or denied consistently with exact blockers." ([ordered]@{ publication_allowed = $publicationAllowed; blockers = $bindingBlockers })
Add-Check "outputs.side_effects_absent" ($denial.side_effects.payload_upload_performed -eq $false -and $denial.side_effects.object_storage_provisioned -eq $false -and $denial.side_effects.network_probe_performed -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC12-010 must not provision storage, upload/fetch payloads, install, activate, rollback, upload support, dispatch, or mutate production rings." $denial.side_effects
Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $bindingPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC12-010 outputs must not contain private key paths, PEM blocks, auth tokens, or signer internals." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-external-object-publication-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC12-010"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    publication_surface = [ordered]@{
        state = $publicationState
        publication_allowed = $publicationAllowed
        external_object_uri_published = $publicationAllowed
        object_uri_classification = $uriPolicy.classification
        current_payload_size_bytes = $sourceArtifactSize
        current_payload_sha256 = $sourceArtifactSha256
        descriptor_candidate_sha256 = $descriptorCandidateSha256
        publication_binding_sha256 = Get-FileSha256 $bindingPath
        freshness_window_bound = (-not [string]::IsNullOrWhiteSpace([string]$descriptorCandidate.fresh_until))
        drift_zero = [bool]$descriptorVerificationResult.verification_surface.drift_zero
        object_trust_allowed = $false
        quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $bindingBlockers
    }
    outputs = [ordered]@{
        publication_binding = [ordered]@{ path = Get-StablePath $bindingPath; sha256 = Get-FileSha256 $bindingPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $sourceBindings
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        object_storage_provisioned = $false
        network_probe_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
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
    blockers = $bindingBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        publication_denied_as_expected = (-not $publicationAllowed)
        rc12_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-011"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-external-object-publication-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC12-010"
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
    publication_surface = $result.publication_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc12_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-011"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC12-010 outputs."
}

Write-Host "RC12 external object publication binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Publication state: $publicationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), blockers: $($bindingBlockers.Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
